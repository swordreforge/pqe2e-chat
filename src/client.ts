/**
 * 客户端（P0）：CLI 聊天 + 混合 PQXDH-lite 会话 + 会话/队列加密持久化。
 *   PQE2E_PASS=<设备口令> pnpm client -- alice    # 或交互输入
 *   之后另开一个: pnpm client -- bob
 *
 * 会话规则：
 *  - 发起恒定：字典序较小者主动发 invite，避免双向握手竞争；
 *  - 会话自愈：dir 刷新或发送时若发现 peer 无会话 → 立即补握手（覆盖对端重连/重启）；
 *  - 收到 invite：用身份 X25519 私钥 + ML-KEM prekey 重建同一会话密钥；
 *  - P0：M4 链位置与"未送达队列"持久化进 argon2id 加密信封——重启零丢失：
 *    本端重启不重新握手（链续接），对端离线期间的帧由 WS error 回灌队列，上线即补发。
 * 服务器全程只见密文与不透明 invite 包（可用 tcpdump/wireshark 演示）。
 */
import { WebSocket } from 'ws';
import readline from 'node:readline/promises';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { loadOrCreateSecureIdentity } from './identity.js';
import { parseWire } from './codec.js';
import { M4Channel } from './m4.js';
import type { M4State, SealedFrame } from './m4.js';
import { initiatorHandshake, responderHandshake } from './channel.js';
import { makeAttestation, verifyAttestation } from './attestation.js';
import { TofuTrust } from './trust.js';
import { writeSecureFile, readSecureFile } from './keystore.js';

const SERVER_URL = process.env.SERVER ?? 'ws://localhost:9090';
const DATA_DIR = 'data';
const SESSIONS_DOMAIN = 'pqe2e/sessions/v1';

interface SessionStore {
  v: 1;
  channels: M4State[];
  pending: Record<string, SealedFrame[]>;
}
const sessionsFile = (user: string): string => path.join(DATA_DIR, `sessions_${user}.enc`);

/** pnpm 会把 `--` 分隔符一并传进来，这里过滤后再取第一个实参 */
const args = process.argv.slice(2).filter((a) => a !== '--');
const argvNameRaw = args[0];
if (typeof argvNameRaw !== 'string' || argvNameRaw.length === 0) {
  console.error('usage: pnpm client -- <name>');
  process.exit(1);
}
const selfUser: string = argvNameRaw;

/** 设备解锁口令：环境变量（冒烟/CI 用）或交互输入（可见回显，课程语境可接受） */
let devicePass = process.env.PQE2E_PASS ?? '';
if (devicePass.length < 8 && !fs.existsSync(path.join(DATA_DIR, `identity_${selfUser}.enc`))) {
  const rlPass = readline.createInterface({ input: process.stdin, output: process.stdout });
  const typed = await rlPass.question('[auth] choose device passphrase (min 8 chars): ');
  rlPass.close();
  devicePass = typed;
}

const ident = loadOrCreateSecureIdentity(DATA_DIR, selfUser, devicePass);
const myAttestation = makeAttestation({
  user: selfUser,
  xPub: ident.xPub,
  kemPublic: ident.kemPublic,
  mldSecret: ident.mldSecret,
  mldPublic: ident.mldPublic,
  wSecret: ident.wSecret,
  wPublic: ident.wPub,
});
const trust = new TofuTrust(DATA_DIR);

/** 已建立会话：peer → M4 棘轮通道（根密钥来自 M2 混合 PQXDH-lite 握手） */
const sessions = new Map<string, M4Channel>();
/** 未送达队列（known-failure 至完整 dir 快照之间）：peer → 帧 FIFO */
const pending = new Map<string, SealedFrame[]>();
/** 发出未确认（error → 回灌 pending；dir 快照 → 视作送达） */
const inflight = new Map<string, SealedFrame[]>();

// 精确恢复链位置与离线队列
const stored = readSecureFile<SessionStore>(sessionsFile(selfUser), devicePass, SESSIONS_DOMAIN);
if (stored !== null && stored.v === 1) {
  for (const st of stored.channels) {
    if (st.self !== selfUser) continue; // 残档：多半是别处改名/换目录
    try { sessions.set(st.peer, M4Channel.restore(st)); } catch { /* 单条损坏即丢弃 */ }
  }
  for (const [peer, frames] of Object.entries(stored.pending ?? {})) {
    pending.set(peer, frames.map((f) => ({ v: 4, seq: f.seq, nonce: f.nonce, ct: f.ct })));
  }
  console.log(`[store] restored ${stored.channels.length} session(s), ${[...pending.values()].reduce((n, f) => n + f.length, 0)} pending frame(s)`);
}

let saveQueued = false;
function persistSoon(): void {
  if (saveQueued) return;
  saveQueued = true;
  setTimeout(persistNow, 20);
}
function persistNow(): void {
  saveQueued = false;
  writeSecureFile(
    sessionsFile(selfUser),
    {
      v: 1,
      channels: [...sessions.values()].map((ch) => ch.exportState()),
      pending: Object.fromEntries(pending),
    },
    devicePass,
    SESSIONS_DOMAIN,
  );
}

/**
 * 在线名单：user → 已验证的目录条目（attestation 有效 + TOFU 无冲突）。
 * dir 来自服务器的广播 → 不可信输入：未通过 verify + TOFU 的条目**不进入** peerInfo，
 * 与之相关的 invite/msg 一律视作攻击面。
 */
const peerInfo = new Map<string, { x: string; kem: string }>();

const ws = new WebSocket(SERVER_URL);
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

ws.on('open', () => {
  ws.send(JSON.stringify({ kind: 'hello', entry: { user: selfUser, ...myAttestation } }));
  console.log(`[chat] connected as "${selfUser}". type messages, ^C to quit.\n`);
});

ws.on('error', (e) => {
  console.error(`[chat] connection error: ${e.message}`);
  process.exit(1);
});

/**
 * 确保与 peer 的会话存在：无会话则本地完成发起方握手、缓存密钥并推送 invite。
 * 默认由字典序较小者发起（防双向竞争）；聊天路径可 `force` 兜底发起
 * （对端重启丢会话时的自愈，竞态后果仅为零星消息丢失，无安全影响）。
 */
function ensureSession(peer: string, force = false): void {
  if (sessions.has(peer)) return;
  const info = peerInfo.get(peer);
  if (info === undefined) return;
  if (selfUser >= peer && !force) return; // 等对方发起
  const est = initiatorHandshake(info.x, info.kem, selfUser, peer);
  sessions.set(peer, new M4Channel(est.key, selfUser, peer));
  ws.send(JSON.stringify({ kind: 'invite', from: selfUser, to: peer, ephX: est.invite.ephX, kem: est.invite.kem }));
  console.log(`[chat]   pq-session ${selfUser}↔${peer} established (root tag ${KEY_TAG(est.key)}…, invite sent)`);
  persistSoon();
}

const KEY_TAG = (key: Uint8Array): string =>
  createHash('sha256').update(key).digest('hex').slice(0, 12);

ws.on('message', (raw) => {
  let wire;
  try {
    wire = parseWire(String(raw));
  } catch {
    console.log('[chat] (dropped malformed frame from server)');
    return;
  }
  switch (wire.kind) {
    case 'dir': {
      const before = new Set(peerInfo.keys());
      const verified = new Map<string, { x: string; kem: string }>();
      for (const e of wire.roster) {
        if (e.user === selfUser) continue;
        // ① 双签验证（fail-closed）
        if (!verifyAttestation(e)) {
          console.log(`[chat] ⚠ attestation INVALID for '${e.user}' — dropped (possible directory tampering)`);
          continue;
        }
        // ② TOFU 钉柱校验（钱包公钥锚点）
        const t = trust.check(e.user, e.w);
        if (t === 'conflict') {
          console.log(`[chat] ⚠⚠ TOFU CONFLICT for '${e.user}': wallet pubkey changed since pinning — dropped`);
          continue;
        }
        if (t === 'new') console.log(`[chat] ⚓ TOFU pinned '${e.user}' (wallet ${e.w.slice(0, 10)}…)`);
        verified.set(e.user, { x: e.x, kem: e.kem });
      }
      peerInfo.clear();
      for (const [user, v] of verified) peerInfo.set(user, v);

      for (const peer of peerInfo.keys()) if (!before.has(peer)) console.log(`[chat] ▶ ${peer} online`);
      for (const peer of before) if (!peerInfo.has(peer)) {
        // P0 语义：对端下线**不销毁会话**（链位置保留，离线消息照常入队，上线补发；
        // 真正的重握手由 msg 路径的 no-session force 自愈兜底）
        console.log(`[chat] ◀ ${peer} offline (session retained for queue/recovery)`);
      }
      // 发出未确认帧：拿到新 dir 快照 → 目标在线，视作已送达并清空
      for (const [peer] of inflight) {
        inflight.delete(peer);
      }
      // 会话自愈 + pending 补发：对每个确认在线的 peer 依次进行
      for (const peer of peerInfo.keys()) {
        ensureSession(peer);
        flushPending(peer);
      }
      console.log();
      break;
    }
    case 'invite': {
      if (wire.to !== selfUser) break;
      if (!peerInfo.has(wire.from)) break; // 未上线者不可信
      try {
        const key = responderHandshake(ident.xSecret, ident.kemSecret, wire, wire.from, wire.to);
        sessions.set(wire.from, new M4Channel(key, selfUser, wire.from));
        console.log(`[chat]   pq-session ${wire.from}↔${selfUser} accepted (root tag ${KEY_TAG(key)}…)`);
        persistSoon();
      } catch {
        console.log(`[chat]   <pq handshake from ${wire.from} failed — invite corrupt/untrusted>`);
      }
      break;
    }
    case 'msg': {
      if (wire.to !== selfUser) break; // 不是给我的，静默
      const chan = sessions.get(wire.from);
      if (chan === undefined) {
        console.log(`[chat]   <no pq session with ${wire.from}; force-rehandshaking, that message is lost>`);
        ensureSession(wire.from, true);
        break;
      }
      try {
        const text = chan.open(wire, wire.from, wire.to);
        console.log(`  [${wire.from}] #${wire.seq} ${text}`);
        // 接收链头已前推——立即持久化（对端重启 fallback 不回退，同 NOTES #11）
        persistSoon();
      } catch {
        console.log(`  [${wire.from}] <dropped ciphertext (seq=${wire.seq}) — tampered/replayed/out-of-window>`);
      }
      break;
    }
    case 'error': {
      // 对端离线：把该 peer 发出未确认的帧回灌 pending，等 dir 快照补发
      const m = /peer '([^']+)' not online/.exec(wire.reason);
      if (m !== null && m[1] !== undefined) {
        const peer = m[1];
        const infl = inflight.get(peer) ?? [];
        const back: SealedFrame[] = [...(pending.get(peer) ?? []), ...infl].filter(
          (f, i, arr) => arr.findIndex((g) => g.seq === f.seq) === i, // 去重
        );
        inflight.delete(peer);
        pending.set(peer, back);
        persistSoon();
        console.log(`[chat] queued ${back.length} frame(s) for offline '${peer}'`);
      } else {
        console.log(`[chat] server error: ${wire.reason}`);
      }
      break;
    }
    default:
      break;
  }
});

/** pending 补发：peer 已确认在线 → FIFO 依次发送并转 inflight */
function flushPending(peer: string): void {
  const queue = pending.get(peer);
  if (queue === undefined || queue.length === 0) return;
  let seqs: number[] = [];  while (queue.length > 0) {
    const f = queue.shift() as SealedFrame;
    ws.send(JSON.stringify({ kind: 'msg', from: selfUser, to: peer, v: 4, seq: f.seq, nonce: f.nonce, ct: f.ct }));
    const infl = inflight.get(peer) ?? [];
    infl.push(f);
    inflight.set(peer, infl);
    seqs.push(f.seq);
  }
  if (seqs.length > 0) console.log(`[chat] flushed ${seqs.length} queued frame(s) to '${peer}' (seq ${seqs.join(',')})`);
  persistSoon();
}

// 一行文本 → 对每个"在线或可补发"的对端各封一份密文（目标 = 在线 ∪ 已有会话 ∪ 有排队）
rl.on('line', (line) => {
  const text = line.trim();
  if (text.length === 0) return;
  const targets = new Set<string>([...peerInfo.keys(), ...sessions.keys()]);
  if (targets.size === 0) {
    console.log('[chat] no peers online yet — run another client, e.g.: pnpm client -- bob');
    return;
  }
  for (const peer of targets) {
    const offline = !peerInfo.has(peer);
    if (!sessions.has(peer)) {
      if (offline) continue; // 离线且无会话：啥也做不了（对端上来会握手）
      ensureSession(peer, true);
      if (!sessions.has(peer)) {
        console.log(`[chat]   (${peer}: awaiting handshake invite)`);
        continue;
      }
    }
    const chan = sessions.get(peer);
    if (chan === undefined) continue;
    const f = chan.seal(text, selfUser, peer);
    if (offline) {
      // 对端离线：密封好入队（链前推一次），dir 快照转在线时 flushPending 补发
      const q = pending.get(peer) ?? [];
      q.push(f);
      pending.set(peer, q);
      console.log(`[chat]   (${peer} offline: sealed seq=${f.seq} into queue)`);
    } else {
      const infl = inflight.get(peer) ?? [];
      infl.push(f);
      inflight.set(peer, infl);
      ws.send(JSON.stringify({ kind: 'msg', from: selfUser, to: peer, v: 4, seq: f.seq, nonce: f.nonce, ct: f.ct }));
    }
    // 注意：链头（headOut）已被 seal 前推——不立即持久化会导致重启后
    // 从同一链位置再次封包 = 一次性密钥复用（安全事故，见 NOTES #11）
    persistSoon();
  }
});

// EOF / 输入结束 → 先优雅关闭再退出（不当场 exit，确保 server 能收到 close 帧）
rl.on('close', () => {
  gracefulExit();
});

process.on('SIGINT', () => {
  rl.close();
  gracefulExit();
});

function gracefulExit(): void {
  // 退出竞态：20ms 防抖落盘可能被 close→exit 抢跑（NOTES #11），此处同步落盘
  persistNow();
  ws.close();
  // 正常情况 server 处理 close 帧后本端也收 close → 事件里退出；这里兜底
  const t = setTimeout(() => process.exit(0), 250);
  void t;
  ws.once('close', () => process.exit(0));
}
