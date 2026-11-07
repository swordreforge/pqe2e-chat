/**
 * 客户端（M2）：CLI 聊天 + 混合 PQXDH-lite 会话。
 *   pnpm client -- alice        # 之后另开一个: pnpm client -- bob
 *
 * 会话规则：
 *  - 发起恒定：字典序较小者主动发 invite，避免双向握手竞争；
 *  - 会话自愈：dir 刷新或发送时若发现 peer 无会话 → 立即补握手（覆盖对端重连/重启）；
 *  - 收到 invite：用身份 X25519 私钥 + ML-KEM prekey 重建同一会话密钥。
 * 服务器全程只见密文与不透明 invite 包（可用 tcpdump/wireshark 演示）。
 */
import { WebSocket } from 'ws';
import readline from 'node:readline/promises';
import { createHash } from 'node:crypto';
import { loadOrCreateIdentity } from './identity.js';
import { parseWire } from './codec.js';
import { initiatorHandshake, responderHandshake } from './channel.js';
import { M4Channel } from './m4.js';
import { makeAttestation, verifyAttestation } from './attestation.js';
import { TofuTrust } from './trust.js';

const SERVER_URL = process.env.SERVER ?? 'ws://localhost:9090';
const DATA_DIR = 'data';

/** pnpm 会把 `--` 分隔符一并传进来，这里过滤后再取第一个实参 */
const args = process.argv.slice(2).filter((a) => a !== '--');
const argvName = args[0];
if (typeof argvName !== 'string' || argvName.length === 0) {
  console.error('usage: pnpm client -- <name>');
  process.exit(1);
}
/** 闭包内使用的显式 string 常量（TS7 不把窄化传播进回调，这里定点固化） */
const selfUser: string = argvName;

const ident = loadOrCreateIdentity(DATA_DIR, selfUser);
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

/**
 * 在线名单：user → 已验证的目录条目（attestation 有效 + TOFU 无冲突）。
 * dir 来自服务器的广播 → 不可信输入：未通过 verify + TOFU 的条目**不进入** peerInfo，
 * 与之相关的 invite/msg 一律视作攻击面。
 */
const peerInfo = new Map<string, { x: string; kem: string }>();
/** 已建立会话：peer → M4 棘轮通道（根密钥来自 M2 混合 PQXDH-lite 握手） */
const sessions = new Map<string, M4Channel>();

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
function ensureSession(peer: string, force = false): Uint8Array | null {
  const cached = sessions.get(peer);
  if (cached !== undefined) return null;
  const info = peerInfo.get(peer);
  if (info === undefined) return null;
  if (selfUser >= peer && !force) return null; // 等对方发起
  const est = initiatorHandshake(info.x, info.kem, selfUser, peer);
  sessions.set(peer, new M4Channel(est.key, selfUser, peer));
  ws.send(JSON.stringify({ kind: 'invite', from: selfUser, to: peer, ephX: est.invite.ephX, kem: est.invite.kem }));
  console.log(`[chat]   pq-session ${selfUser}↔${peer} established (root tag ${KEY_TAG(est.key)}…, invite sent)`);
  return est.key;
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
        console.log(`[chat] ◀ ${peer} offline`);
        sessions.delete(peer);
      }
      // 会话自愈：对所有已知但无会话的 peer 重新发起握手
      for (const peer of peerInfo.keys()) {
        void ensureSession(peer);
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
        void ensureSession(wire.from, true);
        break;
      }
      try {
        const text = chan.open(wire, wire.from, wire.to);
        console.log(`  [${wire.from}] #${wire.seq} ${text}`);
      } catch {
        console.log(`  [${wire.from}] <dropped ciphertext (seq=${wire.seq}) — tampered/replayed/out-of-window>`);
      }
      break;
    }
    case 'error':
      console.log(`[chat] server error: ${wire.reason}`);
      break;
    default:
      break;
  }
});

// 一行文本 → 对每个会话中/可握手的对端各封一份密文
rl.on('line', (line) => {
  const text = line.trim();
  if (text.length === 0) return;
  if (peerInfo.size === 0) {
    console.log('[chat] no peers online yet — run another client, e.g.: pnpm client -- bob');
    return;
  }
  for (const peer of peerInfo.keys()) {
    const established = ensureSession(peer);
    if (established === null && !sessions.has(peer)) {
      console.log(`[chat]   (${peer}: awaiting handshake invite)`);
      continue;
    }
    const chan = sessions.get(peer);
    if (chan === undefined) continue;
    const f = chan.seal(text, selfUser, peer);
    ws.send(JSON.stringify({ kind: 'msg', from: selfUser, to: peer, v: 4, seq: f.seq, nonce: f.nonce, ct: f.ct }));
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
  ws.close();
  // 正常情况 server 处理 close 帧后本端也收 close → 事件里退出；这里兜底
  const t = setTimeout(() => process.exit(0), 250);
  void t;
  ws.once('close', () => process.exit(0));
}
