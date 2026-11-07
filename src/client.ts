/**
 * 客户端（P1）：CLI 聊天 + 混合 PQXDH-lite 会话 + M4 棘轮 + 群聊（MLS-lite）+ 加密持久化。
 *   PQE2E_PASS=<设备口令> pnpm client -- alice    # 或交互输入
 *   之后另开一个: pnpm client -- bob / carl
 *
 * 会话规则：
 *  - 发起恒定（字典序小者握手）+ 会话自愈（dir 刷新即补握手）；
 *  - P0：链位置/乱序缓存/离线队列加密持久化——重启零丢失；
 *  - P1 群聊：`#g` 命令族；L0 creator 单一管理位；epoch（成员表+种子环）全员旋转
 *    （入群/踢人/踢出后旧链 fail-closed = 棘轮版 PCS）。
 * 服务器全程只见密文与不透明转寄帧（可用 tcpdump/wireshark 演示）。
 */
import { WebSocket } from 'ws';
import readline from 'node:readline/promises';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { loadOrCreateSecureIdentity } from './identity.js';
import { parseWire } from './codec.js';
import { M4Channel } from './m4.js';
import type { M4State } from './m4.js';
import { initiatorHandshake, responderHandshake } from './channel.js';
import {
  applyEpoch, encodeEpoch, parseEpoch, restoreGroup, snapshotGroup,
  seedClaimBytes, signClaim, randomSeedHex,
  verifyClaimWithMld,
} from './ggroup.js';
import type { Group, GroupSnapshot } from './ggroup.js';
import { makeAttestation, verifyAttestation, signGmsg, verifyGmsg } from './attestation.js';
import { TofuTrust } from './trust.js';
import { writeSecureFile, readSecureFile } from './keystore.js';

const SERVER_URL = process.env.SERVER ?? 'ws://localhost:9090';
const DATA_DIR = 'data';
const SESSIONS_DOMAIN = 'pqe2e/sessions/v1';

interface SessionStore {
  v: 1;
  channels: M4State[];
  pending: Record<string, unknown[]>;
  /** P1 群组快照密文区 */
  groups: GroupSnapshot[];
}
const sessionsFile = (user: string): string => path.join(DATA_DIR, `sessions_${user}.enc`);

const args = process.argv.slice(2).filter((a) => a !== '--');
const argvNameRaw = args[0];
if (typeof argvNameRaw !== 'string' || argvNameRaw.length === 0) {
  console.error('usage: pnpm client -- <name>');
  process.exit(1);
}
const selfUser: string = argvNameRaw;

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

const peerInfo = new Map<string, { x: string; kem: string }>();
/** 已建立 pairwise 会话：peer → M4 棘轮通道 */
const sessions = new Map<string, M4Channel>();
/** 未送达队列：peer → 完整信封（kind 保留，flush 时原样重发） */
const pending = new Map<string, unknown[]>();
/** 发出未确认（error → 回灌 pending；dir 快照 → 视作送达） */
const inflight = new Map<string, unknown[]>();
/** P1 群组：gid → Group */
const groups = new Map<string, Group>();

const stored = readSecureFile<SessionStore>(sessionsFile(selfUser), devicePass, SESSIONS_DOMAIN);
if (stored !== null && stored.v === 1) {
  for (const st of stored.channels) {
    if (st.self !== selfUser) continue;
    try { sessions.set(st.peer, M4Channel.restore(st)); } catch { /* 单条损坏即丢弃 */ }
  }
  for (const [peer, frames] of Object.entries(stored.pending ?? {})) {
    pending.set(peer, (frames as unknown[]).map((f) => f));
  }
  for (const snap of stored.groups ?? []) {
    const g = restoreGroup(snap);
    if (g !== null) groups.set(g.gid, g);
  }
  console.log(`[store] restored ${stored.channels.length} session(s), ${[...pending.values()].reduce((n, f) => n + f.length, 0)} pending frame(s), ${groups.size} group(s)`);
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
      groups: [...groups.values()].map(snapshotGroup),
    },
    devicePass,
    SESSIONS_DOMAIN,
  );
}

const ws = new WebSocket(SERVER_URL);
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

ws.on('open', () => {
  ws.send(JSON.stringify({ kind: 'hello', entry: { user: selfUser, ...myAttestation } }));
  console.log(`[chat] connected as "${selfUser}". type messages, ^C to quit. (#g help for group cmds)\n`);
});

ws.on('error', (e) => {
  console.error(`[chat] connection error: ${e.message}`);
  process.exit(1);
});

/** 统一信封派发：在线直发（inflight 跟踪），离线入队等待补发 */
function dispatchWire(kind: 'msg' | 'cntl' | 'gmsg', peer: string, chan: M4Channel, plain: string, gid?: string): void {
  const f = chan.seal(plain, selfUser, peer);
  const wire: unknown = (kind === 'gmsg' && gid !== undefined)
    ? { kind, from: selfUser, to: peer, gid, v: 4, seq: f.seq, nonce: f.nonce, ct: f.ct }
    : { kind, from: selfUser, to: peer, v: 4, seq: f.seq, nonce: f.nonce, ct: f.ct };
  if (peerInfo.has(peer)) {
    const infl = inflight.get(peer) ?? [];
    infl.push(wire);
    inflight.set(peer, infl);
    ws.send(JSON.stringify(wire));
  } else {
    const q = pending.get(peer) ?? [];
    q.push(wire);
    pending.set(peer, q);
    console.log(`[chat]   (${peer} offline: ${kind}${gid !== undefined ? `@${gid}` : ''} seq=${f.seq} queued)`);
  }
  persistSoon();
}

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

/** 将 creator 构造的 epoch 通过 pairwise 通道推给所有成员（apply 本地后逐个发） */
function dispatchEpoch(g: Group, announce: string): void {
  let missed = 0;
  for (const m of g.members) {
    if (m === selfUser) continue;
    const chan = sessions.get(m);
    if (chan === undefined || !peerInfo.has(m)) { missed++; continue; }
    dispatchWire('cntl', m, chan, announce);
  }
  console.log(`[chat] epoch ${g.ep} of '${g.name}' sent (members=${g.members.length}, missed=${missed})`);
  if (missed > 0) console.log(`[chat] ⚠ ${missed} member(s) missed the epoch — re-add them later (new epoch rotates everything again)`);
}

/** 本地 claim 验证适配：self 用自身 mld；他人用钉柱 mld（目录不含 self，钉柱永远查不到） */
function claimGate(gid: string, ep: number): (member: string, seedHex: string, ep2: number, claimSig: string) => boolean {
  return (member, seedHex, _ep, claimSig) => {
    const mldPub = (member === selfUser) ? ident.mldPublic : trust.pinnedMld(member);
    return verifyClaimWithMld(mldPub, gid, ep, member, seedHex, claimSig);
  };
}

/** 两阶段轮换聚合窗口（P1/A+B）：creator 只收 claim，成员自造 seed */
interface RollBudget {
  gid: string;
  name: string;
  ep: number;
  members: string[];
  claims: Map<string, { seed: string; sig: string }>;
  timer: NodeJS.Timeout;
}
const rolls = new Map<string, RollBudget>();

function startRoll(gid: string, name: string, ep: number, finalMembers: string[], tellList: string[]): void {
  const prev = rolls.get(gid);
  if (prev !== undefined) { clearTimeout(prev.timer); rolls.delete(gid); }
  const selfSeed = randomSeedHex();
  const selfSig = signClaim(ident.mldSecret, gid, ep, selfUser, selfSeed);
  const budget: RollBudget = {
    gid, name, ep,
    members: finalMembers,
    claims: new Map([[selfUser, { seed: selfSeed, sig: selfSig }]]),
    timer: setTimeout(() => finalizeRoll(gid), 6000),
  };
  rolls.set(gid, budget);
  for (const m of tellList) {
    if (m === selfUser) continue;
    if (!peerInfo.has(m)) { console.log(`[#g] roll cannot reach offline '${m}'`); continue; }
    const chan = sessions.get(m);
    if (chan === undefined) { ensureSession(m, true); continue; }
    dispatchWire('cntl', m, chan, `groll|${gid}|${name}|${selfUser}|${ep}|${finalMembers.join(',')}`);
  }
  console.log(`[#g] roll to ep=${ep} dispatched (members ${finalMembers.join(',')}); collecting signed seed claims (≤6s)`);
}

function finalizeRoll(gid: string): void {
  const b = rolls.get(gid);
  if (b === undefined) return;
  rolls.delete(gid);
  const missing = b.members.filter((m) => m !== selfUser && !b.claims.has(m) && peerInfo.has(m));
  const ring = buildRingFromClaims(b.claims);
  const payload: Parameters<typeof applyEpoch>[1] = {
    gid: b.gid, name: b.name, creator: selfUser, ep: b.ep, members: b.members, ring,
  };
  const applied = applyEpoch(groups.get(gid), payload, selfUser, claimGate(b.gid, b.ep));
  if (applied === null) {
    console.error(`[#g] finalizeRoll rejected by gates (claims/duplicate) — keeping epoch ${groups.get(gid)?.ep ?? 0}`);
    return;
  }
  groups.set(gid, applied);
  persistSoon();
  console.log(`[#g] '${b.name}' epoch → ${applied.ep} (all chains rotated from member-made seeds; claims=${applied.members.length})`);
  if (missing.length > 0) console.log(`[#g] ⚠ offline during roll, dropped: ${missing.join(',')} — re-add them when back online`);
  dispatchEpoch(applied, encodeEpoch(payload));
}

function buildRingFromClaims(claims: Map<string, { seed: string; sig: string }>): Map<string, { seed: string; claim: string }> {
  const ring = new Map<string, { seed: string; claim: string }>();
  for (const [m, c] of claims) ring.set(m, { seed: c.seed, claim: c.sig });
  return ring;
}

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
        if (!verifyAttestation(e)) {
          console.log(`[chat] ⚠ attestation INVALID for '${e.user}' — dropped (possible directory tampering)`);
          continue;
        }
        // ② TOFU 钉柱校验（钱包公钥 + ML-DSA 公钥双锚点——mld 是群签名信任根）
        const t = trust.check(e.user, e.w, e.mld);
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
        console.log(`[chat] ◀ ${peer} offline (session retained for queue/recovery)`);
      }
      for (const [peer] of inflight) inflight.delete(peer);
      for (const peer of peerInfo.keys()) {
        ensureSession(peer);
        flushPending(peer);
      }
      console.log();
      break;
    }
    case 'invite': {
      if (wire.to !== selfUser) break;
      if (!peerInfo.has(wire.from)) break;
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
    case 'cntl': {
      if (wire.to !== selfUser) break;
      const chan = sessions.get(wire.from);
      if (chan === undefined) {
        ensureSession(wire.from, true);
        break;
      }
      try {
        const payload = chan.open(wire, wire.from, wire.to);
        onControl(payload, wire.from);
      } catch {
        console.log(`  [${wire.from}] <control frame undecryptable/tampered>`);
      }
      break;
    }
    case 'msg': {
      if (wire.to !== selfUser) break;
      const chan = sessions.get(wire.from);
      if (chan === undefined) {
        console.log(`[chat]   <no pq session with ${wire.from}; force-rehandshaking, that message is lost>`);
        ensureSession(wire.from, true);
        break;
      }
      try {
        const text = chan.open(wire, wire.from, wire.to);
        console.log(`  [${wire.from}] #${wire.seq} ${text}`);
        persistSoon(); // 接收链头前推 → 落盘（NOTES #11）
      } catch {
        console.log(`  [${wire.from}] <dropped ciphertext (seq=${wire.seq}) — tampered/replayed/out-of-window>`);
      }
      break;
    }
    case 'gmsg': {
      const g = groups.get(wire.gid);
      const chan = g?.chains.get(wire.from);
      if (g === undefined || chan === undefined || !g.members.includes(wire.from)) {
        console.log(`  [#g ${wire.gid}] <frame from '${wire.from}' cannot open — unknown group or sender not in ring>`);
        break;
      }
      // ① 发送者可见签名（ML-DSA，钉柱 mld 公钥验证）：即使 seed 泄露也无法冒名
      const senderMld = trust.pinnedMld(wire.from);
      if (senderMld === undefined || !verifyGmsg(senderMld, wire.gid, wire.from, wire.seq, wire.nonce, wire.ct, wire.sig)) {
        console.log(`  [#g ${g.name}] <signature INVALID from '${wire.from}' seq=${wire.seq} — impersonation attempt?>`);
        break;
      }
      try {
        const text = chan.open(wire, wire.gid, wire.from);
        console.log(`  [#g ${g.name}/${wire.gid} @${wire.from}] #${wire.seq} ${text}`);
        persistSoon(); // 群链同 NOTES #11
      } catch {
        console.log(`  [#g ${g.name}] <dropped ciphertext from '${wire.from}' seq=${wire.seq}>`);
      }
      break;
    }
    case 'error': {
      const m = /peer '([^']+)' not online/.exec(wire.reason);
      if (m !== null && m[1] !== undefined) {
        const peer = m[1];
        const infl = inflight.get(peer) ?? [];
        const back: unknown[] = [...(pending.get(peer) ?? []), ...infl];
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

/** pairwise 控制载荷路由（P1/A+B：两阶段纪元 + 收成 claim 集） */
function onControl(payload: string, from: string): void {
  if (payload.startsWith('groll|')) { handleRollInvite(payload, from); return; }
  if (payload.startsWith('gclaim|')) { handleGroupClaim(payload, from); return; }
  const epoch = parseEpoch(payload);
  if (epoch !== null) {
    const applied = applyEpoch(groups.get(epoch.gid), epoch, selfUser, claimGate(epoch.gid, epoch.ep));
    if (applied === null) {
      console.log(`  [${from}] <gepoch for '${epoch.gid}' rejected (creator/ep/ring/claim gate)>`);
      return;
    }
    groups.set(applied.gid, applied);
    persistSoon();
    console.log(`[#g] group '${applied.name}'/${applied.gid} joined/advanced: epoch ${applied.ep}, members ${applied.members.join(',')} — chains rotated (claims verified)`);
    return;
  }
  console.log(`  [${from}] <unknown control payload (dropped, fail-closed)>`);
}

/** groll：creator 的轮换声明窗（未知 gid = 邀请；已知 gid = 后续轮换，须 creator 本人） */
function handleRollInvite(payload: string, from: string): void {
  const f = payload.split('|');
  if (f.length !== 6) return; // fail-closed
  const gid = f[1] as string;
  const name = f[2] as string;
  const creator = f[3] as string;
  const ep = Number(f[4]);
  const members = (f[5] as string).split(',').filter((x) => x.length > 0);
  if (!Number.isInteger(ep) || ep < 1 || members.length === 0) return;
  const cur = groups.get(gid);
  if (cur !== undefined) {
    if (from !== cur.creator) { console.log(`  [#g ${gid}] <groll from non-creator '${from}' rejected>`); return; }
    if (ep <= cur.ep) return; // 过期 roll
  } else {
    console.log(`[#g] invited to new group '${name}'/${gid} by '${from}' (ep=${ep}, members ${members.join(',')})`);
  }
  const selfSeed = randomSeedHex();
  const declaredEp = cur !== undefined ? ep : ep; // 同一 window
  const sig = signClaim(ident.mldSecret, gid, declaredEp, selfUser, selfSeed);
  const chan = sessions.get(from);
  if (chan === undefined) { console.log(`[#g] cannot reply gclaim (no session with '${from}')`); return; }
  dispatchWire('cntl', from, chan, `gclaim|${gid}|${declaredEp}|${selfUser}|${selfSeed}|${sig}`);
  console.log(`[#g] responded with signed seed claim for ep=${declaredEp} (member-made seed, ${selfSeed.slice(0, 8)}…)`);
}

/** gclaim：creator 收拢成员的签名声明（每帧即时验签，拒绝冒名 cloaked entries） */
function handleGroupClaim(payload: string, from: string): void {
  const f = payload.split('|');
  if (f.length !== 6) return;
  const gid = f[1] as string;
  const ep = Number(f[2]);
  const member = f[3] as string;
  const seed = f[4] as string;
  const sig = f[5] as string;
  if (!Number.isInteger(ep)) return;
  const budget = rolls.get(gid);
  if (budget === undefined) { console.log(`  [${from}] <late/unknown gclaim for '${gid}' (no open roll)>`); return; }
  const expected = claimGate(gid, budget.ep);
  if (from !== member || !expected(member, seed, ep, sig)) {
    console.log(`  [${from}] <gclaim signature/origin MISMATCH for '${member}' — dropped>`);
    return;
  }
  budget.claims.set(member, { seed, sig });
  console.log(`[#g] claim ${budget.claims.size}/${budget.members.length} for ep=${budget.ep} (from '${member}')`);
  const haveAll = budget.members.every((m) => m === selfUser || budget.claims.has(m));
  if (haveAll) {
    clearTimeout(budget.timer);
    finalizeRoll(gid); // 全员到齐 → 立即收口
  }
}

/** pending 补发：peer 已确认在线 → FIFO 依次发送并转 inflight（信封原样重发） */
function flushPending(peer: string): void {
  const queue = pending.get(peer);
  if (queue === undefined || queue.length === 0) return;
  let count = 0;
  while (queue.length > 0) {
    const wire = queue.shift() as unknown;
    const infl = inflight.get(peer) ?? [];
    infl.push(wire);
    inflight.set(peer, infl);
    ws.send(JSON.stringify(wire));
    count++;
  }
  if (count > 0) console.log(`[chat] flushed ${count} queued frame(s) to '${peer}'`);
  persistSoon();
}

// ─────────────────────────── 输入：聊天行 / #g 命令 ───────────────────────────

rl.on('line', (lineRaw: string) => {
  const line = lineRaw.trim();
  if (line.length === 0) return;

  if (line.startsWith('#g')) {
    handleGroupCommand(line);
    return;
  }
  if (line.startsWith('#')) {
    // `#<gid> <text>` 群发（gid 必须是已加入的群）
    const gid = line.split(/\s+/)[0]?.slice(1) as string;
    const g = groups.get(gid);
    const text = line.slice(line.indexOf(' ') + 1);
    if (g === undefined || text.length === 0) {
      console.error(`unknown group '${gid}' (see #g help / #g list)`);
      return;
    }
    sendGroupMessage(g, text);
    return;
  }

  const targets = new Set<string>([...peerInfo.keys(), ...sessions.keys()]);
  if (targets.size === 0) {
    console.log('[chat] no peers online yet — run another client, e.g.: pnpm client -- bob');
    return;
  }
  for (const peer of targets) {
    if (!sessions.has(peer)) {
      if (!peerInfo.has(peer)) continue; // 离线且无会话
      ensureSession(peer, true);
      if (!sessions.has(peer)) {
        console.log(`[chat]   (${peer}: awaiting handshake invite)`);
        continue;
      }
    }
    const chan = sessions.get(peer);
    if (chan === undefined) continue;
    dispatchWire('msg', peer, chan, line);
  }
});

function sendGroupMessage(g: Group, text: string): void {
  const chan = g.chains.get(selfUser);
  if (chan === undefined) { console.error(`[#g] no self chain for '${g.gid}' (epoch glitch)`); return; }
  const f = chan.seal(text, g.gid, selfUser);
  // 逐消息 ML-DSA 可见签名：签 (gid|sender|seq|nonce|ct) 全量
  const sig = signGmsg(ident.mldSecret, g.gid, selfUser, f.seq, f.nonce, f.ct);
  for (const m of g.members) {
    if (m === selfUser) continue;
    const wire: unknown = {
      kind: 'gmsg', from: selfUser, to: m, gid: g.gid, v: 4, seq: f.seq,
      nonce: f.nonce, ct: f.ct, sig,
    };
    if (peerInfo.has(m)) {
      const infl = inflight.get(m) ?? [];
      infl.push(wire);
      inflight.set(m, infl);
      ws.send(JSON.stringify(wire));
    } else {
      const q = pending.get(m) ?? [];
      q.push(wire);
      pending.set(m, q);
      console.log(`[chat]   (${m} offline: gmsg@${g.gid} seq=${f.seq} queued)`);
    }
  }
  persistSoon();
}

function handleGroupCommand(line: string): void {
  const parts = line.split(/\s+/);
  const sub = parts[1];
  switch (sub) {
    case 'help':
      console.log(`#g help                              — this
#g create <gid> <name> <m1 m2...>     — create group (members must be online, roll window 6s)
#<gid> <text>                         — send text to group
#g add <gid> <user>                   — creator only (roll rotation; target must be online)
#g kick <gid> <user>                  — creator only (target = removed; they cannot produce new era claims)
#g list [<gid>]                       — show groups / members`);
      break;
    case 'create': {
      const gid = parts[2];
      const name = parts[3];
      if (gid === undefined || name === undefined) { console.error('usage: #g create <gid> <name> <members...>'); break; }
      const others = parts.slice(4);
      const missing = others.filter((m) => !peerInfo.has(m));
      if (groups.has(gid)) { console.error('group id already exists locally'); break; }
      const finalMembers = [...new Set([selfUser, ...others])].sort();
      if (missing.length > 0) {
        console.error(`#g create requires all target members online (they receive the groll window); missing: ${missing.join(',')}`);
        break;
      }
      startRoll(gid, name, 1, finalMembers, others);
      break;
    }
    case 'add': {
      const gid = parts[2];
      const user = parts[3];
      const g = gid === undefined ? undefined : groups.get(gid);
      if (g === undefined || user === undefined) { console.error('usage: #g add <gid> <user>'); break; }
      if (g.creator !== selfUser) { console.error('only creator may update group membership'); break; }
      if (g.members.includes(user)) { console.error('already in group'); break; }
      if (!peerInfo.has(user)) { console.error('new member must be online (they must answer the roll)'); break; }
      startRoll(g.gid, g.name, g.ep + 1, [...new Set([...g.members, user])].sort(), [...g.members, user]);
      break;
    }
    case 'kick': {
      const gid = parts[2];
      const user = parts[3];
      const g = gid === undefined ? undefined : groups.get(gid);
      if (g === undefined || user === undefined) { console.error('usage: #g kick <gid> <user>'); break; }
      if (g.creator !== selfUser) { console.error('only creator may kick'); break; }
      if (user === selfUser) { console.error('creator cannot kick self (dissolve the group instead)'); break; }
      if (!g.members.includes(user)) { console.error('not a member'); break; }
      const remaining = g.members.filter((m) => m !== user);
      startRoll(g.gid, g.name, g.ep + 1, [...new Set(remaining)].sort(), remaining);
      break;
    }
    case 'list': {
      if (parts[2] === undefined) {
        for (const [gid, g] of groups) console.log(`  ${g.name} ${gid} ep=${g.ep} members=${g.members.join(',')}`);
        break;
      }
      const g = groups.get(parts[2]);
      if (g === undefined) { console.error('unknown group'); break; }
      console.log(`  ${g.name} ep=${g.ep} creator=${g.creator}` +
        ` members=${g.members.join(',')}`);
      break;
    }
    default: {
      // `#<gid> <text>` 群聊天直发（老位置已迁移到 rl.on('line') 的 '#' 前缀路由）
      console.error('unknown #g command (help: #g help)');
      break;
    }
  }
}
