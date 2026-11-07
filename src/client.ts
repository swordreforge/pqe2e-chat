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
import {
  initiatorHandshake,
  responderHandshake,
  sealMessage,
  openMessage,
} from './channel.js';

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

/**
 * 在线名单：user → 对端 { x, kem }。
 * dir 来自服务器的广播 → 不可信输入，仅作查询材料；信任校验在 M3 加 attestation。
 */
const peerInfo = new Map<string, { x: string; kem: string }>();
/** 已建立会话：peer → 会话密钥 */
const sessions = new Map<string, Uint8Array>();

const ws = new WebSocket(SERVER_URL);
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

ws.on('open', () => {
  ws.send(JSON.stringify({ kind: 'hello', user: selfUser, x: ident.xPub, kem: ident.kemPublic }));
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
  if (cached !== undefined) return cached;
  const info = peerInfo.get(peer);
  if (info === undefined) return null;
  if (selfUser >= peer && !force) return null; // 等对方发起
  const est = initiatorHandshake(info.x, info.kem, selfUser, peer);
  sessions.set(peer, est.key);
  ws.send(JSON.stringify({ kind: 'invite', from: selfUser, to: peer, ephX: est.invite.ephX, kem: est.invite.kem }));
  console.log(`[chat]   pq-session ${selfUser}↔${peer} established (tag ${KEY_TAG(est.key)}…, invite sent)`);
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
      peerInfo.clear();
      for (const e of wire.roster) {
        if (e.user !== selfUser) peerInfo.set(e.user, { x: e.x, kem: e.kem });
      }
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
        sessions.set(wire.from, key);
        console.log(`[chat]   pq-session ${wire.from}↔${selfUser} accepted (tag ${KEY_TAG(key)}…)`);
      } catch {
        console.log(`[chat]   <pq handshake from ${wire.from} failed — invite corrupt/untrusted>`);
      }
      break;
    }
    case 'msg': {
      if (wire.to !== selfUser) break; // 不是给我的，静默
      const key = sessions.get(wire.from);
      if (key === undefined) {
        console.log(`[chat]   <no session with ${wire.from}; force-rehandshaking, that message is lost>`);
        void ensureSession(wire.from, true);
        break;
      }
      try {
        const text = openMessage(key, wire.from, wire.to, wire);
        console.log(`  [${wire.from}] ${text}`);
      } catch {
        console.log(`  [${wire.from}] <ciphertext undecryptable/tampered — treat channel data as untrusted>`);
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
    const key = ensureSession(peer);
    if (key === null) {
      console.log(`[chat]   (${peer}: awaiting handshake invite)`);
      continue;
    }
    const sealed = sealMessage(key, selfUser, peer, text);
    ws.send(JSON.stringify({ kind: 'msg', from: selfUser, to: peer, nonce: sealed.nonce, ct: sealed.ct }));
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
