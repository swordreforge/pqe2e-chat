/**
 * 客户端（M1）：CLI 聊天。
 *   pnpm client -- alice        # 之后另开一个: pnpm client -- bob
 * 输入一行文本 → 对在场每个对端用各自的通道密钥加密 → 中继转发 → 对端解密打印。
 * 服务器全程只见 base64 密文（可用 tcpdump/wireshark 演示）。
 */
import { WebSocket } from 'ws';
import readline from 'node:readline/promises';
import { createHash } from 'node:crypto';
import { loadOrCreateIdentity } from './identity.js';
import { parseWire } from './codec.js';
import { deriveChannelKey, sealMessage, openMessage } from './channel.js';

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
 * 在线名单：user → 对端 X25519 公钥（hex）。
 * dir 来自服务器的广播 → 不可信输入，仅作查询材料；信任校验在 M3 加 attestation。
 */
const roster = new Map<string, string>();

const ws = new WebSocket(SERVER_URL);
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

ws.on('open', () => {
  ws.send(JSON.stringify({ kind: 'hello', user: selfUser, x: ident.xPub }));
  console.log(`[chat] connected as "${selfUser}". type messages, ^C to quit.\n`);
});

ws.on('error', (e) => {
  console.error(`[chat] connection error: ${e.message}`);
  process.exit(1);
});

function channelKeyTo(peerUser: string): Uint8Array | null {
  const peerX = roster.get(peerUser);
  if (peerX === undefined) return null;
  return deriveChannelKey(ident.xSecret, peerX, selfUser, peerUser);
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
      const before = new Set(roster.keys());
      roster.clear();
      for (const e of wire.roster) {
        if (e.user !== selfUser) roster.set(e.user, e.x);
      }
      for (const peer of roster.keys()) if (!before.has(peer)) console.log(`[chat] ▶ ${peer} online`);
      for (const peer of before) if (!roster.has(peer)) console.log(`[chat] ◀ ${peer} offline`);
      if (roster.size > 0) {
        for (const peer of roster.keys()) {
          const key = channelKeyTo(peer);
          if (key) console.log(`[chat]   channel ${selfUser}↔${peer} key tag: ${KEY_TAG(key)}…`);
        }
        console.log();
      }
      break;
    }
    case 'msg': {
      if (wire.to !== selfUser) break; // 不是给我的，静默
      const key = channelKeyTo(wire.from);
      if (key === null) break;
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

// 一行文本 → 对每个对端各封一份密文（M1 无选择目标，直播间式全场景广播）
rl.on('line', (line) => {
  const text = line.trim();
  if (text.length === 0) return;
  if (roster.size === 0) {
    console.log('[chat] no peers online yet — run another client, e.g.: pnpm client -- bob');
    return;
  }
  for (const peer of roster.keys()) {
    const key = channelKeyTo(peer);
    if (key === null) continue;
    const sealed = sealMessage(key, selfUser, peer, text);
    ws.send(JSON.stringify({ kind: 'msg', from: selfUser, to: peer, nonce: sealed.nonce, ct: sealed.ct }));
  }
});

// EOF / 输入结束 → 正常退出（管道式冒烟测试依赖它）
rl.on('close', () => {
  void ws.close();
  process.exit(0);
});

process.on('SIGINT', () => {
  rl.close();
  void ws.close();
  process.exit(0);
});
