/**
 * 中继服务器（M1）：**不可信方**。职责仅：
 *  - hello → 维护在线名单 → 广播 dir（发一本"仅供参考"的公钥目录）；
 *  - msg   → 按 `to` 字段转发给在线收件人，绝不解析密文；
 *  掉线即从名单删除并重新广播。
 * 运行：pnpm server            （默认 ws://localhost:9090）
 */
import { WebSocketServer, WebSocket } from 'ws';
import { parseWire } from './codec.js';
import { PROJECT } from './version.js';

const PORT = Number(process.env.PORT ?? 9090);

const roster = new Map<string, WebSocket>();

function broadcastDir(): void {
  const frame = JSON.stringify({
    kind: 'dir',
    roster: [...roster.entries()].map(([user, sock]) => ({ user, x: dirPub.get(user) ?? '' })),
  });
  console.log(`[server] dir updated: ${roster.size} online ${[...roster.keys()].join(',')}`);
  for (const sock of roster.values()) if (sock.readyState === WebSocket.OPEN) sock.send(frame);
}

/** 服务器自己不产密码学，但需要把 hello 里自报的 x 存进目录 */
const dirPub = new Map<string, string>();

const wss = new WebSocketServer({ port: PORT });

wss.on('connection', (ws) => {
  ws.on('message', (raw) => {
    let wire;
    try {
      wire = parseWire(String(raw));
    } catch (e) {
      ws.send(JSON.stringify({ kind: 'error', reason: `malformed frame` }));
      return;
    }
    switch (wire.kind) {
      case 'hello': {
        if (roster.has(wire.user)) {
          ws.send(JSON.stringify({ kind: 'error', reason: `alias '${wire.user}' already online` }));
          return;
        }
        roster.set(wire.user, ws);
        dirPub.set(wire.user, wire.x);
        broadcastDir();
        break;
      }
      case 'msg': {
        const dst = roster.get(wire.to);
        if (!dst || dst.readyState !== WebSocket.OPEN) {
          ws.send(JSON.stringify({ kind: 'error', reason: `peer '${wire.to}' not online` }));
          return;
        }
        dst.send(String(raw));
        break;
      }
      default:
        // 客户端不应给服务器发 dir/error —— 疑似协议异常，静默丢弃
        break;
    }
  });

  ws.on('close', () => {
    for (const [user, sock] of roster) {
      if (sock === ws) {
        roster.delete(user);
        dirPub.delete(user);
        broadcastDir();
      }
    }
  });
});

console.log(`[${PROJECT.name} ${PROJECT.milestone}] relay listening on ws://localhost:${PORT}`);
