/**
 * 中继服务器（M2）：**不可信方**。职责仅：
 *  - hello → 维护在线名单（含 ML-KEM 公钥）→ 广播 dir；
 *  - invite / msg → 按 `to` 字段转发给在线收件人，绝不解析密文与握手包；
 *  掉线即从名单删除并重新广播。
 * 运行：pnpm server            （默认 ws://localhost:9090）
 */
import { WebSocketServer, WebSocket } from 'ws';
import { parseWire } from './codec.js';
import { PROJECT } from './version.js';

const PORT = Number(process.env.PORT ?? 9090);

interface Online {
  sock: WebSocket;
  x: string;
  kem: string;
}
const roster = new Map<string, Online>();

function broadcastDir(): void {
  const frame = JSON.stringify({
    kind: 'dir',
    roster: [...roster.entries()].map(([user, e]) => ({ user, x: e.x, kem: e.kem })),
  });
  console.log(`[server] dir updated: ${roster.size} online ${[...roster.keys()].join(',')}`);
  for (const e of roster.values()) if (e.sock.readyState === WebSocket.OPEN) e.sock.send(frame);
}

const wss = new WebSocketServer({ port: PORT });

wss.on('error', (err: NodeJS.ErrnoException) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[server] port ${PORT} already in use — another relay instance is running; exit.`);
    process.exit(1);
  }
  console.error(`[server] error: ${err.message}`);
  process.exit(1);
});

wss.on('connection', (ws) => {
  ws.on('message', (raw) => {
    let wire;
    try {
      wire = parseWire(String(raw));
    } catch {
      ws.send(JSON.stringify({ kind: 'error', reason: 'malformed frame' }));
      return;
    }
    switch (wire.kind) {
      case 'hello': {
        const existing = roster.get(wire.user);
        if (existing !== undefined) {
          // 重连接管：同一别名的旧连接（可能已死或未优雅关闭）被新连接顶替。
          // 身份认证由 M3 的 ML-DSA attestation 承担，接管语义文档化于此。
          console.log(`[server] takeover: '${wire.user}' reconnects, replacing stale socket`);
          existing.sock.terminate();
        }
        roster.set(wire.user, { sock: ws, x: wire.x, kem: wire.kem });
        broadcastDir();
        break;
      }
      // invite 与 msg 一视同仁：密文端到端，服务器只看 to 路由
      case 'invite':
      case 'msg': {
        const dst = roster.get(wire.to);
        if (!dst || dst.sock.readyState !== WebSocket.OPEN) {
          ws.send(JSON.stringify({ kind: 'error', reason: `peer '${wire.to}' not online` }));
          return;
        }
        dst.sock.send(String(raw));
        break;
      }
      default:
        break;
    }
  });

  ws.on('close', () => {
    for (const [user, e] of roster.entries()) {
      if (e.sock === ws) {
        roster.delete(user);
        broadcastDir();
      }
    }
  });
});

console.log(`[${PROJECT.name} ${PROJECT.milestone}] relay listening on ws://localhost:${PORT}`);
