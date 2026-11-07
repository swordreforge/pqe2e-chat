/**
 * 中继服务器（M3）：**不可信方**。职责仅：
 *  - hello(完整身份条目) → 维护在线名单 → 广播 dir（目录包括 attestation，但由客户端验证）；
 *  - invite / msg → 按 `to` 字段转发给在线收件人，绝不解析密文与握手包；
 *  - 同名连接重连时接管旧 socket（身份真实性由客户端 ML-DSA+wallet 双签承担）。
 * 运行：pnpm server            （默认 ws://localhost:9090）
 */
import { WebSocketServer, WebSocket } from 'ws';
import { parseWire } from './codec.js';
import type { RosterEntry } from './codec.js';
import { PROJECT } from './version.js';

const PORT = Number(process.env.PORT ?? 9090);

interface Online {
  sock: WebSocket;
  entry: RosterEntry;
}
const roster = new Map<string, Online>();

function broadcastDir(): void {
  const frame = JSON.stringify({
    kind: 'dir',
    roster: [...roster.values()].map((e) => ({ ...e.entry })),
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
        const existing = roster.get(wire.entry.user);
        if (existing !== undefined) {
          console.log(`[server] takeover: '${wire.entry.user}' reconnects, replacing stale socket`);
          existing.sock.terminate();
        }
        roster.set(wire.entry.user, { sock: ws, entry: wire.entry });
        broadcastDir();
        break;
      }
      // 棘轮密文/群控制/群文本一视同仁：密文端到端，服务器只看 to 路由
      case 'invite':
      case 'msg':
      case 'cntl':
      case 'gmsg': {
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
