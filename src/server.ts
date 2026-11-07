/**
 * 中继服务器（P2.2）：**不可信方**。职责仅：
 *  - hello(完整身份条目) → 维护在线名单 → 广播 dir（含 merkle root/证明，客户端验证）；
 *  - invite / msg / cntl / gmsg → 按 `to` 字段转发给在线收件人，绝不解析密文与握手包；
 *  - 同名连接重连时接管旧 socket（身份真实性由客户端签名层承担）；
 *  - （P2.2）挂载浏览器前端静态资源：web/index.html + web/bundle.js。
 * 运行：pnpm server            （默认 http://localhost:9090，WS 同端口）
 */
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocketServer, WebSocket } from 'ws';
import { parseWire } from './codec.js';
import type { RosterEntry } from './codec.js';
import { buildTree } from './merkle.js';
import { dirLeafCanonicalText, type AttestedBundle } from './anchor.js';
import { PROJECT } from './version.js';

const PORT = Number(process.env.PORT ?? 9090);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WEB_DIR = path.join(__dirname, '..', 'web', 'dist');

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.ico': 'image/x-icon',
};

/** 静态资源：仅 web/ 白名单内文件（目录穿越防护：realpath 校验） */
const httpServer = http.createServer((req, res) => {
  const urlPath = (req.url ?? '/').split('?')[0] ?? '/';
  const rel = urlPath === '/' || urlPath === '/index.html' ? 'index.html' : urlPath.replace(/^\/+/, '');
  const target = path.join(WEB_DIR, rel);
  if (!target.startsWith(WEB_DIR) || rel.includes('..') || !fs.existsSync(target) || !fs.statSync(target).isFile()) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('not found (build the client first: pnpm web:build)');
    return;
  }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(target)] ?? 'application/octet-stream' });
  res.end(fs.readFileSync(target));
});

interface Online {
  sock: WebSocket;
  entry: RosterEntry;
}
const roster = new Map<string, Online>();

function broadcastDir(): void {
  // Merkle 目录：按 user 排序构建树，每条目附包含证明（T2 深化：目录视区一致性）
  const built = [...roster.values()]
    .map((e) => ({ ...e.entry }))
    .sort((a, b) => a.user.localeCompare(b.user));
  let root: string | undefined;
  let wireRoster: Array<RosterEntry & { proof: unknown[] }> = built.map((e) => ({ ...e, proof: [] }));
  if (built.length > 0) {
    const leaves = built.map((e) => dirLeafCanonicalText(e as unknown as AttestedBundle));
    const t = buildTree(leaves);
    root = t.root;
    wireRoster = built.map((e, i) => ({ ...e, proof: t.proofs[i] ?? [] }));
  }
  const frame = JSON.stringify({ kind: 'dir', ...(root !== undefined ? { root } : {}), roster: wireRoster });
  console.log(`[server] dir updated: ${built.length} online ${built.map((r) => r.user).join(',')} (root ${root === undefined ? 'n/a' : root.slice(0, 10)}…)`);
  for (const e of roster.values()) {
    if (e.sock.readyState === WebSocket.OPEN) e.sock.send(frame);
  }
}

const wss = new WebSocketServer({ server: httpServer });

httpServer.listen(PORT, () => {
  console.log(`[${PROJECT.name} ${PROJECT.milestone}] relay listening on http://localhost:${PORT} (ws same port)`);
});

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

console.log(`[${PROJECT.name} ${PROJECT.milestone}] relay ready — open http://localhost:${PORT} in a browser`);
