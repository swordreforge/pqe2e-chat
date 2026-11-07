/**
 * 身份模块（M1 阶段）：
 * - "钱包" = secp256k1 密钥对 ▸ M3 才用于签名 attestation，现在先落盘持有；
 * - 通道密钥 = static X25519 密钥对 ▸ M1 的 E2E 密钥协商输入。
 *
 * 密钥以 hex 明文存在本地 `data/identity_<user>.json`（本地文件权限视为物理隔离，
 * 课程作业范围内可接受；落盘加密在 PLAN.md §7 P0 完善项内）。
 */
import fs from 'node:fs';
import path from 'node:path';
import { x25519 } from '@noble/curves/ed25519.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex } from '@noble/hashes/utils.js';

export interface Identity {
  user: string;
  xSecret: string;
  xPub: string;
  wSecret: string;
  wPub: string;
}

export function identityPath(dataDir: string, user: string): string {
  if (!/^[a-zA-Z][a-zA-Z0-9_-]{0,31}$/.test(user)) throw new Error(`bad user name: ${user}`);
  return path.join(dataDir, `identity_${user}.json`);
}

function createIdentity(user: string): Identity {
  const xk = x25519.keygen();
  const wk = secp256k1.keygen();
  return {
    user,
    xSecret: bytesToHex(xk.secretKey),
    xPub: bytesToHex(xk.publicKey),
    wSecret: bytesToHex(wk.secretKey),
    wPub: bytesToHex(wk.publicKey),
  };
}

/** 存在则加载；否则生成并落盘。返回的密钥材料永不进日志。 */
export function loadOrCreateIdentity(dataDir: string, user: string): Identity {
  const file = identityPath(dataDir, user);
  if (fs.existsSync(file)) {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8')) as Partial<Identity>;
    if (raw.user !== user
      || typeof raw.xSecret !== 'string' || typeof raw.xPub !== 'string'
      || typeof raw.wSecret !== 'string' || typeof raw.wPub !== 'string') {
      throw new Error(`corrupt identity file: ${file}`);
    }
    return { user, xSecret: raw.xSecret, xPub: raw.xPub, wSecret: raw.wSecret, wPub: raw.wPub };
  }
  const ident = createIdentity(user);
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(file, JSON.stringify(ident, null, 2) + '\n');
  console.log(`[identity] wallet="${user}" created (x pub: ${ident.xPub.slice(0, 12)}…)`);
  return ident;
}
