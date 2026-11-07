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
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { bytesToHex } from '@noble/hashes/utils.js';

export interface Identity {
  user: string;
  /** 静态 X25519（经典侧握手） */
  xSecret: string;
  xPub: string;
  /** ML-KEM-768 身份预共享密钥（量子侧，hex）。别名 prekey：单独泄露不致命，但应定期轮换 */
  kemSecret: string;
  kemPublic: string;
  /** 模拟钱包（M3 attestation 用） */
  wSecret: string;
  wPub: string;
}

export function identityPath(dataDir: string, user: string): string {
  if (!/^[a-zA-Z][a-zA-Z0-9_-]{0,31}$/.test(user)) throw new Error(`bad user name: ${user}`);
  return path.join(dataDir, `identity_${user}.json`);
}

function createIdentity(user: string): Identity {
  const xk = x25519.keygen();
  const kk = ml_kem768.keygen();
  const wk = secp256k1.keygen();
  return {
    user,
    xSecret: bytesToHex(xk.secretKey),
    xPub: bytesToHex(xk.publicKey),
    kemSecret: bytesToHex(kk.secretKey),
    kemPublic: bytesToHex(kk.publicKey),
    wSecret: bytesToHex(wk.secretKey),
    wPub: bytesToHex(wk.publicKey),
  };
}

const KEM_PUB_LEN = 1184; // FIPS 203 ML-KEM-768 ek
const KEM_SK_LEN = 2400;  // FIPS 203 ML-KEM-768 dk
const X_PUB_LEN = 64;     // hex 字符数（32B）

function isValidIdentityShape(raw: Partial<Identity>): boolean {
  return raw.user === undefined
    || (typeof raw.xSecret === 'string' && raw.xSecret.length === 64
      && typeof raw.xPub === 'string' && raw.xPub.length === X_PUB_LEN
      && typeof raw.kemSecret === 'string' && raw.kemSecret.length === KEM_SK_LEN * 2
      && typeof raw.kemPublic === 'string' && raw.kemPublic.length === KEM_PUB_LEN * 2
      && typeof raw.wSecret === 'string' && typeof raw.wPub === 'string');
}

/** 存在则加载；否则生成并落盘。返回的密钥材料永不进日志。 */
export function loadOrCreateIdentity(dataDir: string, user: string): Identity {
  const file = identityPath(dataDir, user);
  if (fs.existsSync(file)) {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8')) as Partial<Identity>;
    if (raw.user === user && isValidIdentityShape(raw)) {
      return {
        user,
        xSecret: raw.xSecret as string,
        xPub: raw.xPub as string,
        kemSecret: raw.kemSecret as string,
        kemPublic: raw.kemPublic as string,
        wSecret: raw.wSecret as string,
        wPub: raw.wPub as string,
      };
    }
    console.log(`[identity] identity file invalid/legacy for "${user}" — regenerating (old file overwritten)`);
  }
  const ident = createIdentity(user);
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(file, JSON.stringify(ident, null, 2) + '\n');
  console.log(`[identity] identity="${user}" created (x pub: ${ident.xPub.slice(0, 12)}…, kem pub: ${ident.kemPublic.slice(0, 12)}…)`);
  return ident;
}
