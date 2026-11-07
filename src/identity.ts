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
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { bytesToHex } from '@noble/hashes/utils.js';

export interface Identity {
  user: string;
  /** 静态 X25519（经典侧握手） */
  xSecret: string;
  xPub: string;
  /** ML-KEM-768 身份预共享密钥（量子侧，hex） */
  kemSecret: string;
  kemPublic: string;
  /** ML-DSA-65 长期签名密钥（PQC 身份层，hex） */
  mldSecret: string;
  mldPublic: string;
  /** 模拟钱包（secp256k1，TOFU 锚定主体，hex） */
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
  const mk = ml_dsa65.keygen();
  const wk = secp256k1.keygen();
  return {
    user,
    xSecret: bytesToHex(xk.secretKey),
    xPub: bytesToHex(xk.publicKey),
    kemSecret: bytesToHex(kk.secretKey),
    kemPublic: bytesToHex(kk.publicKey),
    mldSecret: bytesToHex(mk.secretKey),
    mldPublic: bytesToHex(mk.publicKey),
    wSecret: bytesToHex(wk.secretKey),
    wPub: bytesToHex(wk.publicKey),
  };
}

const IDENTITY_KEYS: Record<keyof Omit<Identity, 'user'>, number> = {
  xSecret: 64, xPub: 64,
  kemSecret: 2400 * 2, kemPublic: 1184 * 2,
  mldSecret: 4032 * 2, mldPublic: 1952 * 2,
  wSecret: 64, wPub: 66,
};

function isValidIdentityShape(raw: Partial<Identity>): boolean {
  for (const key of Object.keys(IDENTITY_KEYS) as Array<keyof typeof IDENTITY_KEYS>) {
    const v = raw[key];
    if (typeof v !== 'string' || v.length !== IDENTITY_KEYS[key]) return false;
  }
  return true;
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
        mldSecret: raw.mldSecret as string,
        mldPublic: raw.mldPublic as string,
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
