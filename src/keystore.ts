/**
 * 本地加密信封（P0 · argon2id 整定落盘）：
 *
 *   KEK = argon2id(passphrase, salt, m/t/p, dkLen=32)
 *   ct  = XChaCha20-Poly1305(KEK, nonce24, aad=domain)
 *
 * 口令是**设备解锁密钥**而非登录凭证（服务器永远见不到）——决策记录见 PLAN §7。
 * fail-closed：口令错误/密文被改/aad 域不符/版本不符 → open 一律抛错。
 * 每次写入生成新 salt + 新 nonce（不复用）。
 */
import { argon2id } from '@noble/hashes/argon2.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '@noble/hashes/utils.js';
import fs from 'node:fs';
import path from 'node:path';
import { b64, unb64, utf8 } from './codec.js';

/** 课程语境折中参数：≈8 MiB、2 轮、单线程（生产建议 m≥19MiB、t≥3，见 REPORT §6） */
export const KDF_PARAMS = { m: 8192, t: 2, p: 1 } as const;

export interface SecureBlob {
  v: 1;
  domain: string;
  kdf: { salt: string; m: number; t: number; p: number };
  nonce: string;
  ct: string;
}

function deriveKek(pass: string, blob: SecureBlob): Uint8Array {
  return argon2id(utf8(pass), unb64(blob.kdf.salt), {
    t: blob.kdf.t,
    m: blob.kdf.m,
    p: blob.kdf.p,
    dkLen: 32,
    maxmem: 2 ** 26,
  });
}

export function sealSecure(obj: unknown, pass: string, domain: string): SecureBlob {
  const salt = randomBytes(16);
  const kek = argon2id(utf8(pass), salt, {
    t: KDF_PARAMS.t, m: KDF_PARAMS.m, p: KDF_PARAMS.p, dkLen: 32, maxmem: 2 ** 26,
  });
  const nonce = randomBytes(24);
  const plaintext = Buffer.from(JSON.stringify(obj), 'utf8');
  const ct = xchacha20poly1305(kek, nonce, utf8(domain)).encrypt(plaintext);
  return {
    v: 1,
    domain,
    kdf: { salt: b64(salt), m: KDF_PARAMS.m, t: KDF_PARAMS.t, p: KDF_PARAMS.p },
    nonce: b64(nonce),
    ct: b64(ct),
  };
}

export function openSecure<T>(blob: SecureBlob, pass: string, domain: string): T {
  if (blob.v !== 1 || blob.domain !== domain) throw new Error('secure blob format mismatch');
  const bytes = xchacha20poly1305(
    deriveKek(pass, blob),
    unb64(blob.nonce),
    utf8(blob.domain),
  ).decrypt(unb64(blob.ct));
  return JSON.parse(new TextDecoder().decode(bytes)) as T;
}

export function writeSecureFile(file: string, obj: unknown, pass: string, domain: string): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(sealSecure(obj, pass, domain), null, 2) + '\n');
}

/** 不存在→null；格式/口令/完整性任一异常→throw（fail-closed） */
export function readSecureFile<T>(file: string, pass: string, domain: string): T | null {
  if (!fs.existsSync(file)) return null;
  const blob = JSON.parse(fs.readFileSync(file, 'utf8')) as Partial<SecureBlob>;
  if (blob.v !== 1 || blob.domain !== domain || typeof blob.kdf !== 'object') {
    throw new Error(`secure file format mismatch: ${file}`);
  }
  return openSecure<T>(blob as SecureBlob, pass, domain);
}
