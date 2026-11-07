/**
 * 通道密钥协商与 AEAD（M1：static X25519 + HKDF + XChaCha20-Poly1305）。
 *
 * 派生：shared = ECDH(mySecret, peerPub)
 *       key    = HKDF-SHA256(ikm=shared, salt, info="pqe2e/m1/<min>/<max>")
 * 通道上下文（双方用户名排序后进 info）、AAD 绑定 from|to —— 防跨通道重放/移花接木。
 *
 * M1 已知缺陷（M2/M4 修复）：
 * - 无 ML-KEM：不抗"HNDL"量子对手（http → M2 混合 PQXDH）；
 * - 无棘轮与消息序号：密钥泄露 FS 无法保证、旧密文可重放（http → M4 Double Ratchet）。
 */
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { utf8, b64, unb64, asText } from './codec.js';

const SALT = utf8('pqe2e-m1-static-salt/v1');

/** hexX25519 私钥 + 对端公钥 + 会话双方 → 32B 通道密钥 */
export function deriveChannelKey(
  myXSecretHex: string,
  peerXPubHex: string,
  nameA: string,
  nameB: string,
): Uint8Array {
  const shared = x25519.getSharedSecret(unb64(hexToB64(myXSecretHex)), unb64(hexToB64(peerXPubHex)));
  const [a, b] = [nameA, nameB].sort();
  return hkdf(sha256, shared, SALT, utf8(`pqe2e/m1/${a}/${b}`), 32);
}

const hexToB64 = (hex: string): string => Buffer.from(hex, 'hex').toString('base64');

/** AAD 绑定通道两端（加密与解密必须一致，否则 Poly1305 tag 校验失败） */
const aadOf = (from: string, to: string): Uint8Array => utf8(`pqe2e/v1|${from}|${to}`);

export interface Sealed {
  nonce: string;
  ct: string;
}

/** 加密一条文本消息（每次随机 24B nonce） */
export function sealMessage(key: Uint8Array, from: string, to: string, text: string): Sealed {
  const nonce = randomBytes(24);
  const aead = xchacha20poly1305(key, nonce, aadOf(from, to));
  return { nonce: b64(nonce), ct: b64(aead.encrypt(utf8(text))) };
}

/** 解密；对端/中继任何篡改（密文、nonce、from/to）都会在此抛出异常 */
export function openMessage(
  key: Uint8Array,
  from: string,
  to: string,
  sealed: { nonce: string; ct: string },
): string {
  const aead = xchacha20poly1305(key, unb64(sealed.nonce), aadOf(from, to));
  return asText(aead.decrypt(unb64(sealed.ct)));
}

/** keyEqual：恒时比较（防时序侧信道的比较习惯，M1 即建立） */
export function keyEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}
