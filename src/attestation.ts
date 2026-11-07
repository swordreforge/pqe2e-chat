/**
 * 身份 attestation（M3 · Web3 身份层核心）：
 *
 *   payload = "pqe2e/att/v1|<user>|<xPub>|<kemPublic>|<mldsaPublic>|<walletPub>"
 *   sw = secp256k1(wallet 私钥, payload)   经典签名 —— "钱包账户"层
 *   sp = ML-DSA-65(mldsa 私钥, payload)    PQC 签名 —— 抗量子层
 *
 * 双签同时有效才算身份可信：攻击者需**同时**掌握钱包私钥与 ML-DSA 私钥
 * 才能伪造/顶替他人公钥目录条目。任何密钥对都可自造，真正的信任根由
 * trust.ts 的 TOFU 锚定（wallet 公钥首次出现即钉柱）承担 —— 模拟真实方案里
 * ENS/合约把 wallet→公钥绑定写链的职责；报告限界见 PLAN.md §6。
 */
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { utf8 } from './codec.js';

export interface AttestationRef {
  user: string;
  /** 静态 X25519 公钥（hex） */
  x: string;
  /** ML-KEM-768 公钥（hex） */
  kem: string;
  /** ML-DSA-65 公钥（hex） */
  mld: string;
  /** 模拟钱包压缩公钥（hex） */
  w: string;
}

export interface SignedAttestation extends AttestationRef {
  /** secp256k1 ECDSA 签名（hex） */
  sw: string;
  /** ML-DSA-65 签名（hex） */
  sp: string;
}

const ATTESTATION_DOMAIN = 'pqe2e/att/v1';

const hexBytes = (hex: string): Uint8Array => new Uint8Array(Buffer.from(hex, 'hex'));

/** 规范化 payload（域分隔 + 字段定序，防字段重排/域混淆） */
export function attestationBytes(r: AttestationRef): Uint8Array {
  return utf8([ATTESTATION_DOMAIN, r.user, r.x, r.kem, r.mld, r.w].join('|'));
}

/** 用本端签名私钥（wallet + ML-DSA）生成双签 attestation；x/kem 私钥不签名，只作被绑定材料 */
export function makeAttestation(ident: {
  user: string;
  xPub: string;
  kemPublic: string;
  mldSecret: string;
  mldPublic: string;
  wSecret: string;
  wPublic: string;
}): { x: string; kem: string; mld: string; w: string; sw: string; sp: string } {
  const ref = {
    user: ident.user,
    x: ident.xPub,
    kem: ident.kemPublic,
    mld: ident.mldPublic,
    w: ident.wPublic,
  };
  const payload = attestationBytes(ref);
  return {
    x: ident.xPub,
    kem: ident.kemPublic,
    mld: ident.mldPublic,
    w: ident.wPublic,
    sw: bytesToHex(secp256k1.sign(payload, hexBytes(ident.wSecret))),
    sp: bytesToHex(ml_dsa65.sign(payload, hexBytes(ident.mldSecret))),
  };
}

/** 目录条目双签验证；任一签名无效/格式异常 → false（fail-closed） */
export function verifyAttestation(entry: SignedAttestation): boolean {
  let payload: Uint8Array;
  try {
    payload = attestationBytes({ user: entry.user, x: entry.x, kem: entry.kem, mld: entry.mld, w: entry.w });
  } catch {
    return false;
  }
  try {
    if (!secp256k1.verify(hexBytes(entry.sw), payload, hexBytes(entry.w))) return false;
  } catch {
    return false;
  }
  try {
    if (!ml_dsa65.verify(hexBytes(entry.sp), payload, hexBytes(entry.mld))) return false;
  } catch {
    return false;
  }
  return true;
}
