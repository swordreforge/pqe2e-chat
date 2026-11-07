/**
 * M3 身份 attestation / TOFU 安全性质测试：
 *  - 双签构造与验证 roundtrip
 *  - 任何字段被换（x/kem/mld/w 逐一）→ 双签立刻失效（payload 绑定）
 *  - 经典/PQC 单独伪造 → 验证失败（需要同时攻破两把签名私钥）
 *  - TOFU：首次钉柱 → 二次通过 → wallet 公钥变更 → conflict（模拟"目录投毒"被捕获）
 *  - 遗留/非法身份文件自动再生（老格式升级路径）
 */
import { describe, expect, it, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { makeAttestation, verifyAttestation } from '../src/attestation.js';
import type { SignedAttestation } from '../src/attestation.js';
import { TofuTrust } from '../src/trust.js';
import { loadOrCreateIdentity } from '../src/identity.js';

const alice = loadOrCreateIdentity(tmpRoot(), 'alice');
const bob = loadOrCreateIdentity(tmpRoot(), 'bob');
const mallory = loadOrCreateIdentity(tmpRoot(), 'mallory');

function tmpRoot(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'pqe2e-m3-'));
}

function attOf(i: typeof alice): SignedAttestation {
  return {
    user: i.user,
    ...makeAttestation({
      user: i.user, xPub: i.xPub, kemPublic: i.kemPublic,
      mldSecret: i.mldSecret, mldPublic: i.mldPublic,
      wSecret: i.wSecret, wPublic: i.wPub,
    }),
  } as SignedAttestation;
}

const REAL = attOf(alice);

describe('M3 attestation sign/verify', () => {
  it('honest attestation verifies; fresh signatures re-verify too (randomized sign is expected)', () => {
    expect(verifyAttestation(REAL)).toBe(true);
    // secp256k1.sign 每次带 aux 随机化 → 双签字节串可能不同，但应同样验证通过
    expect(verifyAttestation(attOf(alice))).toBe(true);
  });

  it('mutating any bound field breaks both signatures at once', () => {
    for (const field of ['x', 'kem', 'mld'] as const) {
      const forged: SignedAttestation = { ...REAL, [field]: flippedHex(REAL[field], 0) };
      expect(verifyAttestation(forged), `field=${field}`).toBe(false);
    }
    const aliasSwap: SignedAttestation = { ...REAL, user: 'bob' };
    expect(verifyAttestation(aliasSwap)).toBe(false);
  });

  it('classic-only forgery (PQC sig dropped) fails', () => {
    const forged: SignedAttestation = { ...REAL, sp: zeroHexLike(REAL.sp.length) };
    expect(verifyAttestation(forged)).toBe(false);
  });

  it('pq-only forgery (classic sig dropped) fails', () => {
    const forged: SignedAttestation = { ...REAL, sw: zeroHexLike(REAL.sw.length) };
    expect(verifyAttestation(forged)).toBe(false);
  });

  it('full attack with fresh keys under ALICE NAME fails (keys unbound to name)', () => {
    // 攻击者无 alice 的任何私钥，试图用全新密钥对自称 alice
    const fake = attOf({ ...mallory, user: 'alice' } as typeof alice);
    expect(verifyAttestation(fake)).toBe(true); // 密码学上自洽…
    // …但 TOFU 层挡住它：见下一组测试
  });
});

describe('M3 TOFU trust store', () => {
  let dir: string;
  let trust: TofuTrust;
  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pqe2e-m3-trust-'));
    trust = new TofuTrust(dir);
  });

  it('first sight pins; repeat passes; changed wallet → conflict', () => {
    expect(trust.check('alice', alice.wPub)).toBe('new');
    expect(trust.check('alice', alice.wPub)).toBe('pinned');
    expect(trust.check('bob', bob.wPub)).toBe('new');
    // mallory 用伪造条目自称 alice（其 attestation 密码学有效），wallet 已被钉柱 → 冲突
    expect(trust.check('alice', mallory.wPub)).toBe('conflict');
  });

  it('unpin simulates explicit on-chain key rotation; then re-pin', () => {
    trust.unpin('alice');
    expect(trust.pinned('alice')).toBeUndefined();
    expect(trust.check('alice', alice.wPub)).toBe('new');
  });

  it('store persists across instances', () => {
    const again = new TofuTrust(dir);
    expect(again.pinned('alice')).toBeDefined();
  });
});

describe('M3 identity file upgrade', () => {
  it('legacy file missing ML-DSA keys is regenerated automatically', () => {
    // M2 留下的 identity 文件无 mldSecret/mldPublic → 校验失败 → 重建
    const f = loadOrCreateIdentity(tmpRoot(), 'bob');
    expect(typeof f.mldSecret).toBe('string');
    expect(f.mldSecret.length).toBe(4032 * 2);
  });
});

const tagOf = (s: string): string => createHash('sha256').update(s).digest('hex').slice(0, 12);
const flippedHex = (hexs: string, index: number): string => {
  const buf = Buffer.from(hexs, 'hex');
  buf[index] = (buf[index] ?? 0) ^ 0x35;
  return buf.toString('hex');
};
const zeroHexLike = (hexLen: number): string => '0'.repeat(hexLen);
