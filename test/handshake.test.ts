/**
 * M2 混合 PQXDH-lite 安全性质测试：
 *  - 对称性：发起/响应两端独立重建出同一会话密钥（哈希比对，不打印原始密钥）
 *  - 量子侧失守模拟：响应方拿错 ML-KEM 私钥 → 密钥不一致、通信失败
 *  - FIPS 203 隐式拒绝：invite 的 KEM 密文被篡改 → 双侧密钥分叉（不抛错）
 *  - transcript 绑定：from/to 上下文不同 → 密钥不同（防跨通道/防重排）
 *  - invite 完整性：ephemeral 公钥被改 → 会话密钥改变且通信失败
 */
import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { initiatorHandshake, responderHandshake } from '../src/channel.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { bytesToHex } from '@noble/hashes/utils.js';

function participant(user: string) {
  const xk = x25519.keygen();
  const kk = ml_kem768.keygen();
  return { user, xSecret: bytesToHex(xk.secretKey), xPub: bytesToHex(xk.publicKey), kemSecret: bytesToHex(kk.secretKey), kemPublic: bytesToHex(kk.publicKey) };
}

const alice = participant('alice');
const bob = participant('bob');
const mallory = participant('mallory');

const tag = (k: Uint8Array) => createHash('sha256').update(k).digest('hex').slice(0, 16);
const notEqualKeys = (a: Uint8Array, b: Uint8Array) => expect(tag(a)).not.toEqual(tag(b));

describe('M2 hybrid handshake', () => {
  it('initiator and responder derive the very same session key', () => {
    const est = initiatorHandshake(bob.xPub, bob.kemPublic, 'alice', 'bob');
    const key = responderHandshake(bob.xSecret, bob.kemSecret, est.invite, 'alice', 'bob');
    expect(tag(est.key)).toBe(tag(key));
  });

  it('is deterministic per handshake replay of identical transcript', () => {
    const est = initiatorHandshake(bob.xPub, bob.kemPublic, 'alice', 'bob');
    const k1 = responderHandshake(bob.xSecret, bob.kemSecret, est.invite, 'alice', 'bob');
    const k2 = responderHandshake(bob.xSecret, bob.kemSecret, est.invite, 'alice', 'bob');
    expect(tag(k1)).toBe(tag(k2));
  });

  it('wrong ML-KEM secret (compromised PQ side) → key mismatch, channel fails closed', () => {
    const est = initiatorHandshake(bob.xPub, bob.kemPublic, 'alice', 'bob');
    const wrong = responderHandshake(bob.xSecret, mallory.kemSecret, est.invite, 'alice', 'bob');
    notEqualKeys(est.key, wrong);
  });

  it('FIPS 203 implicit rejection: tampered kem ciphertext → keys diverge (no crash)', () => {
    const est = initiatorHandshake(bob.xPub, bob.kemPublic, 'alice', 'bob');
    const tampered: typeof est.invite = {
      ephX: est.invite.ephX,
      kem: flipHex(est.invite.kem, 0),
    };
    const viaTamper = responderHandshake(bob.xSecret, bob.kemSecret, tampered, 'alice', 'bob');
    notEqualKeys(est.key, viaTamper);
  });

  it('tampered ephemeral X25519 pubkey → different key & channel fails', () => {
    const est = initiatorHandshake(bob.xPub, bob.kemPublic, 'alice', 'bob');
    const fakeEph = x25519.keygen();
    const tampered: typeof est.invite = {
      ephX: bytesToHex(fakeEph.publicKey),
      kem: est.invite.kem,
    };
    const viaTamper = responderHandshake(bob.xSecret, bob.kemSecret, tampered, 'alice', 'bob');
    notEqualKeys(est.key, viaTamper);
  });

  it('handshake info binding: different channel context names → different key', () => {
    // from/to 排序后方向无关（方向绑定由消息层 AAD 承担）；但换通道名必须分叉密钥
    const est = initiatorHandshake(bob.xPub, bob.kemPublic, 'alice', 'bob');
    const swappedOrder = responderHandshake(bob.xSecret, bob.kemSecret, est.invite, 'bob', 'alice');
    expect(tag(est.key)).toBe(tag(swappedOrder)); // 方向无关：同通道必得同 key
    const otherChannel = responderHandshake(bob.xSecret, bob.kemSecret, est.invite, 'alice', 'mallory');
    notEqualKeys(est.key, otherChannel); // 通道上下文不同 → 密钥不同
  });

  it('peer isolation: handshake against a third party yields unrelated key', () => {
    const estAB = initiatorHandshake(bob.xPub, bob.kemPublic, 'alice', 'bob');
    const estAM = initiatorHandshake(mallory.xPub, mallory.kemPublic, 'alice', 'mallory');
    notEqualKeys(estAB.key, estAM.key);
  });
});

function flipHex(hex: string, index: number): string {
  const buf = Buffer.from(hex, 'hex');
  buf[index] = (buf[index] ?? 0) ^ 0x2a;
  return buf.toString('hex');
}
