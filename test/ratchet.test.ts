/**
 * M4 双棘轮（per-message ratchet）性质测试：
 *  - 顺序交换 / 乱序到达 / 迟到消息缓存（skipped-cache）
 *  - 已消费序号重放必拒（"已用密钥不驻留" = 前向保密的实测形态）
 *  - 单字段篡改（ct/nonce/seq/方向翻转）全部 fail-closed
 *  - 链前推单调性（发送端 seq 递增；状态快照无已用密钥）
 *  - 双向会话不串扰 + 跨会话隔离
 */
import { describe, expect, it } from 'vitest';
import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { initiatorHandshake, responderHandshake } from '../src/channel.js';
import { M4Channel, type SealedFrame } from '../src/m4.js';

/** 跑一遍诚实的 M2 混合握手，返回双向棘轮通道对 */
function freshPair(a: string, b: string): { A: M4Channel; B: M4Channel } {
  const ax = x25519.keygen();        // A 的握手身份 X25519
  const bx = x25519.keygen();        // B 的握手身份 X25519
  const bk = ml_kem768.keygen();     // B 的 ML-KEM prekey
  const est = initiatorHandshake(bytesToHex(bx.publicKey), bytesToHex(bk.publicKey), a, b);
  const root = responderHandshake(bytesToHex(bx.secretKey), bytesToHex(bk.secretKey), est.invite, a, b);
  return { A: new M4Channel(est.key, a, b), B: new M4Channel(root, b, a) };
}

describe('M4 ratchet round-trip', () => {
  it('ordered exchange: per-message unique key, seq monotonic', () => {
    const { A, B } = freshPair('alice', 'bob');
    for (let i = 0; i < 5; i++) {
      const f = A.seal(`msg-${i}`, 'alice', 'bob');
      expect(f.seq).toBe(i);
      expect(B.open({ ...f }, 'alice', 'bob')).toBe(`msg-${i}`);
    }
  });

  it('bidirectional interleaving does not disturb direction states', () => {
    const { A, B } = freshPair('alice', 'bob');
    expect(B.open(A.seal('hi1', 'alice', 'bob'), 'alice', 'bob')).toBe('hi1');
    expect(A.open(B.seal('reply', 'bob', 'alice'), 'bob', 'alice')).toBe('reply');
    expect(B.open(A.seal('hi2', 'alice', 'bob'), 'alice', 'bob')).toBe('hi2');
    expect(A.open(B.seal('reply2', 'bob', 'alice'), 'bob', 'alice')).toBe('reply2');
  });

  it('out-of-order arrival opens; any frame replays once rejected (past keys burned)', () => {
    const { A, B } = freshPair('alice', 'bob');
    const frames = [0, 1, 2, 3].map((i) => A.seal(`m${i}`, 'alice', 'bob'));
    // 乱序送达：2,0,3,1
    expect(B.open(frames[2] as SealedFrame, 'alice', 'bob')).toBe('m2');
    expect(B.open(frames[0] as SealedFrame, 'alice', 'bob')).toBe('m0');
    expect(B.open(frames[3] as SealedFrame, 'alice', 'bob')).toBe('m3');
    expect(B.open(frames[1] as SealedFrame, 'alice', 'bob')).toBe('m1');
    // 全部重放一次 → 每帧必拒（已用 mk 不驻留）
    for (const f of frames) expect(() => B.open(f, 'alice', 'bob')).toThrow();
  });

  it('skipped-cache: far-ahead frame opens, late ones still decrypt, then replay rejects', () => {
    const { A, B } = freshPair('alice', 'bob');
    const f: SealedFrame[] = [0, 1, 2].map((i) => A.seal(`lat${i}`, 'alice', 'bob'));
    expect(B.open(f[2] as SealedFrame, 'alice', 'bob')).toBe('lat2');
    expect(B.open(f[0] as SealedFrame, 'alice', 'bob')).toBe('lat0');
    expect(B.open(f[1] as SealedFrame, 'alice', 'bob')).toBe('lat1');
    for (const g of f) expect(() => B.open(g, 'alice', 'bob')).toThrow();
  });
});

describe('M4 fail-closed tamper matrix', () => {
  const { A, B } = freshPair('alice', 'bob');
  const f = A.seal('original', 'alice', 'bob');

  it('ct flip → poly1305 throws', () => {
    expect(() => B.open({ ...f, ct: flipB64(f.ct, 0) }, 'alice', 'bob')).toThrow();
  });

  it('nonce flip → throws', () => {
    expect(() => B.open({ ...f, nonce: flipB64(f.nonce, 0) }, 'alice', 'bob')).toThrow();
  });

  it('seq spoof (any other number) → AAD-bound tag refuses', () => {
    expect(() => B.open({ ...f, seq: 5 }, 'alice', 'bob')).toThrow();
  });

  it('direction swap (envelope from/to rotated) → throws', () => {
    expect(() => B.open(f, 'bob', 'alice')).toThrow(); // 发送方不是 peer
    expect(() => B.open(f, 'alice', 'carl')).toThrow(); // 接收方不是 self
  });

  it('far-future seq is windowed', () => {
    expect(() => B.open({ ...f, seq: 10_000_000 }, 'alice', 'bob')).toThrow();
  });
});

describe('M4 state/isolation properties', () => {
  it('sender state snapshot has no retained used mks; seq strictly increases', () => {
    const { A } = freshPair('alice', 'bob');
    for (let i = 0; i < 5; i++) A.seal('x', 'alice', 'bob');
    const state = JSON.parse(A.inspectState()) as { out: number; skippedKeys: number[] };
    expect(state.out).toBe(5);
    expect(state.skippedKeys).toEqual([]); // 发送端不缓存任何已用/待用消息密钥
  });

  it('different handshakes → unrelated ratchet chains (cross-session frames never open)', () => {
    const p1 = freshPair('alice', 'bob');
    const p2 = freshPair('alice', 'bob');
    const f = p1.A.seal('secret', 'alice', 'bob');
    // 与方向/名字无关的另一条会话也无法解开这帧
    expect(() => p2.B.open(f, 'alice', 'bob')).toThrow();
  });
});

function flipB64(s: string, index: number): string {
  const buf = Buffer.from(s, 'base64');
  buf[index] = (buf[index] ?? 0) ^ 0x2a;
  return buf.toString('base64');
}
