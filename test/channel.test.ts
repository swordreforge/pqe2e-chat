/**
 * M1 核心安全性质测试（对应 PLAN.md §5 验证清单的可自动化部分）：
 *  - 通道密钥对称性：两端独立推导出同一密钥（哈希摘要比对，不打印原始密钥）
 *  - 用户组隔离：不同会话对派生通道密钥不同、且与"明文 ECDH"结果绑定
 *  - AEAD 正确性 / 篡改检测（密文、nonce、AAD 三向）
 *  - 身份加载/落盘 roundtrip 与坏文件拒绝
 */
import { describe, expect, it, beforeAll } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { x25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { createHash } from 'node:crypto';
import { deriveChannelKey, sealMessage, openMessage, keyEqual } from '../src/channel.js';
import { loadOrCreateIdentity } from '../src/identity.js';

function LocalTestIdentity(user: string) {
  const xk = x25519.keygen();
  const wk = x25519.keygen();
  return {
    user,
    xSecret: bytesToHex(xk.secretKey),
    xPub: bytesToHex(xk.publicKey),
    wSecret: bytesToHex(wk.secretKey),
    wPub: bytesToHex(wk.publicKey),
  };
}

let alice_xSecret: string, alice_xPub: string, bob_xSecret: string, bob_xPub: string, mallory_xSecret: string;
let alice_bob_key: Uint8Array;

describe('M1 channel key', () => {
  beforeAll(() => {
    const alice = LocalTestIdentity('alice');
    const bob = LocalTestIdentity('bob');
    const mallory = LocalTestIdentity('mallory');
    alice_xSecret = alice.xSecret;
    alice_xPub = alice.xPub;
    bob_xSecret = bob.xSecret;
    bob_xPub = bob.xPub;
    mallory_xSecret = mallory.xSecret;
    // 两端独立推导（同一对 static X25519、同一通道上下文）
    alice_bob_key = deriveChannelKey(alice_xSecret, bob_xPub, 'alice', 'bob');
  });

  it('symmetric key derivation: both ends derive identical key', () => {
    const bob_view = deriveChannelKey(bob_xSecret, alice_xPub, 'bob', 'alice');
    expect(keyEqual(alice_bob_key, bob_view)).toBe(true);
  });

  it('channel context separates conversations between different peers', () => {
    const alice_mallory = deriveChannelKey(alice_xSecret, malloryPub(), 'alice', 'mallory');
    expect(keyEqual(alice_bob_key, alice_mallory)).toBe(false);
  });

  it('key derivation is deterministic (server restart / dir refresh replays)', () => {
    const again = deriveChannelKey(alice_xSecret, bob_xPub, 'alice', 'bob');
    expect(keyEqual(alice_bob_key, again)).toBe(true);
  });

  it('wrong-peer static key derives an unrelated channel key', () => {
    const wrong = deriveChannelKey(alice_xSecret, bytesToHex(x25519.keygen().publicKey), 'alice', 'bob');
    expect(createHash('sha256').update(wrong).digest('hex').slice(0, 16))
      .not.toBe(createHash('sha256').update(alice_bob_key).digest('hex').slice(0, 16));
  });

  function malloryPub() { return bytesToHex(x25519.keygen().publicKey); }
});

describe('M1 AEAD seal/open', () => {
  it('roundtrip + tamper detection on ciphertext / nonce / aad (from, to)', () => {
    const key = alice_bob_key;
    const sealed = sealMessage(key, 'alice', 'bob', 'night watch 🔒');

    expect(openMessage(key, 'alice', 'bob', sealed)).toBe('night watch 🔒');

    // 密文篡改
    const badCt = { nonce: sealed.nonce, ct: flipBase64(sealed.ct, 0) };
    expect(() => openMessage(key, 'alice', 'bob', badCt)).toThrow();
    // nonce 篡改（换 nonce）→ 解出的明文应为垃圾或直接 poly1305 tag 失败抛异常
    const badNonce = { nonce: flipBase64(sealed.nonce, 0), ct: sealed.ct };
    expect(() => openMessage(key, 'alice', 'bob', badNonce)).toThrow();

    // AAD 篡改 —— 中继重wladir 投毒/换端点攻击（收发对调）
    expect(() => openMessage(key, 'bob', 'alice', sealed)).toThrow();
  });

  it('different text yield different ciphertext (nonce 随机.) ', () => {
    const s1 = sealMessage(alice_bob_key, 'alice', 'bob', 'same');
    const s2 = sealMessage(alice_bob_key, 'alice', 'bob', 'same');
    expect(s1.ct).not.toBe(s2.ct);
    expect(openMessage(alice_bob_key, 'alice', 'bob', s1)).toBe('same');
    expect(openMessage(alice_bob_key, 'alice', 'bob', s2)).toBe('same');
  });

  it('seal binds channel: alice↔bob key cannot open 隔离', () => {
    const other = deriveChannelKey(alice_xSecret, bob_xPub, 'carl', 'dave');
    const sealed = sealMessage(other, 'carl', 'dave', 'for carl+dave only');
    expect(() => openMessage(alice_bob_key, 'carl', 'dave', sealed)).toThrow();
  });
});

describe('M1 identity persistence', () => {
  let dir: string;
  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pqe2e-m1-'));
  });

  it('roundtrip: first create, then load returns same material', () => {
    const a = loadOrCreateIdentity(dir, 'eve');
    const b = loadOrCreateIdentity(dir, 'eve');
    expect(b).toEqual(a);
  });

  it('alias reuse: loading another user creates another file, no collision', () => {
    const eve = loadOrCreateIdentity(dir, 'eve');
    const frank = loadOrCreateIdentity(dir, 'frank');
    expect(frank.xSecret).not.toBe(eve.xSecret);
  });

  it('bad username format rejected', () => {
    expect(() => loadOrCreateIdentity(dir, '../attacker')).toThrow(/bad user name/);
  });
});

describe('M1 key compare (constant-time style)', () => {
  it('keyEqual behaves like equals with different lengths', () => {
    expect(keyEqual(new Uint8Array(32), new Uint8Array(32))).toBe(true);
    expect(keyEqual(new Uint8Array(31), new Uint8Array(32))).toBe(false);
    const a = new Uint8Array(32); a.fill(7);
    const b = new Uint8Array(32); b.fill(7);
    b.set([8], 31);
    expect(keyEqual(a, b)).toBe(false);
  });
});

function flipBase64(b64str: string, index: number): string {
  const buf = Buffer.from(b64str, 'base64');
  buf[index] = (buf[index] ?? 0) ^ 0x42;
  return buf.toString('base64');
}
