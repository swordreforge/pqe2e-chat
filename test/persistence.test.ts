/**
 * P0 持久化/信封性质测试：
 *  - M4 状态导出/恢复：跨"重启"精确续接链位置（乱序缓存一并恢复、重放仍拒）
 *  - argon2id 加密信封：roundtrip / 口令错误 fail-closed / 密文篡改 fail-closed / 格式域校验
 *  - 每次 seal 新 salt（无 salt 复用）
 */
import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { initiatorHandshake, responderHandshake } from '../src/channel.js';
import { M4Channel, type M4State, type SealedFrame } from '../src/m4.js';
import { sealSecure, openSecure, readSecureFile, writeSecureFile } from '../src/keystore.js';
import { loadOrCreateSecureIdentity, loadOrCreateIdentity } from '../src/identity.js';

function freshPair(a: string, b: string): { A: M4Channel; B: M4Channel } {
  const ax = x25519.keygen();
  const bx = x25519.keygen();
  const bk = ml_kem768.keygen();
  const est = initiatorHandshake(bytesToHex(bx.publicKey), bytesToHex(bk.publicKey), a, b);
  const root = responderHandshake(bytesToHex(bx.secretKey), bytesToHex(bk.secretKey), est.invite, a, b);
  return { A: new M4Channel(est.key, a, b), B: new M4Channel(root, b, a) };
}

function getState(c: M4Channel): M4State {
  return JSON.parse(JSON.stringify(c.exportState())) as M4State;
}

describe('P0 M4 state persistence', () => {
  it('restored channels resume chains exactly: late/skipped frames decrypt, then replay rejected', () => {
    const { A, B } = freshPair('alice', 'bob');
    const f = [0, 1, 2].map((i) => A.seal(`m${i}`, 'alice', 'bob'));
    // B 原实例只收到 seq2（乱序跳号），0/1 留在 skipped-cache
    expect(B.open(f[2] as SealedFrame, 'alice', 'bob')).toBe('m2');

    // 模拟 B 进程重启：state → 磁盘序列化 → restore
    const restored = M4Channel.restore(getState(B));
    expect(restored.open(f[0] as SealedFrame, 'alice', 'bob')).toBe('m0');
    expect(restored.open(f[1] as SealedFrame, 'alice', 'bob')).toBe('m1');

    // 恢复实例继续收新帧
    const f3 = A.seal('m3', 'alice', 'bob');
    expect(restored.open(f3, 'alice', 'bob')).toBe('m3');

    // 重放/sealedcache 消费语义在恢复实例上同样成立
    expect(() => restored.open(f[0] as SealedFrame, 'alice', 'bob')).toThrow();
  });

  it('sender state restores too: restart keeps composing on the same chain (no new handshake needed)', () => {
    const { A, B } = freshPair('alice', 'bob');
    A.seal('one', 'alice', 'bob');
    const restored = M4Channel.restore(getState(A));
    const next = restored.seal('two', 'alice', 'bob');
    expect(next.seq).toBe(1); // 链继续，不重置
    expect(B.open(next, 'alice', 'bob')).toBe('two');
  });

  it('corrupt state rejected (length checks)', () => {
    const { A } = freshPair('alice', 'bob');
    const st = getState(A);
    const bad: M4State = { ...st, headOut: st.headOut.slice(0, 8) };
    expect(() => M4Channel.restore(bad)).toThrow(/corrupted/);
    const badSK: M4State = { ...st, skipped: [[7, 'AAAA']] };
    expect(() => M4Channel.restore(badSK)).toThrow(/corrupted/);
  });
});

describe('P0 keystore envelope', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pqe2e-p0-'));
  const file = path.join(dir, 'enc.enc');
  const secret = { hello: 'world', arr: [1, 2, 3] };

  it('roundtrip with correct passphrase', () => {
    writeSecureFile(file, secret, 'correct horse', 'test/domain');
    expect(readSecureFile<typeof secret>(file, 'correct horse', 'test/domain')).toEqual(secret);
  });

  it('wrong passphrase fails closed', () => {
    expect(() => readSecureFile(file, 'wrong pass!!', 'test/domain')).toThrow();
  });

  it('domain mismatch fails closed', () => {
    expect(() => readSecureFile(file, 'correct horse', 'other/domain')).toThrow(/format|mismatch/);
  });

  it('missing file → null', () => {
    expect(readSecureFile(path.join(dir, 'nope.enc'), 'correct horse', 'test/domain')).toBeNull();
  });

  it('tampered ciphertext fails closed', () => {
    const blob = sealSecure(secret, 'correct horse', 'test/domain');
    const buf = Buffer.from(blob.ct, 'base64');
    buf[5] = (buf[5] ?? 0) ^ 0x40;
    blob.ct = buf.toString('base64');
    expect(() => openSecure(blob, 'correct horse', 'test/domain')).toThrow();
  });

  it('every seal uses fresh salt (no reuse)', () => {
    const a = sealSecure(secret, 'pw', 'test/domain');
    const b = sealSecure(secret, 'pw', 'test/domain');
    expect(a.kdf.salt).not.toBe(b.kdf.salt);
    expect(a.nonce).not.toBe(b.nonce);
  });
});

describe('P0 secure identity store', () => {
  it('migrates legacy plaintext → encrypted store, plaintext removed', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pqe2e-p0-id-'));
    const plainPath = path.join(dir, 'identity_carl.json');
    const encPath = path.join(dir, 'identity_carl.enc');
    const legacy = loadOrCreateIdentity(dir, 'carl');
    writeSecureFile(encPath, legacy, 'longenough', 'pqe2e/identity/v1');
    // 先造出明文文件再走安全加载（模拟 M2-M5 的旧数据）
    expect(fs.existsSync(plainPath)).toBe(true);
    fs.rmSync(encPath);
    const through = loadOrCreateSecureIdentity(dir, 'carl', 'longenoughpwd');
    expect(through.user).toBe('carl');
    expect(fs.existsSync(encPath)).toBe(true);
    expect(fs.existsSync(plainPath)).toBe(false);
  });

  it('wrong passphrase on existing encrypted store fails closed', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pqe2e-p0-id2-'));
    loadOrCreateSecureIdentity(dir, 'dave', 'firstPWD99');
    expect(() => loadOrCreateSecureIdentity(dir, 'dave', 'wrongPASS')).toThrow();
  });
});
