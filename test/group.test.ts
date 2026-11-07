/**
 * P1 群链（GChain）与 epoch 逻辑性质测试：
 *  - 同 seed 副本消费：sender seal / receivers open 目录一致
 *  - 乱序/迟到/重放/篡改 fail-closed（与 M4 同语义）
 *  - epoch 旋转：新种子环 → 旧帧 fail-closed（被踢者视角）
 *  - applyEpoch 闸门：creator/ep/ring 三重校验、join（新 gid）直通
 *  - GroupSnapshot/restore roundtrip
 */
import { describe, expect, it } from 'vitest';
import { GChain, type GFrame } from '../src/gchain.js';
import {
  encodeEpoch, parseEpoch, applyEpoch, signClaim, verifyClaimWithMld,
  snapshotGroup, restoreGroup, randomSeedHex, seedClaimBytes,
} from '../src/ggroup.js';
import { signGmsg, verifyGmsg } from '../src/attestation.js';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const seedHex = () => bytesToHex(randomBytes(32));

describe('P1 GChain stream semantics', () => {
  const seed = randomSeedHex();
  const alice = GChain.fromSeed(Buffer.from(seed, 'hex'));
  const bob = GChain.fromSeed(Buffer.from(seed, 'hex'));
  const carl = GChain.fromSeed(Buffer.from(seed, 'hex'));
  const rings = (n: number) => Array.from({ length: n }, (_, i) => alice.seal(`g-${i}`, 'room1', 'alice'));

  it('one stream, many replica consumers', () => {
    for (const f of rings(4)) {
      expect(bob.open(f, 'room1', 'alice')).toBe(`g-${f.seq}`);
      expect(carl.open({ ...f }, 'room1', 'alice')).toBe(`g-${f.seq}`);
    }
  });

  it('out-of-order + skip-cache + full-consumption replay rejection identical to M4', () => {
    const bobLate = GChain.fromSeed(Buffer.from(seed, 'hex'));
    const all = rings(4);
    // 乱序送达 2,0,3,1 全开
    expect(bobLate.open(all[2] as GFrame, 'room1', 'alice')).toBe('g-2');
    expect(bobLate.open(all[0] as GFrame, 'room1', 'alice')).toBe('g-0');
    expect(bobLate.open(all[3] as GFrame, 'room1', 'alice')).toBe('g-3');
    expect(bobLate.open(all[1] as GFrame, 'room1', 'alice')).toBe('g-1');
    // 全部已消费 → 各帧重放必拒
    for (const f of all) expect(() => bobLate.open(f, 'room1', 'alice')).toThrow();
  });

  it('another member seed (non sharer) cannot open alice frames', () => {
    const evaChain = GChain.fromSeed(Buffer.from(seedHex(), 'hex'));
    const f = alice.seal('secret', 'room1', 'alice');
    expect(() => evaChain.open(f, 'room1', 'alice')).toThrow();
  });

  it('tampered frames fail closed (ct/nonce/aad via gid-sender mismatch)', () => {
    const bobc = GChain.fromSeed(Buffer.from(seed, 'hex'));
    const f = alice.seal('hi', 'room1', 'alice');
    expect(() => bobc.open({ ...f, ct: flip(f.ct, 0) }, 'room1', 'alice')).toThrow();
    expect(() => bobc.open({ ...f, gid: 'room2' }, 'room1', 'alice')).toThrow();
    expect(() => bobc.open({ ...f }, 'room1', 'bob')).toThrow();
  });

  it('epoch rotation: fresh seed chain replaces old (kicked-member view fails closed)', () => {
    const oldFrame = alice.seal('old-epoch', 'room2', 'alice');
    // 全员旋转：发送方换新链（同一新 seed 派生）
    const newSeed = randomSeedHex();
    const alice2 = GChain.fromSeed(Buffer.from(newSeed, 'hex'));
    const bob2 = GChain.fromSeed(Buffer.from(newSeed, 'hex'));
    const newFrame = alice2.seal('new-epoch', 'room2', 'alice');
    expect(bob2.open(newFrame, 'room2', 'alice')).toBe('new-epoch');
    // 旧链帧在新链条依次密钥位序上无从解开
    expect(() => bob2.open(oldFrame, 'room2', 'alice')).toThrow();
  });

  it('state snapshot/restore continues chains', () => {
    const { B: bobc } = ((): { B: GChain } => ({ B: GChain.fromSeed(Buffer.from(seed, 'hex')) }))();
    const all = rings(3);
    expect(bobc.open(all[0] as GFrame, 'room1', 'alice')).toBe('g-0');
    const re = GChain.restore(JSON.parse(JSON.stringify(bobc.export())));
    expect(re.open(all[2] as GFrame, 'room1', 'alice')).toBe('g-2'); // 跳号缓存随快照恢复
    expect(re.open(all[1] as GFrame, 'room1', 'alice')).toBe('g-1');
    expect(() => re.open(all[1] as GFrame, 'room1', 'alice')).toThrow();
  });
});

describe('P1 per-message ML-DSA signature (anti-impersonation)', () => {
  const aliceMld = ml_dsa65.keygen();
  const evaMld = ml_dsa65.keygen();
  const gid = 'roomS'; const sender = 'alice'; const seq = 42;
  const nonce = Buffer.from(randomBytes(24)).toString('base64');
  const ct = Buffer.from(randomBytes(48)).toString('base64');

  it('honest sender signature verifies against pinned mld pub', () => {
    const sig = signGmsg(bytesToHex(aliceMld.secretKey), gid, sender, seq, nonce, ct);
    expect(verifyGmsg(bytesToHex(aliceMld.publicKey), gid, sender, seq, nonce, ct, sig)).toBe(true);
  });

  it('attacker knowing the groups SEED but not mld secret cannot forge alice', () => {
    // 这是 creator 冒名威胁的核心断言：seed 副本不能替代身份签名
    const forged = signGmsg(bytesToHex(evaMld.secretKey), gid, sender, seq, nonce, ct);
    expect(verifyGmsg(bytesToHex(aliceMld.publicKey), gid, sender, seq, nonce, ct, forged)).toBe(false);
  });

  it('field tampering breaks the visible signature', () => {
    const sig = signGmsg(bytesToHex(aliceMld.secretKey), gid, sender, seq, nonce, ct);
    expect(verifyGmsg(bytesToHex(aliceMld.publicKey), gid, sender, seq + 1, nonce, ct, sig)).toBe(false);
    expect(verifyGmsg(bytesToHex(aliceMld.publicKey), gid, sender, seq, Buffer.from(randomBytes(24)).toString('base64'), ct, sig)).toBe(false);
  });
});

describe('P1 epoch / roster logic (claim-signed era)', () => {
  const mkKey = (): { secret: string; pub: string } => {
    const k = ml_dsa65.keygen();
    return { secret: bytesToHex(k.secretKey), pub: bytesToHex(k.publicKey) };
  };
  const keys = { alice: mkKey(), bob: mkKey(), carl: mkKey(), eva: mkKey() };
  type UserId = keyof typeof keys;
  /** 钉柱模拟 trust.pinnedMld（读取可 undefined = 未钉柱） */
  const pins: Record<string, string> = {};
  const gate = (gid: string, ep: number) =>
    (member: string, seed: string, ep2: number, sig: string) =>
      verifyClaimWithMld(pins[member], gid, ep2, member, seed, sig);
  /** 模拟"两阶段 roll"结果：成员自造 seed 并签名 → epoch 载荷 */
  const makePayload = (gid: string, name: string, ep: number, members: string[], signers: UserId[] = members as UserId[]) => {
    const ring = new Map<string, { seed: string; claim: string }>();
    for (const m of members) {
      const seed = seedHex();
      const signer = (signers.includes(m as UserId) ? m : 'eva') as UserId;
      ring.set(m, { seed, claim: signClaim(keys[signer].secret, gid, ep, m, seed) });
    }
    return { gid, name, creator: members[0] as string, ep, members: [...members].sort(), ring };
  };

  it('claim-signed epoch applies (claims verified), eva cannot slip in a forged seed', () => {
    for (const u of ['alice', 'bob', 'carl'] as const) pins[u] = keys[u].pub;
    const p = makePayload('room1', 'Room', 1, ['alice', 'bob', 'carl']);
    const g = applyEpoch(undefined, p, 'bob', gate('room1', 1));
    expect(g?.members).toEqual(['alice', 'bob', 'carl']);
    // creator 用 eva 假签名冒充 bob 的种子声明 → 整个 epoch 拒收
    const forged = new Map(p.ring);
    const evaSeed = seedHex();
    forged.set('bob', { seed: evaSeed, claim: signClaim(keys.eva.secret, 'room1', 1, 'bob', evaSeed) });
    const pg = { ...p, ring: forged };
    expect(applyEpoch(undefined, pg as Parameters<typeof applyEpoch>[1], 'bob', gate('room1', 1))).toBeNull();
  });

  it('encode/parse roundtrip preserves claims;ring 覆盖不全/ep 不增 → 拒', () => {
    for (const u of ['alice', 'bob', 'carl'] as const) pins[u] = keys[u].pub;
    const p = makePayload('room1', 'Room', 1, ['alice', 'bob', 'carl']);
    const back = parseEpoch(encodeEpoch(p));
    expect(back?.members).toEqual([...p.members].sort());
    expect(back?.ring.size).toBe(3);
    const partial = { ...p, ring: new Map([...p.ring].slice(0, 1)) };
    expect(applyEpoch(undefined, partial as Parameters<typeof applyEpoch>[1], 'alice', gate('room1', 1))).toBeNull();
    const g0 = applyEpoch(undefined, p, 'alice', gate('room1', 1));
    const stale = makePayload('room1', 'Room', 1, ['alice', 'bob', 'carl']); // ep 与当前相同 → 不增
    expect(applyEpoch(g0 as NonNullable<ReturnType<typeof applyEpoch>>, stale, 'alice', gate('room1', 1))).toBeNull();
  });

  it('creator mismatch rejected (端侧权限闸门)', () => {
    pins.alice = keys.alice.pub;
    pins.bob = keys.bob.pub;
    const p = makePayload('room1', 'Room', 1, ['alice', 'bob']);
    const g = applyEpoch(undefined, p, 'bob', gate('room1', 1)) as NonNullable<ReturnType<typeof applyEpoch>>;
    const hijack = { ...makePayload('room1', 'Room', 2, ['alice', 'bob']), creator: 'bob' }; // bob 抢管理位
    expect(applyEpoch(g, hijack, 'bob', gate('room1', 2))).toBeNull();
  });

  it('non-listed member (被踢者) epoch rejects itself out', () => {
    pins.alice = keys.alice.pub; pins.bob = keys.bob.pub; pins.carl = keys.carl.pub;
    const p = makePayload('room1', 'Room', 1, ['alice', 'bob', 'carl']);
    const g = applyEpoch(undefined, p, 'carl', gate('room1', 1)) as NonNullable<ReturnType<typeof applyEpoch>>;
    const kick = makePayload('room1', 'Room', 2, ['alice', 'bob']);
    expect(kick.members.includes('carl')).toBe(false);
    expect(applyEpoch(g, kick, 'carl', gate('room1', 2))).toBeNull();
    // 且即便 carl 拿到新载荷，也不可能造出过 gate 的 claim（签名不匹配）
  });

  it('unpinned member claim (trust store 无 mld) → claim fail-closed', () => {
    const p2 = makePayload('room9', 'Room9', 1, ['alice']);
    // 未给 eva 钉柱（pins.eva 不存在）但 eva 冒名 alice？
    const noPin = makePayload('room8', 'Room8', 1, ['alice']);
    pins.alice = keys.eva.pub; // 被投毒的钉柱（evade）→ 诚实 alice 的 claim 反而不匹配
    expect(applyEpoch(undefined, noPin as Parameters<typeof applyEpoch>[1], 'alice', gate('room8', 1))).toBeNull();
    delete pins.alice;
    expect(applyEpoch(undefined, p2 as Parameters<typeof applyEpoch>[1], 'alice', gate('room9', 1))).toBeNull(); // 无钉柱 → 拒
  });

  it('snapshot/restore roundtrip preserves group with chains', () => {
    for (const u of ['alice', 'bob'] as const) pins[u] = keys[u].pub;
    const p = makePayload('room1', 'Room', 1, ['alice', 'bob']);
    const g = applyEpoch(undefined, p, 'bob', gate('room1', 1)) as NonNullable<ReturnType<typeof applyEpoch>>;
    const re = restoreGroup(snapshotGroup(g)) as NonNullable<ReturnType<typeof restoreGroup>>;
    expect(re.members).toEqual(g.members);
    expect(re.selfSeed).toBe(g.selfSeed);
    expect(re.chains.size).toBe(g.chains.size);
  });
});

function flip(s: string, index: number): string {
  const buf = Buffer.from(s, 'base64');
  buf[index] = (buf[index] ?? 0) ^ 0x2a;
  return buf.toString('base64');
}
