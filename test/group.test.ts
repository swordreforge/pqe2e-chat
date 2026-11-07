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
  encodeEpoch, parseEpoch, applyEpoch, newEpochRoster, snapshotGroup, restoreGroup, randomSeedHex,
} from '../src/ggroup.js';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';

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

describe('P1 epoch / roster logic', () => {
  const idAlice = 'alice';
  const idBob = 'bob';
  const idCarl = 'carl';

  it('encode/parse roundtrip and gate rejections', () => {
    const p = newEpochRoster('room1', 'First Room', 'alice', 0, ['bob', 'carl']);
    const back = parseEpoch(encodeEpoch(p));
    expect(back?.members).toEqual([...p.members].sort());
    expect(back?.ring.size).toBe(3);
    // ring 不覆盖成员 → 拒
    const partial = { ...p, ring: new Map([...p.ring].slice(0, 1)) };
    expect(applyEpoch(undefined, partial, 'alice')).toBeNull();
    // ep 不增 → 拒
    const g0 = applyEpoch(undefined, p, 'alice');
    const stale = newEpochRoster('room1', 'First Room', 'alice', p.ep - 1, p.members);
    expect(applyEpoch(g0 as NonNullable<ReturnType<typeof applyEpoch>>, stale, 'alice')).toBeNull();
  });

  it('creator mismatch rejected (端侧权限闸门)', () => {
    const p = newEpochRoster('room1', 'Room', 'alice', 0, ['bob']);
    const g = applyEpoch(undefined, p, 'bob') as NonNullable<ReturnType<typeof applyEpoch>>;
    const hijack = newEpochRoster('room1', 'Room', 'bob', p.ep, ['alice']); // bob 抢管理位
    expect(applyEpoch(g, hijack, 'bob')).toBeNull(); // creator 变了 → 拒
  });

  it('non-listed member (被踢者) epoch rejects itself out', () => {
    const p = newEpochRoster('room1', 'Room', 'alice', 0, ['bob', 'carl']);
    const g = applyEpoch(undefined, p, 'carl') as NonNullable<ReturnType<typeof applyEpoch>>;
    // 踢掉 carl 的 epoch：成员表不含 carl → carl 视角直接拒（不再随新链）
    const kick = newEpochRoster('room1', 'Room', 'alice', p.ep, ['bob']);
    expect(kick.members.includes('carl')).toBe(false);
    expect(applyEpoch(g, kick, 'carl')).toBeNull();
  });

  it('snapshot/restore roundtrip preserves group with chains', () => {
    const p = newEpochRoster('room1', 'Room', 'alice', 0, ['bob']);
    const g = applyEpoch(undefined, p, 'bob') as NonNullable<ReturnType<typeof applyEpoch>>;
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
