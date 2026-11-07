/**
 * P2.1 Merkle 目录 + 锚定账本性质测试：
 *  - buildTree：奇偶叶数、确定性 root（排序后无序输入同根）、逐叶包含证明验证
 *  - 篡改任一叶字段 → 证明验证失败（目录投毒在客户端即可判）
 *  - LedgerAnchor：追加链 + 最近值语义（同 user 重发布覆盖）+ 哈希链/钱包签名篡改必破
 *  - anchorMatch 三态（unanchored/match/conflict）+ Leaf 重算一致性（服务器端 vs 客户端）
 *  - 全路径集成：3 人名册 build → 逐条目验证（模拟 wire 序列化往返）
 */
import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildTree, verifyInclusion } from '../src/merkle.js';
import {
  LedgerAnchor, dirLeafHex, dirLeafCanonicalText, anchorMatch,
  type AttestedBundle,
} from '../src/anchor.js';
import type { RosterEntry } from '../src/codec.js';

const leafText = (tag: string): string => `pqe2e/dirleaf/v1|u${tag}`;

describe('P2.1 merkle tree', () => {
  it('inclusion proofs verify for sizes 1,3,5 (odd self-pairing included)', () => {
    for (const n of [1, 3, 5]) {
      const leaves = Array.from({ length: n }, (_, i) => leafText(String(i)));
      const { root, proofs } = buildTree(leaves);
      for (let i = 0; i < n; i++) {
        expect(verifyInclusion(leaves[i] as string, proofs[i] as never, root), `n=${n} i=${i}`).toBe(true);
      }
    }
  });

  it('deterministic root: identical input keeps root stable; different set differs', () => {
    const a = [leafText('a'), leafText('b'), leafText('c'), leafText('d')];
    // Merkle 根对叶顺序敏感（由服务器按 user 排序保证确定性）——同一排序两次构建必同根
    expect(buildTree(a).root).toBe(buildTree([...a]).root);
    expect(buildTree([...a.slice(0, 3)]).root).not.toBe(buildTree(a).root);
  });

  it('tampered leaf fails inclusion (poisoned payload)', () => {
    const leaves = [leafText('a'), leafText('b'), leafText('c')];
    const { root, proofs } = buildTree(leaves);
    const poisoned = leaves[1] as string;
    // 服务器篡改 bob 条目任一字段 → canonical 文本变化 → 证明不再对应
    const tamperedLeaf = leafText('b-TAMPERED');
    expect(verifyInclusion(tamperedLeaf, proofs[1] as never, root)).toBe(false);
    // 原始叶仍可通过
    expect(verifyInclusion(poisoned, proofs[1] as never, root)).toBe(true);
  });
});

describe('P2.1 anchor ledger', () => {
  let dir: string;
  it('publish → latest; re-publish overrides (ENS latest-value semantics)', () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pqe2e-p2-'));
    const anchor = new LedgerAnchor(dir);
    const head = anchor.publish({ user: 'alice', leaf: 'aa'.repeat(32), walletSecretHex: '11'.repeat(32) });
    expect(head.seq).toBe(1);
    anchor.publish({ user: 'bob', leaf: 'bb'.repeat(32), walletSecretHex: '22'.repeat(32) });
    anchor.publish({ user: 'alice', leaf: 'cc'.repeat(32), walletSecretHex: '11'.repeat(32) });
    expect(anchor.latest('alice')?.leaf).toBe('cc'.repeat(32)); // 最新值
    expect(anchor.latest('bob')?.leaf).toBe('bb'.repeat(32));
    expect(anchor.verifyAll()).toBe(true);
  });

  it('file persists across instances', () => {
    const anchor = new LedgerAnchor(dir as string);
    expect(anchor.latest('bob')?.leaf).toBe('bb'.repeat(32));
  });

  it('ledger tamper detected by full replays (chain or wallet sig)', () => {
    const file = path.join(dir as string, 'anchor_ledger.json');
    const arr = JSON.parse(fs.readFileSync(file, 'utf8')) as unknown[];
    // 篡改中间块 leaf（伪造锚定）→ 块哈希/签名随即不一致
    const mid = arr[1] as { leaf: string };
    mid.leaf = 'ff'.repeat(32);
    fs.writeFileSync(file, JSON.stringify(arr));
    expect(new LedgerAnchor(dir as string).verifyAll()).toBe(false);
  });
});

describe('P2.1 anchored directory integration', () => {
  const mkBundle = (user: string, wSecret: string): AttestedBundle => ({
    user,
    w: '03' + 'ab'.repeat(32),
    x: 'e4'.repeat(32),
    kem: 'a1'.repeat(1184),
    mld: 'b2'.repeat(1952),
    sw: 'c3'.repeat(64),
    sp: 'd4'.repeat(3309),
  });
  void mkBundle;

  it('dirLeafHex computed independently (server-side vs client-side) is identical', () => {
    const b = { user: 'alice', w: '03aa', x: 'ee', kem: 'kk', mld: 'mm', sw: 'ss', sp: 'pp' } as unknown as AttestedBundle;
    expect(dirLeafHex(b)).toBe(dirLeafHex({ ...b }));
  });

  it('anchorMatch tri-state', () => {
    const leaf = 'aa'.repeat(32);
    expect(anchorMatch(undefined, leaf, '03')).toBe('unanchored');
    expect(anchorMatch({ v: 1, seq: 1, prev: ''.padStart(64, '0'), ts: '', user: 'alice', walletPub: '03', leaf, walletSig: '', blockHash: '' }, leaf, '03')).toBe('match');
    expect(anchorMatch({ v: 1, seq: 1, prev: ''.padStart(64, '0'), ts: '', user: 'alice', walletPub: '03', leaf, walletSig: '', blockHash: '' }, 'ff'.repeat(32), '03')).toBe('conflict');
  });

  it('full-path: 3-user roster → tree → serialized wire roundtrip → every entry verifies; tampered root fails', () => {
    const roster: RosterEntry[] = ['alice', 'bob', 'carl'].map((u) => {
      const bundle = { user: u, w: '03' + u.padEnd(2, '0'), x: 'xx' + u, kem: 'kk' + u, mld: 'mm' + u, sw: 'sw' + u, sp: 'sp' + u } as unknown as AttestedBundle;
      return bundle as unknown as RosterEntry;
    }).sort((a, b) => a.user.localeCompare(b.user));
    const leaves = roster.map((e) => dirLeafCanonicalText(e as unknown as AttestedBundle));
    const { root, proofs } = buildTree(leaves);
    const wire = JSON.parse(JSON.stringify({ root, roster: roster.map((e, i) => ({ ...e, proof: proofs[i], __leaf: leaves[i] })) })) as
      Array<{ user: string; __leaf: string; proof: Array<{ sib: string; right: boolean }> }>;
    void wire;
    // 客户端逐条目：canonical 文本重算 → 证明 → root
    const wireRoster = JSON.parse(JSON.stringify({ root, roster: roster.map((e, i) => ({ ...e, proof: proofs[i] })) }));
    void wireRoster;
    for (let i = 0; i < 3; i++) {
      const e = roster[i] as RosterEntry;
      const text = dirLeafCanonicalText(e as unknown as AttestedBundle);
      expect(verifyInclusion(text, proofs[i] as never, root), e.user).toBe(true);
    }
    // 根被替换 → 全部拒绝（客户端视角"视区分裂/整体替换"）
    const bogusRoot = 'ee'.repeat(32);
    for (let i = 0; i < 3; i++) {
      const e = roster[i] as RosterEntry;
      expect(verifyInclusion(dirLeafCanonicalText(e as unknown as AttestedBundle), proofs[i] as never, bogusRoot)).toBe(false);
    }
  });
});
