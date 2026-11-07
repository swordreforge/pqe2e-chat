/**
 * Merkle 目录（P2.1）：服务器对当前名册构建二叉树，dir 广播携带 root 与每条目的
 * 包含证明；客户端本地重算叶 → 走证明 → 比对 root。防"目录部分篡改/视区分裂"。
 *
 * 约定：叶节点值 = SHA256(canonical 叶文本)（utf8）；叶顺序由调用方排序（确定性）。
 * odd 长度层用"自配对"（parent = H(x ‖ x)），证明中自配对 sibling = 自身（right=true）。
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { utf8 } from './codec.js';

export interface ProofStep {
  /** 兄弟节点哈希（hex） */
  sib: string;
  /** true：兄弟在当前节点右侧 → parent = H(cur ‖ sib)；false → H(sib ‖ cur) */
  right: boolean;
}

const h2 = (a: string, b: string): string => {
  const ab = new Uint8Array(64);
  ab.set(new Uint8Array(Buffer.from(a, 'hex')), 0);
  ab.set(new Uint8Array(Buffer.from(b, 'hex')), 32);
  return bytesToHex(sha256(ab));
};

export const leafHash = (leafText: string): string => bytesToHex(sha256(utf8(leafText)));

/** 输入=确定排序后的 canonical 叶文本数组；返回 root 与每叶（按原顺序）的证明 */
export function buildTree(leafTexts: string[]): { root: string; proofs: ProofStep[][] } {
  if (leafTexts.length === 0) throw new Error('merkle: empty roster');
  let cur = leafTexts.map(leafHash);
  // desc[i] = 当前层第 i 个节点所覆盖的"原始叶索引"集合（父节点可覆盖多叶）
  let desc: number[][] = cur.map((_, i) => [i]);
  const proofs: ProofStep[][] = cur.map(() => []);
  while (cur.length > 1) {
    const n = cur.length;
    const next: string[] = [];
    const nextDesc: number[][] = [];
    for (let i = 0; i < n; i += 2) {
      const left = cur[i] as string;
      const hasRight = i + 1 < n;
      const right = hasRight ? cur[i + 1] as string : left; // odd 自配对
      // 本层步骤：左子树的所有叶 → 兄弟在右；右子树的所有叶 → 兄弟在左
      for (const leaf of desc[i] as number[]) proofs[leaf]!.push({ sib: right, right: true });
      if (hasRight) for (const leaf of desc[i + 1] as number[]) proofs[leaf]!.push({ sib: left, right: false });
      next.push(h2(left, right));
      nextDesc.push([...desc[i] as number[], ...(hasRight ? desc[i + 1] as number[] : [])]);
    }
    cur = next;
    desc = nextDesc;
  }
  return { root: cur[0] as string, proofs };
}

/** 包含证明重放：从 canonical 叶文本出发（哈希约定与 buildTree 一致） */
export function verifyInclusion(leafText: string, proof: ProofStep[], root: string): boolean {
  let cur = leafHash(leafText);
  for (const st of proof) {
    if (!/^[0-9a-f]{64}$/.test(st.sib)) return false;
    cur = st.right ? h2(cur, st.sib) : h2(st.sib, cur);
  }
  return cur === root;
}
