/**
 * GroupSenderChain（P1 · MLS-lite 群链）：
 *
 * 每个成员一条**对称**棘轮链，链头 = HKDF(seed) ：
 *   mk_i = SHA256(chain_i ‖ G_MK)；chain_{i+1} = SHA256(mk_i ‖ G_NEXT)
 * 发送端用自己这条链逐消息密封群文本；其余成员各持有**同一份 seed 副本**消费流。
 * 与 M4Channel 区别：M4 是确定性分方向的两条链（两人）；GChain 是"一条链，副本消费"
 * （群），seed 经 pairwise E2EE 分发。
 *
 * seed 生成模型（PLAN 允许的简化）：创始人 epoch 旋转时**替全体成员生成新 seed**
 * （MLS 本为叶自造）；报告 §6 诚实限界：创始人可冒充他人消息，需成员自造钥才根除。
 * AAD 绑定 gid|sender；跳号缓存/重放拒绝语义与 M4 相同（窗口 1000）。
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { utf8, b64, unb64, asText } from './codec.js';

const G_MK = utf8('pqe2e/p1/gchain/mk');
const G_NEXT = utf8('pqe2e/p1/gchain/next');
const G_SALT = utf8('pqe2e/p1/gchain-salt/v1');
/** 乱序/跳号缓存窗口 */
const G_RECV_WINDOW = 1000;

export interface GFrame {
  v: 4;
  gid: string;
  seq: number;
  nonce: string;
  ct: string;
}

/** 可恢复快照（含密钥材料，只允许进加密信封） */
export interface GState {
  v: 1;
  head: string;
  outSeq: number;
  inCursor: number;
  skipped: Array<[number, string]>;
}

const sha = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  const c = new Uint8Array(a.length + b.length);
  c.set(a, 0);
  c.set(b, a.length);
  return sha256(c);
};

export class GChain {
  private constructor(
    private head: Uint8Array,
    private outSeq = 0,
    private inCursor = 0,
    private skipped = new Map<number, Uint8Array>(),
  ) {}

  static fromSeed(seed: Uint8Array): GChain {
    const head = hkdf(sha256, seed, G_SALT, utf8('pqe2e/p1/chain'), 32);
    return new GChain(head);
  }

  private aad(gid: string, sender: string): Uint8Array {
    return utf8(`pqe2e/p1|${gid}|${sender}`);
  }

  seal(text: string, gid: string, sender: string): GFrame {
    const mk = sha(this.head, G_MK);
    this.head = sha(mk, G_NEXT);
    const seq = this.outSeq++;
    const nonce = randomBytes(24);
    const aead = xchacha20poly1305(mk, nonce, this.aad(gid, sender));
    return { v: 4, gid, seq, nonce: b64(nonce), ct: b64(aead.encrypt(utf8(text))) };
  }

  /** 消费序号对应的接收链 mk（乱序/迟到/重放/篡改统一 fail-closed，语义同 M4） */
  private consume(seq: number, gid: string, sender: string): Uint8Array {
    if (!Number.isInteger(seq) || seq < 0) throw new Error(`gchain bad seq: ${seq}`);
    if (seq < this.inCursor && !this.skipped.has(seq)) throw new Error(`gchain replay/past-seq: ${seq}`);
    if (seq >= this.inCursor + G_RECV_WINDOW) throw new Error(`gchain seq far-future: ${seq}`);
    const cached = this.skipped.get(seq);
    if (cached !== undefined) {
      this.skipped.delete(seq);
      return cached;
    }
    while (this.inCursor < seq) {
      const mk = sha(this.head, G_MK);
      this.head = sha(mk, G_NEXT);
      this.skipped.set(this.inCursor, mk);
      if (this.skipped.size > G_RECV_WINDOW) throw new Error('gchain skipped-cache overflow');
      this.inCursor++;
    }
    const mk = sha(this.head, G_MK);
    this.head = sha(mk, G_NEXT);
    this.inCursor++;
    return mk;
  }

  open(frame: GFrame, gid: string, sender: string): string {
    const mk = this.consume(frame.seq, gid, sender);
    const aead = xchacha20poly1305(mk, unb64(frame.nonce), this.aad(gid, sender));
    try {
      return asText(aead.decrypt(unb64(frame.ct)));
    } catch {
      throw new Error(`gchain poly1305 failure (gid=${gid}, sender=${sender}, seq=${frame.seq})`);
    }
  }

  export(): GState {
    return {
      v: 1,
      head: b64(this.head),
      outSeq: this.outSeq,
      inCursor: this.inCursor,
      skipped: [...this.skipped.entries()].map(([seq, mk]) => [seq, b64(mk)]),
    };
  }

  static restore(st: GState): GChain {
    if (st.v !== 1) throw new Error('gchain state version');
    const head = unb64(st.head);
    if (head.length !== 32) throw new Error('gchain state corrupted (head length)');
    const skipped = new Map<number, Uint8Array>();
    for (const [seq, mk] of st.skipped) {
      const bytes = unb64(mk);
      if (bytes.length !== 32) throw new Error('gchain state corrupted (mk length)');
      skipped.set(seq, bytes);
    }
    return new GChain(head, st.outSeq, st.inCursor, skipped);
  }
}
