/**
 * Double Ratchet（M4）：逐消息密钥轮换。
 *
 * 与 M1/M2 的差别：会话密钥不再"一次握手定终身"，而是每个方向一条棘轮链：
 *   mk_i     = SHA256(chain_i    || "pqe2e/m4/mk")
 *   chain_{i+1} = SHA256(mk_i       || "pqe2e/m4/mk/next")
 * 发送端每封一条消息即前推链头并**丢弃已用 mk**（前向保密）；接收端为乱序消息
 * 缓存"跳号 mk"（窗口 1000），迟到的旧序号也能解；已消费序号重放必拒。
 *
 * 链头由 M2 混合 PQXDH-lite 的会话根密钥按会话参与方名字排序确定性分方向派生
 * （防角色混淆），AAD 绑定 from|to|seq。
 * 边界：妥协 = 链头指针泄露仍无法回溯过去（PFS）；PCS 依赖对端重连后重新握手（M2 自愈）。
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { utf8, b64, unb64, asText } from './codec.js';

const MK_DOMAIN = utf8('pqe2e/m4/mk');
const MK_NEXT = utf8('pqe2e/m4/mk/next');
const M4_SALT = utf8('pqe2e/m4-ratchet-salt/v1');
/** 乱序/跳号缓存窗口 */
const RECV_WINDOW = 1000;

export interface SealedFrame {
  v: 4;
  seq: number;
  nonce: string;
  ct: string;
}

/** 可恢复的棘轮状态快照（含密钥材料，仅允许进入加密信封，严禁明文落盘） */
export interface M4State {
  v: 1;
  self: string;
  peer: string;
  headOut: string;
  headIn: string;
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

export class M4Channel {
  private selfName: string;
  private peerName: string;
  private headOut: Uint8Array;
  private headIn: Uint8Array;
  private outSeq = 0;
  private inCursor = 0;
  private skipped = new Map<number, Uint8Array>();

  constructor(rootKey: Uint8Array, selfName: string, peerName: string) {
    this.selfName = selfName;
    this.peerName = peerName;
    const [sidMin, sidMax] = split64(hkdf(sha256, rootKey, M4_SALT, utf8('pqe2e/m4/chains'), 64));
    const names = [selfName, peerName].sort();
    const selfIsMin = selfName === names[0];
    const sidOut = selfIsMin ? sidMin : sidMax;
    const sidIn = selfIsMin ? sidMax : sidMin;
    this.headOut = sha(sidOut, utf8('pqe2e/m4/chain/kernel'));
    this.headIn = sha(sidIn, utf8('pqe2e/m4/chain/kernel'));
  }

  /** 静态序列化仅用于人工诊断/单测快照，含密钥材料，严禁落盘 */
  inspectState(): string {
    return JSON.stringify({
      self: this.selfName,
      peer: this.peerName,
      out: this.outSeq,
      inCursor: this.inCursor,
      headOutTag: tagOf(this.headOut),
      headInTag: tagOf(this.headIn),
      skippedKeys: [...this.skipped.keys()],
    });
  }

  /** current transcript AAD：域 + 方向 + 序号（包裹完整 envelope 可防字段落改） */
  private aad(from: string, to: string, seq: number): Uint8Array {
    return utf8(`pqe2e/m4/v1|${[from, to].sort().join('/')}|${seq}`);
  }

  seal(text: string, from: string, to: string): SealedFrame {
    if (from !== this.selfName || to !== this.peerName) throw new Error(`m4 wrong direction: ${from}→${to}`);
    const mk = sha(this.headOut, MK_DOMAIN);
    this.headOut = sha(mk, MK_NEXT);
    const seq = this.outSeq++;
    const nonce = randomBytes(24);
    const aead = xchacha20poly1305(mk, nonce, this.aad(from, to, seq));
    return { v: 4, seq, nonce: b64(nonce), ct: b64(aead.encrypt(utf8(text))) };
  }

  /** 消费一个序号对应的接收链 mk（乱序/迟到/重放/篡改统一 fail-closed） */
  private consumeIn(seq: number, from: string, to: string): Uint8Array {
    if (!Number.isInteger(seq) || seq < 0) throw new Error(`m4 bad seq: ${seq}`);
    if (seq < this.inCursor && !this.skipped.has(seq)) throw new Error(`m4 replay/past-seq: ${seq}`);
    if (seq >= this.inCursor + RECV_WINDOW) throw new Error(`m4 seq far-future: ${seq}`);
    const cached = this.skipped.get(seq);
    if (cached !== undefined) {
      this.skipped.delete(seq);
      return cached;
    }
    // 前向推进接收链，途中"跳号 mk"全部缓存供迟到帧使用
    while (this.inCursor < seq) {
      const mk = sha(this.headIn, MK_DOMAIN);
      this.headIn = sha(mk, MK_NEXT);
      this.skipped.set(this.inCursor, mk);
      if (this.skipped.size > RECV_WINDOW) throw new Error('m4 skipped-cache overflow');
      this.inCursor++;
    }
    const mk = sha(this.headIn, MK_DOMAIN);
    this.headIn = sha(mk, MK_NEXT);
    this.inCursor++;
    return mk;
  }

  open(frame: SealedFrame, from: string, to: string): string {
    if (from !== this.peerName || to !== this.selfName) throw new Error(`m4 wrong direction: ${from}→${to}`);
    const mk = this.consumeIn(frame.seq, from, to);
    const aead = xchacha20poly1305(mk, unb64(frame.nonce), this.aad(from, to, frame.seq));
    try {
      return asText(aead.decrypt(unb64(frame.ct)));
    } catch {
      throw new Error(`m4 poly1305 failure at seq=${frame.seq}`);
    }
  }

  /** 状态快照：进加密信封（keystore），重启后用 restore 精确续接链位置 */
  exportState(): M4State {
    return {
      v: 1,
      self: this.selfName,
      peer: this.peerName,
      headOut: b64(this.headOut),
      headIn: b64(this.headIn),
      outSeq: this.outSeq,
      inCursor: this.inCursor,
      skipped: [...this.skipped.entries()].map(([seq, mk]) => [seq, b64(mk)]),
    };
  }

  static restore(st: M4State): M4Channel {
    const c = new M4Channel(new Uint8Array(32), st.self, st.peer); // 占位 root，立即被覆盖
    if (st.v !== 1) throw new Error('m4 state version');
    c.headOut = unb64(st.headOut);
    c.headIn = unb64(st.headIn);
    c.outSeq = st.outSeq;
    c.inCursor = st.inCursor;
    c.skipped = new Map(st.skipped.map(([seq, mk]) => [seq, unb64(mk)]));
    if (c.headOut.length !== 32 || c.headIn.length !== 32) throw new Error('m4 state corrupted (chain head length)');
    for (const mk of c.skipped.values()) if (mk.length !== 32) throw new Error('m4 state corrupted (mk length)');
    return c;
  }
}


const tagOf = (b: Uint8Array): string => Buffer.from(sha256(b)).toString('hex').slice(0, 12);

function split64(bytes: Uint8Array): [Uint8Array, Uint8Array] {
  return [bytes.slice(0, 32), bytes.slice(32, 64)];
}
