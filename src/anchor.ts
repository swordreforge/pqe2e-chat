/**
 * 目录锚定层（P2.1 · "ENS 等价协议面"）：
 *
 * 每个 identity 的目录叶 leaf = SHA256("pqe2e/dirleaf/v1|user|w|x|kem|mld|sw|sp")。
 * **发布**（≈ ENS setTextRecord）：钱包 ECDSA 签 (domain|user|walletPub|leaf) →
 * 追加进 append-only 账本（prev 哈希链，minseq/篡改全网可回放检测）。
 * **消费**：客户端验目录条目时先过 Merkle 证明，再比对"最新锚定叶"——
 * 服务器离线篡改/替换公钥当场败露（TOFU 保留为后备层）。
 *
 * Provider 缝线：本次实现 `LedgerAnchor`（本地账本，单机多进程共享）；
 * 接真链时替换 publish/latest 两个函数为 ENS 合约调用（映射表见 REPORT §3 T2 注）。
 */
import fs from 'node:fs';
import path from 'node:path';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { utf8 } from './codec.js';

export const DIR_LEAF_DOMAIN = 'pqe2e/dirleaf/v1';
export const ANCHOR_DOMAIN = 'pqe2e/anchor/v1';

export interface AttestedBundle {
  user: string;
  w: string;
  x: string;
  kem: string;
  mld: string;
  sw: string;
  sp: string;
}

/** 目录叶 canonical 文本（Merkle 树叶节点输入） */
export function dirLeafCanonicalText(r: AttestedBundle): string {
  return [DIR_LEAF_DOMAIN, r.user, r.w, r.x, r.kem, r.mld, r.sw, r.sp].join('|');
}

/** 目录叶：身份包整体哈希（canonical 定序） */
export function dirLeafHex(r: AttestedBundle): string {
  return bytesToHex(sha256(utf8(dirLeafCanonicalText(r))));
}

export interface AnchorBlock {
  v: 1;
  seq: number;
  prev: string;
  ts: string;
  user: string;
  walletPub: string;
  leaf: string;
  walletSig: string;
  blockHash: string;
}

const anchorBody = (user: string, walletPub: string, leaf: string): Uint8Array =>
  utf8([ANCHOR_DOMAIN, user, walletPub, leaf].join('|'));

const GENESIS_HASH = '0'.repeat(64);

export interface AnchorProvider {
  /** 写入或覆盖式更新本 user 的锚定叶（钱包签名由 provider 用 walletSecret 生成） */
  publish(opts: { user: string; leaf: string; walletSecretHex: string }): AnchorBlock;
  latest(user: string): AnchorBlock | undefined;
  /** 全链回放校验（哈希链 + 钱包签名） */
  verifyAll(): boolean;
}

/** 本地 append-only 账本（P2 内宿实现；真链替换点见类注释） */
export class LedgerAnchor implements AnchorProvider {
  private chain: AnchorBlock[] = [];
  readonly file: string;

  constructor(dataDir: string) {
    this.file = path.join(dataDir, 'anchor_ledger.json');
    if (fs.existsSync(this.file)) {
      try {
        const raw = JSON.parse(fs.readFileSync(this.file, 'utf8')) as AnchorBlock[];
        if (Array.isArray(raw)) this.chain = raw;
      } catch (err) {
        this.chain = [];
      }
    }
  }

  publish(opts: { user: string; leaf: string; walletSecretHex: string }): AnchorBlock {
    const walletPub = bytesToHex(secp256k1.getPublicKey(new Uint8Array(Buffer.from(opts.walletSecretHex, 'hex'))));
    const walletSig = bytesToHex(secp256k1.sign(anchorBody(opts.user, walletPub, opts.leaf), new Uint8Array(Buffer.from(opts.walletSecretHex, 'hex'))));
    const prev = this.chain.length > 0 ? this.chain[this.chain.length - 1]?.blockHash ?? GENESIS_HASH : GENESIS_HASH;
    const block: AnchorBlock = {
      v: 1,
      seq: this.chain.length + 1,
      prev,
      ts: new Date().toISOString(),
      user: opts.user,
      walletPub,
      leaf: opts.leaf,
      walletSig,
      blockHash: '',
    };
    block.blockHash = blockHashOf(block);
    this.chain.push(block);
    this.persist();
    return block;
  }

  /** 同 user 的最新锚定（ENS 最新值语义）；每次调用重读账本文件——
   *  单机多进程共享账本，别处的 publish 必须立刻可见（等价真链 RPC 每查询读状态） */
  latest(user: string): AnchorBlock | undefined {
    this.reload();
    let found: AnchorBlock | undefined;
    for (const b of this.chain) if (b.user === user) found = b;
    return found;
  }

  private reload(): void {
    if (!fs.existsSync(this.file)) return;
    try {
      const raw = JSON.parse(fs.readFileSync(this.file, 'utf8')) as AnchorBlock[];
      if (Array.isArray(raw)) this.chain = raw;
    } catch (err) {
      // 撕裂/并发写窗口：维持旧 state（下一次重读复原），不崩
    }
  }

  /** 哈希链接力 + 每块钱包签名（incl genesis 0 前缀） */
  verifyAll(): boolean {
    let prev = GENESIS_HASH;
    for (let i = 0; i < this.chain.length; i++) {
      const b = this.chain[i] as AnchorBlock;
      if (b.seq !== i + 1 || b.prev !== prev || b.blockHash !== blockHashOf(b)) return false;
      try {
        if (!secp256k1.verify(new Uint8Array(Buffer.from(b.walletSig, 'hex')), anchorBody(b.user, b.walletPub, b.leaf), new Uint8Array(Buffer.from(b.walletPub, 'hex')))) return false;
      } catch {
        return false;
      }
      prev = b.blockHash;
    }
    return true;
  }

  private persist(): void {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    // 原子替换：写临时文件再 rename，避免多进程并发撕裂 JSON
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(this.chain, null, 2) + '\n');
    fs.renameSync(tmp, this.file);
  }
}

function blockHashOf(b: Omit<AnchorBlock, 'blockHash'> & { blockHash?: string }): string {
  const text = [ANCHOR_DOMAIN + '.blk', String(b.seq), b.prev, b.ts, b.user, b.walletPub, b.leaf, b.walletSig].join('|');
  return bytesToHex(sha256(utf8(text)));
}

/** 目录条目侧消费：比较"锚定叶"与"当前条目重算叶"，返回状态机结论 */
export function anchorMatch(
  latest: AnchorBlock | undefined,
  currentLeaf: string,
  entryWalletPub: string,
): 'unanchored' | 'match' | 'conflict' {
  if (latest === undefined) return 'unanchored';
  if (latest.walletPub !== entryWalletPub) return 'conflict';
  if (latest.leaf !== currentLeaf) return 'conflict';
  return 'match';
}
