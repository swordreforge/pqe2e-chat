/**
 * TOFU 信任锚定（M3 · 模拟"链上绑定"）：
 * wallet 公钥首次出现在已验证的目录条目里 → 钉柱（pin）进本地 trust.json；
 * 之后同一 user 的 wallet 公钥若与钉柱不符 → 冲突，条目作废并告警。
 * 等价于真实方案中 ENS/合约不可变的 wallet→公钥绑定；密钥轮换需显式删除钉柱
 * （data/trust.json），与真实链上的"轮换即新身份绑定交易"语义对应。
 */
import fs from 'node:fs';
import path from 'node:path';

export interface TrustEntry {
  /** 钉柱的 wallet 公钥（hex） */
  wallet: string;
  /** 钉柱的 ML-DSA-65 公钥（hex，attestation 绑定，用于群消息签名验证） */
  mld?: string;
  /** 首次钉柱时间 ISO */
  first: string;
}

export interface TrustStore {
  pinned: Record<string, TrustEntry>;
}

export type TrustResult = 'pinned' | 'new' | 'conflict';

export class TofuTrust {
  private store: TrustStore = { pinned: {} };
  readonly file: string;

  constructor(dataDir: string) {
    this.file = path.join(dataDir, 'trust.json');
    if (fs.existsSync(this.file)) {
      const raw = JSON.parse(fs.readFileSync(this.file, 'utf8')) as Partial<TrustStore>;
      if (typeof raw.pinned === 'object' && raw.pinned !== null) this.store = { pinned: raw.pinned };
    }
  }

  /** wallet 与 mld 都校验（mld 是群消息签名信任根）；返回判定的同时完成"首次即钉柱" */
  check(user: string, walletPubHex: string, mldPubHex?: string): TrustResult {
    const entry = this.store.pinned[user];
    if (entry === undefined) {
      this.store.pinned[user] = {
        wallet: walletPubHex,
        first: new Date().toISOString(),
        ...(mldPubHex !== undefined ? { mld: mldPubHex } : {}),
      };
      this.persist();
      return 'new';
    }
    if (entry.wallet !== walletPubHex) return 'conflict';
    if (mldPubHex !== undefined) {
      if (entry.mld === undefined) {
        entry.mld = mldPubHex; // 老钉柱缺 mld → 升级补钉
        this.persist();
        return 'pinned';
      }
      if (entry.mld !== mldPubHex) return 'conflict'; // mld 变更 = 目录中身份替换攻
    }
    return 'pinned';
  }

  /** 群消息签名验证用的钉柱 mld 公钥 */
  pinnedMld(user: string): string | undefined {
    return this.store.pinned[user]?.mld;
  }

  /** 显式换钥匙（模拟链上轮换交易）：删除钉柱，等待下次首次重钉 */
  unpin(user: string): void {
    delete this.store.pinned[user];
    this.persist();
  }

  pinned(user: string): TrustEntry | undefined {
    return this.store.pinned[user];
  }

  private persist(): void {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    fs.writeFileSync(this.file, JSON.stringify(this.store, null, 2) + '\n');
  }
}
