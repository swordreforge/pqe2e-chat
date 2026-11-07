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

  /** 返回判定的同时完成"首次即钉柱"副作用；调用方须在管道层 verify 之后使用 */
  check(user: string, walletPubHex: string): TrustResult {
    const entry = this.store.pinned[user];
    if (entry === undefined) {
      this.store.pinned[user] = { wallet: walletPubHex, first: new Date().toISOString() };
      this.persist();
      return 'new';
    }
    if (entry.wallet !== walletPubHex) return 'conflict';
    return 'pinned';
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
