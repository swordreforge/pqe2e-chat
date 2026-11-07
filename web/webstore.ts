/**
 * web 端身份/信任/锚定存储适配（localStorage 版）：
 * - 身份：argon2id 信封（sealSecure/openSecure 纯函数）+ localStorage 持久化；
 * - trust/锚定账本：localStorage 简版。语义限界（写进报告 §6）：浏览器端账本仅本机
 *   视角（无跨设备共享文件），故仍具备 merkle 证明 + attestation + TOFU 三层；
 *   "所有者自愈"的锚定特性在 CLI 端已冒烟实证。
 */
import { createIdentity, type Identity } from '../src/identity.ts';
import { sealSecure, openSecure, type SecureBlob } from '../src/keystore.ts';

const IDENT_KEY = 'pqe2e.identity';
const PASS_MIN = 8;

export function ensureBrowserIdentity(user: string, pass: string): Identity {
  const raw = localStorage.getItem(`${IDENT_KEY}.${user}`);
  if (raw !== null) {
    const blob = JSON.parse(raw) as SecureBlob;
    return openSecure<Identity>(blob, pass, 'pqe2e/identity/v1');
  }
  if (pass.length < PASS_MIN) throw new Error(`passphrase too short (min ${PASS_MIN})`);
  const ident = createIdentity(user);
  localStorage.setItem(`${IDENT_KEY}.${user}`, JSON.stringify(sealSecure(ident, pass, 'pqe2e/identity/v1')));
  return ident;
}

export interface TrustEntry { wallet: string; mld: string; first: string }

/** 浏览器简版 TOFU（与 src/trust.ts 同语义；localStorage 持久化） */
export const webTrust = {
  load(): Record<string, TrustEntry> {
    const raw = localStorage.getItem('pqe2e.trust');
    if (raw === null) return {};
    try { return JSON.parse(raw) as Record<string, TrustEntry>; } catch { return {}; }
  },
  save(store: Record<string, TrustEntry>): void {
    localStorage.setItem('pqe2e.trust', JSON.stringify(store));
  },
  check(store: Record<string, TrustEntry>, user: string, wallet: string, mld: string): 'new' | 'pinned' | 'conflict' {
    const e = store[user];
    if (e === undefined) { store[user] = { wallet, mld, first: new Date().toISOString() }; return 'new'; }
    if (e.wallet !== wallet || e.mld !== mld) return 'conflict';
    return 'pinned';
  },
  pinnedMld(store: Record<string, TrustEntry>, user: string): string | undefined {
    return store[user]?.mld;
  },
};

/** 锚定账本（浏览器端简化：本机视角 + localStorage；跨设备账本共识留真 ENS Provider） */
export const webAnchor = {
  latest(user: string): { walletPub: string; leaf: string } | undefined {
    const raw = localStorage.getItem(`pqe2e.anchor.${user}`);
    if (raw === null) return undefined;
    try { return JSON.parse(raw) as { walletPub: string; leaf: string }; } catch { return undefined; }
  },
  publish(user: string, leaf: string, walletPubHex: string): void {
    localStorage.setItem(`pqe2e.anchor.${user}`, JSON.stringify({ walletPub: walletPubHex, leaf }));
  },
};
