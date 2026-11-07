/**
 * 群组逻辑（P1/A+B · MLS-lite）：种子**叶自造** + 种子声明签名。
 *
 * 时序（两阶段，creator 仅协调，无内容伪造权）：
 *   ① creator ──groll──▶ 成员:"轮换到 ep=N+1，成员表 X"
 *   ② 成员自造 seed_i，回 ──gclaim──▶ creator：描述 {gid,ep,member,seed} + ML-DSA 签名
 *   ③ creator 集合所有 claim → gepoch（ring=member:seed:sig）→ 全员
 *   ④ 每个成员 apply 时逐条**验 claim 签名**（钉柱 mld）→ creator 换/塞种子即败
 * 集合缺员（离线未回 claim）：creator 关窗后按**实际收到的 claim**组 epoch →
 * 缺席者落解析时代（fail-closed，CLI 告警）。
 *
 * 被踢者不参与新 groll/claim → 新 epoch 无他 → 其旧知识对新链失效（同 P1 冒烟实证）。
 * 权限模型不变：**creator 端侧管理位** + 全员验签（PLAN 决策②示范叠加体）。
 */
import { randomBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { GChain } from './gchain.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { utf8 } from './codec.js';

export type GChainMap = Map<string, GChain>;

export interface RingClaim {
  /** 种子（hex） */
  seed: string;
  /** 成员的 ML-DSA 签名（hex） */
  claim: string;
}

export interface Group {
  gid: string;
  name: string;
  /** 端侧唯一管理/协调位 */
  creator: string;
  ep: number;
  /** 排序成员表，含 self */
  members: string[];
  /** 本成员在当前 epoch ring 里的 seed（hex） */
  selfSeed: string;
  /** member → GChain：self 为发送方向，他人为接收方向 */
  chains: GChainMap;
}

export interface EpochPayload {
  gid: string;
  name: string;
  creator: string;
  ep: number;
  members: string[];
  /** member → seed + claimSig */
  ring: Map<string, RingClaim>;
}

export const randomSeedHex = (): string => bytesToHex(randomBytes(32));

const CLAIM_DOMAIN = 'pqe2e/seed-claim/v1';
const hexBytes = (hex: string): Uint8Array => new Uint8Array(Buffer.from(hex, 'hex'));

/** 种子声明载荷：声称 {gid,ep,member,seed} */
export function seedClaimBytes(gid: string, ep: number, member: string, seedHex: string): Uint8Array {
  return utf8([CLAIM_DOMAIN, gid, String(ep), member, seedHex].join('|'));
}

/** 成员自造 seed 后的声明签名（claimSig） */
export function signClaim(mldSecretHex: string, gid: string, ep: number, member: string, seedHex: string): string {
  return bytesToHex(ml_dsa65.sign(seedClaimBytes(gid, ep, member, seedHex), hexBytes(mldSecretHex)));
}

/** 独立验签助手（TOFU 钉柱 mld 公钥可用时） */
export function verifyClaimWithMld(
  mldPubHex: string | undefined,
  gid: string,
  ep: number,
  member: string,
  seedHex: string,
  claimSigHex: string,
): boolean {
  if (mldPubHex === undefined) return false;
  try {
    return ml_dsa65.verify(hexBytes(claimSigHex), seedClaimBytes(gid, ep, member, seedHex), hexBytes(mldPubHex));
  } catch {
    return false;
  }
}

/** epoch 规范化编码：ring = "member:seed:claimSig,..."; members/ring 都确定性排序 */
export function encodeEpoch(p: EpochPayload): string {
  const members = [...p.members].sort().join(',');
  const ring = [...p.ring.entries()].sort().map(([m, c]) => `${m}:${c.seed}:${c.claim}`).join(',');
  return `gepoch|${p.gid}|${p.name}|${p.creator}|${p.ep}|${members}|${ring}`;
}

export function parseEpoch(text: string): EpochPayload | null {
  const f = text.split('|');
  if (f.length !== 7 || f[0] !== 'gepoch') return null;
  const members = (f[5] as string).split(',');
  const ring = new Map<string, RingClaim>();
  for (const entry of (f[6] as string).split(',')) {
    const parts = entry.split(':');
    if (parts.length !== 3) return null;
    ring.set(parts[0] as string, { seed: parts[1] as string, claim: parts[2] as string });
  }
  const ep = Number(f[4]);
  if (!Number.isInteger(ep) || ep < 1) return null;
  return { gid: f[1] as string, name: f[2] as string, creator: f[3] as string, ep, members, ring };
}

/** 合并校验：creator/ep/ring 覆盖/claim 签名 四重闸门（fail-closed） */
export function applyEpoch(
  cur: Group | undefined,
  payload: EpochPayload,
  self: string,
  verifyClaim: (member: string, seedHex: string, ep: number, claimSig: string) => boolean,
): Group | null {
  if (!payload.members.includes(self)) return null;
  if (!payload.members.includes(payload.creator)) return null;
  for (const m of payload.members) if (!payload.ring.has(m)) return null; // ring 覆盖全员
  for (const m of payload.ring.keys()) if (!payload.members.includes(m)) return null;
  if (cur !== undefined) {
    if (cur.creator !== payload.creator) return null; // 抢管理位 = 拒收
    if (cur.gid !== payload.gid || cur.name !== payload.name) return null;
    if (payload.ep <= cur.ep) return null; // 旧/重放 epoch
  }
  const chains: GChainMap = new Map();
  for (const m of payload.members) {
    const rc = payload.ring.get(m) as RingClaim;
    if (!verifyClaim(m, rc.seed, payload.ep, rc.claim)) return null; // 冒名种子 = 拒收
    const seed = unhex(rc.seed);
    if (seed.length !== 32) return null;
    chains.set(m, GChain.fromSeed(seed));
  }
  return {
    gid: payload.gid,
    name: payload.name,
    creator: payload.creator,
    ep: payload.ep,
    members: [...payload.members].sort(),
    selfSeed: (payload.ring.get(self) as RingClaim).seed,
    chains,
  };
}

function unhex(hex: string): Uint8Array {
  const b = new Uint8Array(Buffer.from(hex, 'hex'));
  return b;
}

/**
 * 持久化快照（密钥材料，只允许进加密信封）
 */
export interface GroupSnapshot {
  v: 1;
  gid: string;
  name: string;
  creator: string;
  ep: number;
  members: string[];
  selfSeed: string;
  chains: Record<string, ReturnType<GChain['export']>>;
}

export function snapshotGroup(g: Group): GroupSnapshot {
  const chains: GroupSnapshot['chains'] = {};
  for (const [m, ch] of g.chains) chains[m] = ch.export();
  return { v: 1, gid: g.gid, name: g.name, creator: g.creator, ep: g.ep, members: g.members, selfSeed: g.selfSeed, chains };
}

export function restoreGroup(s: GroupSnapshot): Group | null {
  if (s.v !== 1) return null;
  const chains: GChainMap = new Map();
  try {
    for (const [m, st] of Object.entries(s.chains)) chains.set(m, GChain.restore(st));
  } catch (err) {
    return null;
  }
  return { gid: s.gid, name: s.name, creator: s.creator, ep: s.ep, members: s.members, selfSeed: s.selfSeed, chains };
}
