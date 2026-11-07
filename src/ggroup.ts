/**
 * 群组逻辑（P1 · MLS-lite）：creater 管理 epoch（成员表 + 种子环）。
 *
 * epoch 载荷（走 pairwise E2EE 通道的 cntl 帧，收到即已过 T5 链完整性）：
 *   "gepoch|<gid>|<name>|<creator>|<ep>|<membersCsv>|<ringCsv>"
 *   ringCsv = "member:seedHex,..."（覆盖全员，persons 派生确定性排序）
 *
 * 接受规则：新 gid 直接加入；已存在组必须 creator 相同 && ep 严格增大 && ring 覆盖全员。
 * 踢人不通知被踢者——新链 seed 被踢者永不获得，其旧链帧在新 epoch 下 fail-closed。
 * 权限模型：**端侧 role=creator** 是唯一管理位（PLAN 决策②"权限随密钥走"的示范）。
 */
import { randomBytes } from '@noble/hashes/utils.js';
import { GChain } from './gchain.js';
import { bytesToHex } from '@noble/hashes/utils.js';

export type GChainMap = Map<string, GChain>;

export interface Group {
  gid: string;
  name: string;
  /** 唯一管理位 */
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
  /** member → seed(hex) */
  ring: Map<string, string>;
}

export const randomSeedHex = (): string => bytesToHex(randomBytes(32));

/** epoch 载荷规范化编码 */
export function encodeEpoch(p: EpochPayload): string {
  const members = [...p.members].sort().join(',');
  const ring = [...p.ring.entries()].sort().map(([m, s]) => `${m}:${s}`).join(',');
  return `gepoch|${p.gid}|${p.name}|${p.creator}|${p.ep}|${members}|${ring}`;
}

export function parseEpoch(text: string): EpochPayload | null {
  const f = text.split('|');
  if (f.length !== 7 || f[0] !== 'gepoch') return null;
  const gid = f[1] as string;
  const members = (f[5] as string).split(',');
  const ring = new Map<string, string>();
  for (const pair of (f[6] as string).split(',')) {
    const i = pair.indexOf(':');
    if (i <= 0) return null;
    ring.set(pair.slice(0, i), pair.slice(i + 1));
  }
  const ep = Number(f[4]);
  if (!Number.isInteger(ep) || ep < 1) return null;
  return { gid, name: f[2] as string, creator: f[3] as string, ep, members, ring };
}

/** epoch 合并校验：creator/ep/ring 三重闸门（fail-closed） */
export function applyEpoch(cur: Group | undefined, payload: EpochPayload, self: string): Group | null {
  if (!payload.members.includes(self)) return null; // 不是给我的（成员表外）
  if (!payload.members.includes(payload.creator)) return null; // creator 必须在群里
  // ring 必须覆盖全员
  for (const m of payload.members) if (!payload.ring.has(m)) return null;
  for (const m of payload.ring.keys()) if (!payload.members.includes(m)) return null;
  if (cur !== undefined) {
    if (cur.creator !== payload.creator) return null; // 抢管理位 = 拒收
    if (cur.gid !== payload.gid || cur.name !== payload.name) return null;
    if (payload.ep <= cur.ep) return null; // 旧/重放 epoch
  }
  const chains: GChainMap = new Map();
  for (const m of payload.members) {
    const seed = unhex(payload.ring.get(m) as string);
    if (seed.length !== 32) return null;
    chains.set(m, GChain.fromSeed(seed));
  }
  const g: Group = {
    gid: payload.gid,
    name: payload.name,
    creator: payload.creator,
    ep: payload.ep,
    members: [...payload.members].sort(),
    selfSeed: payload.ring.get(self) as string,
    chains,
  };
  return g;
}

/** creator 工具：构造"成员表 + 全新种子环"的 epoch（全员旋转 = PCS 语义） */
export function newEpochRoster(gid: string, name: string, creator: string, prevEp: number, members: string[]): EpochPayload {
  const uniq = [...new Set([...members, creator])].sort();
  const ring = new Map<string, string>();
  for (const m of uniq) ring.set(m, randomSeedHex());
  return { gid, name, creator, ep: prevEp + 1, members: uniq, ring };
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
  /** member → GState（chained 状态） */
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

const unhex = (hex: string): Uint8Array => new Uint8Array(Buffer.from(hex, 'hex'));
