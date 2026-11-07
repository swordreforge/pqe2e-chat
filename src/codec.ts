/**
 * 线格式（wire format）：客户端 ↔ 中继服务器 与 客户端 ↔ 客户端 之间的 JSON 帧。
 * 中继服务器仅透传 `msg` 帧，不解析密文；`dir` 由服务器从 hello 维护后广播。
 *
 * M1 语义（在实现 PQXDH/attestation 前的已知缺陷，见 PLAN.md §6）：
 * - `dir` 目录由服务器广播、客户端按"不可信输入"对待 → 客户端必须校验来源；
 * - `msg.from` 由发送端自报，中继与服务器均不认证 → M3 用 ML-DSA attestation 修复；
 * - 全部二进制字段以 base64 字符串承载。
 */

export interface RosterEntry {
  user: string;
  /** X25519 静态公钥（hex） */
  x: string;
  /** ML-KEM-768 预共享公钥（hex，1184B） */
  kem: string;
  /** ML-DSA-65 公钥（hex） */
  mld: string;
  /** 钱包压缩公钥（hex） */
  w: string;
  /** wallet ECDSA 签名（hex） */
  sw: string;
  /** ML-DSA-65 签名（hex） */
  sp: string;
  /** P2.1 Merkle 包含证明（optional：老服务兼容） */
  proof?: Array<{ sib: string; right: boolean }>;
}

export type Wire =
  | { kind: 'hello'; entry: RosterEntry }
  | { kind: 'dir'; root?: string; roster: RosterEntry[] }
  /** M2 混合握手邀请：发起方 → 响应方 */
  | { kind: 'invite'; from: string; to: string; ephX: string; kem: string }
  /** M4 棘轮帧：每条消息独立轮换密钥 */
  | { kind: 'msg'; from: string; to: string; v: 4; seq: number; nonce: string; ct: string }
  /** P1 群控制帧（走 pairwise 通道；服务器不解内容） */
  | { kind: 'cntl'; from: string; to: string; v: 4; seq: number; nonce: string; ct: string }
  /** P1 群文本帧（GChain 群密文 + ML-DSA 发送者可见签名，防止 seed 泄露后冒名） */
  | { kind: 'gmsg'; from: string; to: string; gid: string; v: 4; seq: number; nonce: string; ct: string; sig: string }
  | { kind: 'error'; reason: string };

export const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64');

export const unb64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64'));

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

export const asText = (b: Uint8Array): string => new TextDecoder().decode(b);

const isStr = (v: unknown): v is string => typeof v === 'string' && v.length > 0;

const isProof = (v: unknown): v is Array<{ sib: string; right: boolean }> =>
  Array.isArray(v) && v.every((s) => typeof s === 'object' && s !== null &&
    typeof (s as { sib: unknown }).sib === 'string' && typeof (s as { right: unknown }).right === 'boolean');

const isRosterEntryObj = (e: unknown): e is RosterEntry =>
  typeof e === 'object' && e !== null && isStr((e as RosterEntry).user)
  && isStr((e as RosterEntry).x) && isStr((e as RosterEntry).kem)
  && isStr((e as RosterEntry).mld) && isStr((e as RosterEntry).w)
  && isStr((e as RosterEntry).sw) && isStr((e as RosterEntry).sp)
  && ((e as RosterEntry).proof === undefined || isProof((e as RosterEntry).proof));

const isRoster = (v: unknown): v is RosterEntry[] => Array.isArray(v) && v.every(isRosterEntryObj);

const isSafeSeq = (seq: unknown): seq is number => typeof seq === 'number' && Number.isInteger(seq) && seq >= 0 && seq < 2 ** 32;

const isHex64 = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);

/**
 * 对服务器转来的帧做最基本的结构校验。
 * 服务器不可信：这里只保证"结构可解析"，不保证"内容可信"。
 */
export function parseWire(data: string): Wire {
  const w = JSON.parse(data) as Record<string, unknown>;
  switch (w.kind) {
    case 'hello':
      if (isRosterEntryObj(w.entry)) return { kind: 'hello', entry: w.entry };
      break;
    case 'dir':
      if (isRoster(w.roster) && (w.root === undefined || isHex64(w.root))) {
        return { kind: 'dir', root: w.root, roster: w.roster };
      }
      break;
    case 'invite':
      if (isStr(w.from) && isStr(w.to) && isStr(w.ephX) && isStr(w.kem)) {
        return { kind: 'invite', from: w.from, to: w.to, ephX: w.ephX, kem: w.kem };
      }
      break;
    case 'msg':
      if (isStr(w.from) && isStr(w.to) && w.v === 4 && isSafeSeq(w.seq) && isStr(w.nonce) && isStr(w.ct)) {
        return { kind: 'msg', from: w.from, to: w.to, v: 4, seq: w.seq, nonce: w.nonce, ct: w.ct };
      }
      break;
    case 'cntl':
      if (isStr(w.from) && isStr(w.to) && w.v === 4 && isSafeSeq(w.seq) && isStr(w.nonce) && isStr(w.ct)) {
        return { kind: 'cntl', from: w.from, to: w.to, v: 4, seq: w.seq, nonce: w.nonce, ct: w.ct };
      }
      break;
    case 'gmsg':
      if (isStr(w.from) && isStr(w.to) && isStr(w.gid) && w.v === 4 && isSafeSeq(w.seq) && isStr(w.nonce) && isStr(w.ct) && isStr(w.sig)) {
        return {
          kind: 'gmsg', from: w.from, to: w.to, gid: w.gid, v: 4, seq: w.seq,
          nonce: w.nonce, ct: w.ct, sig: w.sig,
        };
      }
      break;
    case 'error':
      if (isStr(w.reason)) return { kind: 'error', reason: w.reason };
      break;
    default:
      break;
  }
  throw new Error(`unrecognized wire frame: ${data.slice(0, 120)}`);
}
