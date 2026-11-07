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
}

export type Wire =
  | { kind: 'hello'; user: string; x: string }
  | { kind: 'dir'; roster: RosterEntry[] }
  | { kind: 'msg'; from: string; to: string; nonce: string; ct: string }
  | { kind: 'error'; reason: string };

export const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64');

export const unb64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64'));

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

export const asText = (b: Uint8Array): string => new TextDecoder().decode(b);

const isStr = (v: unknown): v is string => typeof v === 'string' && v.length > 0;

const isRoster = (v: unknown): v is RosterEntry[] =>
  Array.isArray(v) && v.every((e) => typeof e === 'object' && e !== null &&
    isStr((e as RosterEntry).user) && isStr((e as RosterEntry).x));

/**
 * 对服务器转来的帧做最基本的结构校验。
 * 服务器不可信：这里只保证"结构可解析"，不保证"内容可信"。
 */
export function parseWire(data: string): Wire {
  const w = JSON.parse(data) as Record<string, unknown>;
  switch (w.kind) {
    case 'hello':
      if (isStr(w.user) && isStr(w.x)) return { kind: 'hello', user: w.user, x: w.x };
      break;
    case 'dir':
      if (isRoster(w.roster)) return { kind: 'dir', roster: w.roster };
      break;
    case 'msg':
      if (isStr(w.from) && isStr(w.to) && isStr(w.nonce) && isStr(w.ct)) {
        return { kind: 'msg', from: w.from, to: w.to, nonce: w.nonce, ct: w.ct };
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
