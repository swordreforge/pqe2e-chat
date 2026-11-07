/**
 * fs 内存垫片（web 端）：src 纯协议模块里少数文件操作经 esbuild --alias:node:fs
 * 重定向到这里 → 浏览器端零原生依赖。持久化由 web 层走 localStorage（加密信封）。
 * 注意：本文件自身不得 import 任何 node 模块。
 */
type PathLike = string;
const mem = new Map<string, string>();

export function existsSync(p: PathLike): boolean {
  return mem.has(String(p));
}
export function readFileSync(p: PathLike): Uint8Array {
  const v = mem.get(String(p));
  if (v === undefined) throw new Error(`ENOENT: ${String(p)}`);
  return new TextEncoder().encode(v);
}
export function writeFileSync(p: PathLike, data: string | Uint8Array): void {
  mem.set(String(p), typeof data === 'string' ? data : new TextDecoder().decode(data));
}
export function mkdirSync(): string { return ''; }
export function renameSync(a: PathLike, b: PathLike): void {
  const v = mem.get(String(a));
  if (v !== undefined) { mem.set(String(b), v); mem.delete(String(a)); }
}
export function rmSync(p: PathLike): void { mem.delete(String(p)); }
export function statSync(): { isFile: () => boolean } { return { isFile: () => false }; }
export function dirname(p: string): string { return p; }
export function realpathSync(p: string): string { return p; }
export default { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync, rmSync, statSync, dirname, realpathSync };
