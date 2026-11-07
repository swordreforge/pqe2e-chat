/**
 * 浏览器客户端（P2.2 · Notion Style UI）：复用 src 全部纯协议模块。
 *   pnpm web:build && pnpm server   →  http://localhost:9090
 * 特性：1:1 混合 PQXDH-lite + M4 棘轮；群聊（epoch 声明制全流程）；
 * 目录四层验证（merkle/attestation/anchor/TOFU）；身份 argon2id 信封 + localStorage。
 * 限界：锚定账本为浏览器本机视角（跨设备账本共识属真 ENS Provider，见 REPORT §6.1）。
 */
import { Buffer } from 'buffer';

// Buffer 全局垫片（noble 系与 src 各纯模块依赖）
(globalThis as unknown as { Buffer: unknown }).Buffer = Buffer;

// —— 以下 import 需在垫片之后（esbuild 静态排序由依赖图保证） ——
import { ensureBrowserIdentity, webTrust, webAnchor, type TrustEntry } from './webstore.js';
import { parseWire } from '../src/codec.js';
import type { RosterEntry } from '../src/codec.js';
import { initiatorHandshake, responderHandshake } from '../src/channel.js';
import { M4Channel } from '../src/m4.js';
import type { M4State } from '../src/m4.js';
import { applyEpoch, parseEpoch, signClaim, randomSeedHex, encodeEpoch, snapshotGroup, restoreGroup, verifyClaimWithMld } from '../src/ggroup.js';
import type { Group, GroupSnapshot, EpochPayload } from '../src/ggroup.js';
import { makeAttestation, verifyAttestation, signGmsg, verifyGmsg } from '../src/attestation.js';
import { dirLeafHex, dirLeafCanonicalText, anchorMatch, type AttestedBundle } from '../src/anchor.js';
import { verifyInclusion } from '../src/merkle.js';
import { sealSecure, openSecure } from '../src/keystore.js';

// ─────────────────────────── 状态 ───────────────────────────

type Entry = { x: string; kem: string };
let ident: import('../src/identity.js').Identity | null = null;
let myAtt: ReturnType<typeof makeAttestation> | null = null;
let selfUser = '';
let trust: Record<string, TrustEntry> = {};
let devicePass = '';

const peerInfo = new Map<string, { x: string; kem: string }>();
const sessions = new Map<string, M4Channel>();
const groups = new Map<string, Group>();
const pending = new Map<string, unknown[]>();
const inflight = new Map<string, unknown[]>();
const timeline: Array<{ t: string; kind: 'msg' | 'sys' | 'group' | 'warn'; peer: string; text: string }> = [];
let currentTarget: string | null = null;
let rolls = new Map<string, { name: string; ep: number; members: string[]; claims: Map<string, { seed: string; sig: string }>; timer: number }>();

let ws: WebSocket | null = null;

const $ = (id: string): HTMLElement => document.getElementById(id) as HTMLElement;
const logSys = (text: string): void => { timeline.push({ t: new Date().toLocaleTimeString(), kind: 'sys', peer: currentTarget ?? '*', text }); renderTimeline(); };
const logWarn = (text: string): void => { timeline.push({ t: new Date().toLocaleTimeString(), kind: 'warn', peer: currentTarget ?? '*', text }); renderTimeline(); };

/** UI 装配自检：缺少任何必需 id → 明确列出（防"bundle 与页面 DOM 失配"故障类，NOTES 式要求） */
const REQUIRED_IDS = ['dot', 'st-text', 'merkle', 'srv', 'username', 'pass', 'connect', 'roster-list', 'group-list',
  'g-gid', 'g-name', 'g-members', 'g-create', 'target-label', 'timeline', 'chat-input', 'send'];

function assertIds(): boolean {
  const missing = REQUIRED_IDS.filter((id) => document.getElementById(id) === null);
  if (missing.length > 0) {
    console.error(`[ui] missing element ids (页面与 bundle 失配?): ${missing.join(', ')}`);
    document.body.insertAdjacentHTML('afterbegin',
      `<div class="bg-[#eb5757] text-white text-sm px-4 py-2">UI 装配失败：页面缺少元素 ${missing.join(', ')} — 请硬刷新（Ctrl+Shift+R）或重建 bundle（pnpm web:build）</div>`);
    return false;
  }
  return true;
}

// ─────────────────────────── UI：连接面板 ───────────────────────────

function onConnect(): void {
  try {
    const url = ($('#srv').value || 'ws://localhost:9090').trim();
    selfUser = ($('#username').value || '').trim();
    devicePass = ($('#pass').value || '');
    if (selfUser.length === 0) throw new Error('需要用户名');
    ident = ensureBrowserIdentity(selfUser, devicePass);
    myAtt = makeAttestation({
      user: selfUser, xPub: ident.xPub, kemPublic: ident.kemPublic,
      mldSecret: ident.mldSecret, mldPublic: ident.mldPublic,
      wSecret: ident.wSecret, wPublic: ident.wPub,
    });
    trust = webTrust.load();
    // 自锚定（浏览器本机账本）
    const leaf = dirLeafHex(bundleFrom(selfUser));
    webAnchor.publish(selfUser, leaf, ident.wPub);

    ws = new WebSocket(url);
    ws.onopen = () => {
      ws?.send(JSON.stringify({ kind: 'hello', entry: { user: selfUser, ...myAtt } }));
      logSys(`connected as "${selfUser}" — identity到账（argon2id 信封已解封）`);
      restoreEncryptedState();
      setConnected(true);
    };
    ws.onerror = () => logWarn('connection error（服务器未开？）');
    ws.onmessage = (ev) => onWire(String(ev.data));
    ws.onclose = () => { setConnected(false); logWarn('connection closed'); };
  } catch (e) {
    logWarn(`boot failed: ${(e as Error).message}`);
  }
}

/** UI 错误兜底：任何点击异常不再静默（页面上直接可见 + 控制台） */
function safe(fn: () => void): void {
  try { fn(); } catch (e) {
    const msg = (e as Error).message ?? String(e);
    console.error('[ui]', e);
    logWarn(`UI error: ${msg}`);
  }
}

function setConnected(ok: boolean): void {
  $('dot').className = ok ? 'bg-[#0f7b6c]' : 'bg-[#eb5757]';
  $('st-text').textContent = ok ? `已连接 · ${selfUser}` : '未连接';
}

/** 自描述身份包（供 leaf 与 attestation） */
function bundleFrom(user: string): AttestedBundle {
  return { user, w: ident!.wPub, x: ident!.xPub, kem: ident!.kemPublic, mld: ident!.mldPublic, sw: myAtt!.sw, sp: myAtt!.sp };
}

// ─────────────────────────── 加密状态持久化（P0 语义） ───────────────────────────

const STORE_KEY = 'pqe2e.sessions';

function restoreEncryptedState(): void {
  const raw = localStorage.getItem(STORE_KEY + '.' + selfUser);
  if (raw === null) return;
  try {
    const store = openSecure<{ v: 1; channels: M4State[]; groups: GroupSnapshot[] }>(JSON.parse(raw) as never, devicePass, 'pqe2e/sessions/v1');
    for (const st of store.channels) {
      if (st.self !== selfUser) continue;
      try { sessions.set(st.peer, M4Channel.restore(st)); } catch { /* 单条损坏即弃 */ }
    }
    for (const snap of store.groups) {
      const g = restoreGroup(snap);
      if (g !== null) groups.set(g.gid, g);
    }
    logSys(`restored ${store.channels.length} session(s), ${store.groups.length} group(s)（加密信封）`);
  } catch (e) {
    logWarn(`store open failed（口令不符？旧数据将重建）: ${(e as Error).message}`);
  }
}

function persistSoon(): void {
  if (ident === null) return;
  const store = { v: 1, channels: [...sessions.values()].map((c) => c.exportState()), groups: [...groups.values()].map(snapshotGroup) };
  localStorage.setItem(STORE_KEY + '.' + selfUser, JSON.stringify(sealSecure(store, devicePass, 'pqe2e/sessions/v1')));
}

// ─────────────────────────── 信封派发 / 会话 ───────────────────────────

function dispatchWire(kind: 'msg' | 'cntl' | 'gmsg', peer: string, chan: M4Channel, plain: string, gid?: string): void {
  if (ws === null || chan === undefined) return;
  const f = chan.seal(plain, selfUser, peer);
  const wire: unknown = (kind === 'gmsg' && gid !== undefined)
    ? { kind, from: selfUser, to: peer, gid, v: 4, seq: f.seq, nonce: f.nonce, ct: f.ct }
    : { kind, from: selfUser, to: peer, v: 4, seq: f.seq, nonce: f.nonce, ct: f.ct };
  if (peerInfo.has(peer)) {
    const infl = inflight.get(peer) ?? []; infl.push(wire); inflight.set(peer, infl);
    ws.send(JSON.stringify(wire));
  } else {
    const q = pending.get(peer) ?? []; q.push(wire); pending.set(peer, q);
    logSys(`(${peer} offline: ${kind} seq=${f.seq} queued)`);
  }
  persistSoon();
}

function ensureSession(peer: string, force = false): void {
  if (sessions.has(peer) || peerInfo.get(peer) === undefined) return;
  if (selfUser >= peer && !force) return; // 字典序发起恒定
  const info = peerInfo.get(peer) as { x: string; kem: string };
  const est = initiatorHandshake(info.x, info.kem, selfUser, peer);
  sessions.set(peer, new M4Channel(est.key, selfUser, peer));
  ws?.send(JSON.stringify({ kind: 'invite', from: selfUser, to: peer, ephX: est.invite.ephX, kem: est.invite.kem }));
  logSys(`pq-session ${selfUser}↔${peer} established (invite sent)`);
  persistSoon();
}

function flushPending(peer: string): void {
  const queue = pending.get(peer);
  if (queue === undefined || queue.length === 0 || ws === null) return;
  let n = 0;
  while (queue.length > 0) {
    const wire = queue.shift() as unknown;
    const infl = inflight.get(peer) ?? []; infl.push(wire); inflight.set(peer, infl);
    ws.send(JSON.stringify(wire)); n++;
  }
  if (n > 0) logSys(`flushed ${n} queued frame(s) to '${peer}'`);
  persistSoon();
}

// ─────────────────────────── 入站帧处理 ───────────────────────────

function onWire(raw: string): void {
  let wire: import('../src/codec.js').Wire;
  try { wire = parseWire(raw); } catch { logWarn('(dropped malformed frame from server)'); return; }
  switch (wire.kind) {
    case 'dir': {
      const before = new Set(peerInfo.keys());
      const verified = new Map<string, Entry>();
      for (const e of wire.roster) {
        if (e.user === selfUser || e.user === '') continue;
        const leaf = dirLeafHex(e as unknown as AttestedBundle);
        if (wire.root !== undefined && e.proof !== undefined &&
          !verifyInclusion(dirLeafCanonicalText(e as unknown as AttestedBundle), e.proof, wire.root)) {
          logWarn(`merkle proof FAILED for '${e.user}' — dropped`);
          continue;
        }
        if (!verifyAttestation(e)) { logWarn(`attestation INVALID for '${e.user}' — dropped`); continue; }
        const st = anchorMatch(webAnchor.latest(e.user), leaf, e.w);
        if (st === 'conflict') { logWarn(`ANCHOR CONFLICT for '${e.user}' — dropped（本机账本视角）`); continue; }
        if (st === 'unanchored') { logSys(`'${e.user}' not yet anchored in MY ledger（TOFU 后备层生效）`); }
        const t = webTrust.check(trust, e.user, e.w, e.mld);
        if (t === 'conflict') { logWarn(`TOFU CONFLICT for '${e.user}' — dropped`); webTrust.save(trust); continue; }
        webTrust.save(trust);
        verified.set(e.user, { x: e.x, kem: e.kem });
      }
      peerInfo.clear();
      for (const [u, v] of verified) peerInfo.set(u, v);
      for (const p of peerInfo.keys()) if (!before.has(p)) logSys(`▶ ${p} online`);
      for (const p of before) if (!peerInfo.has(p)) logSys(`◀ ${p} offline (session retained)`);
      for (const [p] of inflight) inflight.delete(p);
      for (const p of peerInfo.keys()) { ensureSession(p); flushPending(p); }
      renderRoster(); renderMerkleRoot(wire.root);
      break;
    }
    case 'invite': {
      if (ident === null || wire.to !== selfUser) break;
      const key = responderHandshake(ident.xSecret, ident.kemSecret, wire, wire.from, wire.to);
      sessions.set(wire.from, new M4Channel(key, selfUser, wire.from));
      logSys(`pq-session ${wire.from}↔${selfUser} accepted`);
      persistSoon();
      break;
    }
    case 'cntl': {
      if (wire.to !== selfUser) break;
      const chan = sessions.get(wire.from);
      if (chan === undefined) { ensureSession(wire.from, true); break; }
      const payload = chan.open(wire, wire.from, wire.to);
      onControl(payload, wire.from);
      break;
    }
    case 'msg': {
      if (wire.to !== selfUser) break;
      const chan = sessions.get(wire.from);
      if (chan === undefined) { ensureSession(wire.from, true); break; }
      const text = chan.open(wire, wire.from, wire.to);
      timeline.push({ t: new Date().toLocaleTimeString(), kind: 'msg', peer: wire.from, text });
      renderTimeline(); persistSoon(); // 接收链头前推 → 落盘（P0 语义）
      break;
    }
    case 'gmsg': {
      const g = groups.get(wire.gid);
      const chan = g?.chains.get(wire.from);
      if (g === undefined || chan === undefined || !g.members.includes(wire.from)) {
        logWarn(`[#g ${wire.gid}] frame from '${wire.from}' cannot open — unknown group/sender`);
        break;
      }
      const senderMld = webTrust.pinnedMld(trust, wire.from);
      if (senderMld === undefined || !verifyGmsg(senderMld, wire.gid, wire.from, wire.seq, wire.nonce, wire.ct, wire.sig)) {
        logWarn(`[#g ${g.name}] signature INVALID from '${wire.from}' — impersonation?`);
        break;
      }
      const text = chan.open(wire, wire.gid, wire.from);
      timeline.push({ t: new Date().toLocaleTimeString(), kind: 'group', peer: `${g.name} @${wire.from}`, text: `#${wire.seq} ${text}` });
      renderTimeline(); renderRoster(); persistSoon();
      break;
    }
    case 'error': {
      const m = /peer '([^']+)' not online/.exec(wire.reason);
      if (m !== null && m[1] !== undefined) {
        const back: unknown[] = [...(pending.get(m[1]) ?? []), ...(inflight.get(m[1]) ?? [])];
        inflight.delete(m[1]);
        pending.set(m[1], back);
        logSys(`queued ${back.length} frame(s) for offline '${m[1]}'`);
        persistSoon();
      }
      break;
    }
    default: break;
  }
}

// ─────────────────────────── 群组控制面（与 CLI 同语义） ───────────────────────────

function claimGate(gid: string, ep: number) {
  return (member: string, seedHex: string, _ep: number, claimSig: string): boolean =>
    verifyClaimWithMld((member === selfUser ? ident!.mldPublic : webTrust.pinnedMld(trust, member)), gid, ep, member, seedHex, claimSig);
}

function startRoll(gid: string, name: string, ep: number, finalMembers: string[], tellList: string[]): void {
  const prev = rolls.get(gid);
  if (prev !== undefined) { clearTimeout(prev.timer); rolls.delete(gid); }
  const selfSeed = randomSeedHex();
  const selfSig = signClaim(ident!.mldSecret, gid, ep, selfUser, selfSeed);
  const budget = {
    gid, name, ep, members: finalMembers,
    claims: new Map([[selfUser, { seed: selfSeed, sig: selfSig }]]),
    timer: window.setTimeout(() => finalizeRoll(gid), 6000),
  };
  rolls.set(gid, budget);
  for (const m of tellList) {
    if (m === selfUser || !peerInfo.has(m)) continue;
    const chan = sessions.get(m);
    if (chan === undefined) { ensureSession(m, true); continue; }
    dispatchWire('cntl', m, chan, `groll|${gid}|${name}|${selfUser}|${ep}|${finalMembers.join(',')}`);
  }
  logSys(`[#g] roll to ep=${ep} dispatched; collecting signed claims (≤6s)`);
}

function finalizeRoll(gid: string): void {
  const b = rolls.get(gid);
  if (b === undefined) return;
  rolls.delete(gid);
  const ring = new Map<string, { seed: string; claim: string }>();
  for (const [m, c] of b.claims) ring.set(m, { seed: c.seed, claim: c.sig });
  const payload: EpochPayload = { gid: b.gid, name: b.name, creator: selfUser, ep: b.ep, members: b.members, ring };
  const applied = applyEpoch(groups.get(gid), payload, selfUser, claimGate(gid, b.ep));
  if (applied === null) { logWarn(`[#g] finalizeRoll rejected by gates — epoch kept`); return; }
  groups.set(gid, applied);
  persistSoon();
  logSys(`[#g] '${b.name}' epoch → ${applied.ep}（成员自造种子+声明签名；claims=${applied.members.length}）`);
  dispatchEpoch(applied, encodeEpoch(payload));
  renderRoster();
}

function dispatchEpoch(g: Group, announce: string): void {
  let missed = 0;
  for (const m of g.members) {
    if (m === selfUser) continue;
    const chan = sessions.get(m);
    if (chan === undefined || !peerInfo.has(m)) { missed++; continue; }
    dispatchWire('cntl', m, chan, announce);
  }
  if (missed > 0) logWarn(`[#g] ${missed} member(s) missed the epoch — re-add later`);
}

function onControl(payload: string, from: string): void {
  if (payload.startsWith('groll|')) {
    const f = payload.split('|');
    if (f.length !== 6) return;
    const gid = f[1] as string; const name = f[2] as string; const creator = f[3] as string;
    const ep = Number(f[4]); const members = (f[5] as string).split(',');
    const cur = groups.get(gid);
    if (cur !== undefined && from !== cur.creator) { logWarn(`[#g ${gid}] groll from non-creator rejected`); return; }
    if (cur !== undefined && ep <= cur.ep) return;
    const selfSeed = randomSeedHex();
    const sig = signClaim(ident!.mldSecret, gid, cur === undefined ? ep : ep, selfUser, selfSeed);
    const chan = sessions.get(from);
    if (chan === undefined) return;
    dispatchWire('cntl', from, chan, `gclaim|${gid}|${ep}|${selfUser}|${selfSeed}|${sig}`);
    logSys(cur === undefined ? `[#g] invited to '${name}'/${gid} by '${from}' — replied signed seed claim` : `[#g] roll ep=${ep} responded`);
    return;
  }
  if (payload.startsWith('gclaim|')) {
    const f = payload.split('|');
    if (f.length !== 6) return;
    const gid = f[1] as string; const ep = Number(f[2]);
    const member = f[3] as string; const seed = f[4] as string; const sig = f[5] as string;
    const b = rolls.get(gid);
    if (b === undefined || ep !== b.ep) return;
    if (from !== member || !claimGate(gid, b.ep)(member, seed, b.ep, sig)) {
      logWarn(`[#g ${gid}] gclaim signature/origin mismatch — dropped`); return;
    }
    b.claims.set(member, { seed, sig });
    logSys(`[#g] claim ${b.claims.size}/${b.members.length} for ep=${b.ep} (from '${member}')`);
    if (b.members.every((m) => m === selfUser || b.claims.has(m))) finalizeRoll(gid);
    return;
  }
  const epoch = parseEpoch(payload);
  if (epoch !== null) {
    const applied = applyEpoch(groups.get(epoch.gid), epoch, selfUser, claimGate(epoch.gid, epoch.ep));
    if (applied === null) { logWarn(`[#g ${epoch.gid}] gepoch rejected (creator/ep/ring/claim gate)`); return; }
    groups.set(applied.gid, applied);
    persistSoon();
    logSys(`[#g] group '${applied.name}' joined/advanced: epoch ${applied.ep}, members ${applied.members.join(',')}`);
    renderRoster();
    return;
  }
  logWarn(`unknown control payload (fail-closed)`);
}

// ─────────────────────────── UI：发送路径 ───────────────────────────

// ─────────────────────────── UI 装配（DOMContentLoaded 安全绑定） ───────────────────────────

function onCreateGroup(): void {
  const gid = ($('#g-gid').value || '').trim();
  const name = ($('#g-name').value || '').trim();
  const members = ($('#g-members').value || '').split(',').map((s) => s.trim()).filter((s) => s.length > 0);
  if (gid.length === 0 || name.length === 0) { logWarn('#g create 需要 gid 与 name'); return; }
  const missing = members.filter((m) => !peerInfo.has(m));
  if (groups.has(gid) || missing.length > 0) { logWarn(`create: 成员须在线; missing/重复: ${missing.join(',')}`); return; }
  startRoll(gid, name, 1, [...new Set([selfUser, ...members])].sort(), members);
}

function initUI(): void {
  if (!assertIds()) return;
  $('connect').addEventListener('click', () => safe(onConnect));
  $('send').addEventListener('click', () => safe(onSend));
  $('chat-input').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') safe(onSend); });
  $('g-create').addEventListener('click', () => safe(onCreateGroup));
  $('target-label').textContent = '（未选择会话 — 左侧选择联系人或群）';
  renderRoster();
  renderTimeline();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initUI);
} else {
  initUI();
}

function onSend(): void {
  const input = $('chat-input') as HTMLInputElement;
  const text = input.value.trim();
  input.value = '';
  if (text.length === 0 || currentTarget === null) return;
  if (currentTarget.startsWith('[g]')) {
    const gid = currentTarget.slice(3);
    const g = groups.get(gid);
    const chan = g?.chains.get(selfUser);
    if (chan === undefined) { logWarn('no self chain (epoch glitch)'); return; }
    const f = chan.seal(text, g.gid, selfUser);
    const sig = signGmsg(ident!.mldSecret, g.gid, selfUser, f.seq, f.nonce, f.ct);
    for (const m of g.members) {
      if (m === selfUser) continue;
      const wire: unknown = { kind: 'gmsg', from: selfUser, to: m, gid: g.gid, v: 4, seq: f.seq, nonce: f.nonce, ct: f.ct, sig };
      if (peerInfo.has(m)) {
        const infl = inflight.get(m) ?? []; infl.push(wire); inflight.set(m, infl);
        ws?.send(JSON.stringify(wire));
      } else {
        const q = pending.get(m) ?? []; q.push(wire); pending.set(m, q);
      }
    }
    persistSoon();
    timeline.push({ t: new Date().toLocaleTimeString(), kind: 'group', peer: `${g.name} @me`, text: `#${f.seq} ${text}` });
    renderTimeline();
  } else {
    const chan = sessions.get(currentTarget);
    if (chan === undefined) { logWarn('awaiting handshake'); ensureSession(currentTarget, true); return; }
    dispatchWire('msg', currentTarget, chan, text);
    timeline.push({ t: new Date().toLocaleTimeString(), kind: 'msg', peer: `me→${currentTarget}`, text });
    renderTimeline();
  }
}

// ─────────────────────────── UI 渲染（Notion 风格） ───────────────────────────

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function renderRoster(): void {
  const peers = [...peerInfo.keys()].sort();
  const meRow = `<div class="group flex items-center gap-2 px-3 py-2 text-sm text-[#37352f]">
      <span class="opacity-0 group-hover:opacity-100 transition-opacity duration-150 text-gray-400 select-none">⋮⋮</span>
      <span class="font-semibold">${esc(selfUser)}</span><span class="text-gray-400 text-xs">me</span>
    </div>`;
  const peerRows = peers.map((p) => {
    const sel = currentTarget === p;
    const lay = sessions.has(p);
    return `<div data-peer="${esc(p)}" class="group peer-row flex items-center gap-2 px-3 py-2 rounded-md cursor-pointer ${sel ? 'bg-[#e3e1db]' : 'hover:bg-[#efedea]'} transition-colors duration-150">
      <span class="opacity-0 group-hover:opacity-100 transition-opacity duration-150 text-gray-400 select-none">⋮⋮</span>
      <span class="text-sm ${sel ? 'font-semibold text-gray-900' : 'text-[#37352f]'}">${esc(p)}</span>
      <span class="text-xs ${lay ? 'text-[#0f7b6c]' : 'text-gray-400'}">${lay ? 'session' : '…'}</span>
    </div>`;
  }).join('');
  const gRows = [...groups.values()].map((g) => {
    const sel = currentTarget === `[g]${g.gid}`;
    return `<div data-gid="${esc(g.gid)}" class="group g-row flex items-center gap-2 px-3 py-2 rounded-md cursor-pointer ${sel ? 'bg-[#e3e1db]' : 'hover:bg-[#efedea]'} transition-colors duration-150">
      <span class="opacity-0 group-hover:opacity-100 transition-opacity duration-150 text-gray-400 select-none">⋮⋮</span>
      <span class="text-sm text-[#37352f]">${esc(g.name)}</span>
      <span class="text-xs text-gray-400">ep${g.ep} · ${g.members.length}</span>
    </div>`;
  }).join('');
  $('roster-list').innerHTML = meRow + peerRows;
  $('group-list').innerHTML = gRows || '<div class="px-3 py-2 text-sm text-gray-400">（尚无群 — 创建一个）</div>';
  document.querySelectorAll('.peer-row').forEach((el) => el.addEventListener('click', () => {
    currentTarget = (el as HTMLElement).dataset.peer ?? null; renderRoster(); renderTimeline();
  }));
  document.querySelectorAll('.g-row').forEach((el) => el.addEventListener('click', () => {
    currentTarget = `[g]${(el as HTMLElement).dataset.gid ?? ''}`; renderRoster(); renderTimeline();
  }));
}

function renderTimeline(): void {
  const rows = timeline.filter((r) => r.peer === currentTarget || currentTarget === null).slice(-60).map((r) => {
    const tone = r.kind === 'warn' ? 'text-[#eb5757]' : r.kind === 'sys' ? 'text-gray-400 text-xs' : 'text-[#37352f]';
    return `<div class="flex gap-3 px-3 py-1.5 ${r.kind !== 'msg' && r.kind !== 'group' ? 'bg-[#efedea]/40' : ''}">
      <span class="text-xs text-gray-400 shrink-0 w-20 font-mono">${esc(r.t)}</span>
      <span class="text-sm shrink-0 w-32 truncate ${r.kind === 'group' ? 'text-[#2eaadc]' : 'text-gray-600'}">${esc(r.peer)}</span>
      <span class="text-sm ${tone} break-all">${esc(r.text)}</span>
    </div>`;
  }).join('');
  $('timeline').innerHTML = rows || '<div class="px-3 py-6 text-sm text-gray-400">— 暂无消息（左侧选择对端或群;直发文案已自动建立会话）—</div>';
  const box = $('timeline'); box.scrollTop = box.scrollHeight;
}

function renderMerkleRoot(root?: string): void {
  const el = $('merkle');
  if (root === undefined) { el.textContent = 'merkle root n/a'; return; }
  el.textContent = `merkle root ${root.slice(0, 12)}… · peers ${peerInfo.size}`;
}

export {};
