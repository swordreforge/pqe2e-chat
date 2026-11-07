/**
 * 浏览器客户端（React · P2.2 重写版）：
 * 复用 src 全部纯协议模块（混合 PQXDH / M4 棘轮 / 群组两阶段 / attestation / merkle / anchor）。
 * 与手写版的关键差异：**零手动 DOM 查询** —— 输入走 React ref，列表走状态驱动渲染，
 * 自此"渲染正常、点击读 null"一类的故障类在结构上不存在。
 * 限界：锚定账本为浏览器本机视角（跨设备共识属真 ENS Provider，REPORT §6.1）。
 */
import React, { useEffect, useRef, useState } from 'react';
import { Buffer } from 'buffer';
(globalThis as unknown as { Buffer: unknown }).Buffer = Buffer;

import { ensureBrowserIdentity, webTrust, webAnchor, type TrustEntry } from '../webstore.ts';
import type { Identity } from '../../src/identity.ts';
import { makeAttestation, verifyAttestation, signGmsg, verifyGmsg } from '../../src/attestation.ts';
import { parseWire } from '../../src/codec.ts';
import type { RosterEntry } from '../../src/codec.ts';
import { initiatorHandshake, responderHandshake } from '../../src/channel.ts';
import { M4Channel } from '../../src/m4.ts';
import type { M4State } from '../../src/m4.ts';
import {
  applyEpoch, parseEpoch, signClaim, randomSeedHex, encodeEpoch,
  snapshotGroup, restoreGroup, verifyClaimWithMld,
} from '../../src/ggroup.ts';
import type { Group, GroupSnapshot, EpochPayload } from '../../src/ggroup.ts';
import { dirLeafHex, dirLeafCanonicalText, anchorMatch, type AttestedBundle } from '../../src/anchor.ts';
import { verifyInclusion } from '../../src/merkle.ts';
import { sealSecure, openSecure } from '../../src/keystore.ts';
import { useTranslation } from 'react-i18next';
import i18n from 'i18next';

// ─────────────────────────── 引擎（命令式内核，框架只负责呈现） ───────────────────────────

interface Engine {
  peerInfo: Map<string, { x: string; kem: string }>;
  sessions: Map<string, M4Channel>;
  pending: Map<string, unknown[]>;
  inflight: Map<string, unknown[]>;
}
const engine: Engine = {
  peerInfo: new Map(), sessions: new Map(), pending: new Map(), inflight: new Map(),
};

interface LogRow { t: string; kind: 'sys' | 'warn' | 'msg' | 'group'; peer: string; text: string }

const groupsRef = { current: new Map<string, Group>() };
const trustRef = { current: {} as Record<string, TrustEntry> };
const identRef = { current: null as Identity | null };
const selfUserRef = { current: '' };
const devicePassRef = { current: '' };
const wsRef = { current: null as WebSocket | null };
const persistPending = { current: false };

// ─────────────────────────── 组件 ───────────────────────────

export function App(): React.ReactElement {
  const { t } = useTranslation();
  const [connected, setConnected] = useState(false);
  const [log, setLog] = useState<LogRow[]>([]);
  const [roster, setRoster] = useState<Array<{ user: string; session: boolean }>>([]);
  const [groups, setGroups] = useState<Array<{ gid: string; name: string; ep: number; members: string[] }>>([]);
  const [merkle, setMerkle] = useState('');
  const [target, setTarget] = useState<string | null>(null);

  const srvRef = useRef<HTMLInputElement>(null);
  const userRef = useRef<HTMLInputElement>(null);
  const passRef = useRef<HTMLInputElement>(null);
  const chatRef = useRef<HTMLInputElement>(null);
  const gGidRef = useRef<HTMLInputElement>(null);
  const gNameRef = useRef<HTMLInputElement>(null);
  const gMembersRef = useRef<HTMLInputElement>(null);
  const timelineRef = useRef<HTMLDivElement>(null);

  const pushLog = (kind: LogRow['kind'], peer: string, text: string): void => {
    setLog((prev) => [...prev.slice(-199), { t: new Date().toLocaleTimeString(), kind, peer, text }]);
  };
  const refreshLists = (): void => {
    setRoster([...engine.peerInfo.keys()].sort().map((u) => ({ user: u, session: engine.sessions.has(u) })));
    setGroups([...groupsRef.current.values()].map((g) => ({ gid: g.gid, name: g.name, ep: g.ep, members: [...g.members] })));
  };

  // ── 持久化（P0 语义：argon2id 信封 + localStorage） ──
  function persistNow(): void {
    if (identRef.current === null || devicePassRef.current === '' || persistPending.current === false) return;
    persistPending.current = false;
    const store = {
      v: 1,
      channels: [...engine.sessions.values()].map((c) => c.exportState()),
      groups: [...groupsRef.current.values()].map(snapshotGroup),
    };
    localStorage.setItem(`pqe2e.sessions.${selfUserRef.current}`,
      JSON.stringify(sealSecure(store, devicePassRef.current, 'pqe2e/sessions/v1')));
  }
  function persistSoon(): void {
    if (persistPending.current) return;
    persistPending.current = true;
    window.setTimeout(persistNow, 20);
  }
  function restoreEncryptedState(): void {
    const raw = localStorage.getItem(`pqe2e.sessions.${selfUserRef.current}`);
    if (raw === null) return;
    try {
      const store = openSecure<{ v: 1; channels: M4State[]; groups: GroupSnapshot[] }>(
        JSON.parse(raw) as never, devicePassRef.current, 'pqe2e/sessions/v1');
      for (const st of store.channels) {
        if (st.self !== selfUserRef.current) continue;
        try { engine.sessions.set(st.peer, M4Channel.restore(st)); } catch { /* 单条损坏即弃 */ }
      }
      for (const snap of store.groups) {
        const g = restoreGroup(snap);
        if (g !== null) groupsRef.current.set(g.gid, g);
      }
      pushLog('sys', '*', `restored ${store.channels.length} session(s), ${store.groups.length} group(s)（加密信封）`);
      refreshLists();
    } catch (e) {
      pushLog('warn', '*', `store open failed（口令不符？）: ${(e as Error).message}`);
    }
  }

  // ── 信封派发 / 会话 ──
  function dispatchWire(kind: 'msg' | 'cntl' | 'gmsg', peer: string, chan: M4Channel, plain: string, gid?: string): void {
    const ws = wsRef.current;
    if (ws === null) return;
    const f = chan.seal(plain, selfUserRef.current, peer);
    const wire: unknown = (kind === 'gmsg' && gid !== undefined)
      ? { kind, from: selfUserRef.current, to: peer, gid, v: 4, seq: f.seq, nonce: f.nonce, ct: f.ct }
      : { kind, from: selfUserRef.current, to: peer, v: 4, seq: f.seq, nonce: f.nonce, ct: f.ct };
    if (engine.peerInfo.has(peer)) {
      const infl = engine.inflight.get(peer) ?? []; infl.push(wire); engine.inflight.set(peer, infl);
      ws.send(JSON.stringify(wire));
    } else {
      const q = engine.pending.get(peer) ?? []; q.push(wire); engine.pending.set(peer, q);
      pushLog('sys', '*', `(${peer} offline: ${kind} seq=${f.seq} queued)`);
    }
    persistSoon();
  }

  function ensureSession(peer: string, force = false): void {
    if (engine.sessions.has(peer)) return;
    const info = engine.peerInfo.get(peer);
    if (info === undefined) return;
    if (selfUserRef.current >= peer && !force) return;
    const est = initiatorHandshake(info.x, info.kem, selfUserRef.current, peer);
    engine.sessions.set(peer, new M4Channel(est.key, selfUserRef.current, peer));
    wsRef.current?.send(JSON.stringify({ kind: 'invite', from: selfUserRef.current, to: peer, ephX: est.invite.ephX, kem: est.invite.kem }));
    pushLog('sys', '*', `pq-session ${selfUserRef.current}↔${peer} established (invite sent)`);
    persistSoon();
  }

  function flushPending(peer: string): void {
    const queue = engine.pending.get(peer);
    const ws = wsRef.current;
    if (queue === undefined || queue.length === 0 || ws === null) return;
    let n = 0;
    while (queue.length > 0) {
      const wire = queue.shift() as unknown;
      const infl = engine.inflight.get(peer) ?? []; infl.push(wire); engine.inflight.set(peer, infl);
      ws.send(JSON.stringify(wire)); n++;
    }
    if (n > 0) pushLog('sys', '*', `flushed ${n} queued frame(s) to '${peer}'`);
    persistSoon();
  }

  // ── 入站帧 ──
  function onWire(raw: string): void {
    let wire: import('../src/codec.js').Wire;
    try { wire = parseWire(raw); } catch { pushLog('warn', '*', '(dropped malformed frame)'); return; }
    switch (wire.kind) {
      case 'dir': {
        const before = new Set(engine.peerInfo.keys());
        const verified = new Map<string, { x: string; kem: string }>();
        for (const e of wire.roster) {
          if (e.user === selfUserRef.current) continue;
          const leaf = dirLeafHex(e as unknown as AttestedBundle);
          if (wire.root !== undefined && e.proof !== undefined &&
            !verifyInclusion(dirLeafCanonicalText(e as unknown as AttestedBundle), e.proof, wire.root)) {
            pushLog('warn', '*', `merkle proof FAILED for '${e.user}' — dropped`); continue;
          }
          if (!verifyAttestation(e)) { pushLog('warn', '*', `attestation INVALID for '${e.user}' — dropped`); continue; }
          const st = anchorMatch(webAnchor.latest(e.user), leaf, e.w);
          if (st === 'conflict') { pushLog('warn', '*', `ANCHOR CONFLICT for '${e.user}' — dropped`); continue; }
          if (st === 'unanchored') pushLog('sys', '*', `'${e.user}' not yet anchored in MY ledger（TOFU 后备层生效）`);
          const t = webTrust.check(trustRef.current, e.user, e.w, e.mld);
          if (t === 'conflict') { pushLog('warn', '*', `TOFU CONFLICT for '${e.user}' — dropped`); webTrust.save(trustRef.current); continue; }
          webTrust.save(trustRef.current);
          verified.set(e.user, { x: e.x, kem: e.kem });
        }
        engine.peerInfo.clear();
        for (const [u, v] of verified) engine.peerInfo.set(u, v);
        for (const p of engine.peerInfo.keys()) if (!before.has(p)) pushLog('sys', '*', `▶ ${p} online`);
        for (const p of before) if (!engine.peerInfo.has(p)) pushLog('sys', '*', `◀ ${p} offline (session retained)`);
        for (const [p] of engine.inflight) engine.inflight.delete(p);
        for (const p of engine.peerInfo.keys()) { ensureSession(p); flushPending(p); }
        setMerkle(wire.root === undefined ? '' : `merkle ${wire.root.slice(0, 12)}… · peers ${engine.peerInfo.size}`);
        refreshLists();
        break;
      }
      case 'invite': {
        if (identRef.current === null || wire.to !== selfUserRef.current) break;
        const key = responderHandshake(identRef.current.xSecret, identRef.current.kemSecret, wire, wire.from, wire.to);
        engine.sessions.set(wire.from, new M4Channel(key, selfUserRef.current, wire.from));
        pushLog('sys', '*', `pq-session ${wire.from}↔${selfUserRef.current} accepted`);
        persistSoon(); refreshLists();
        break;
      }
      case 'cntl': {
        if (wire.to !== selfUserRef.current) break;
        const chan = engine.sessions.get(wire.from);
        if (chan === undefined) { ensureSession(wire.from, true); break; }
        onControl(chan.open(wire, wire.from, wire.to), wire.from);
        break;
      }
      case 'msg': {
        if (wire.to !== selfUserRef.current) break;
        const chan = engine.sessions.get(wire.from);
        if (chan === undefined) { ensureSession(wire.from, true); break; }
        const text = chan.open(wire, wire.from, wire.to);
        pushLog('msg', wire.from, `#${wire.seq} ${text}`);
        persistSoon(); // 接收链头前推 → 落盘（NOTES #11）
        break;
      }
      case 'gmsg': {
        const g = groupsRef.current.get(wire.gid);
        const chan = g?.chains.get(wire.from);
        if (g === undefined || chan === undefined || !g.members.includes(wire.from)) {
          pushLog('warn', `[#g ${wire.gid}]`, `frame from '${wire.from}' cannot open — unknown group/sender`);
          break;
        }
        const senderMld = webTrust.pinnedMld(trustRef.current, wire.from);
        if (senderMld === undefined || !verifyGmsg(senderMld, wire.gid, wire.from, wire.seq, wire.nonce, wire.ct, wire.sig)) {
          pushLog('warn', `[#g ${g.name}]`, `signature INVALID from '${wire.from}' — impersonation?`);
          break;
        }
        const text = chan.open(wire, wire.gid, wire.from);
        pushLog('group', `${g.name} @${wire.from}`, `#${wire.seq} ${text}`);
        persistSoon();
        break;
      }
      case 'error': {
        const m = /peer '([^']+)' not online/.exec(wire.reason);
        if (m !== null && m[1] !== undefined) {
          const back: unknown[] = [...(engine.pending.get(m[1]) ?? []), ...(engine.inflight.get(m[1]) ?? [])];
          engine.inflight.delete(m[1]);
          engine.pending.set(m[1], back);
          pushLog('sys', '*', `queued ${back.length} frame(s) for offline '${m[1]}'`);
          persistSoon();
        } else {
          pushLog('warn', '*', `server error: ${wire.reason}`);
        }
        break;
      }
      default: break;
    }
  }

  // ── 群组控制面（两个阶段 roll，与 CLI 同语义） ──
  const rollsRef = useRef(new Map<string, { name: string; ep: number; members: string[]; claims: Map<string, { seed: string; sig: string }>; timer: number }>());

  function claimGate(gid: string, ep: number) {
    return (member: string, seedHex: string, _ep: number, claimSig: string): boolean =>
      verifyClaimWithMld((member === selfUserRef.current ? identRef.current!.mldPublic : webTrust.pinnedMld(trustRef.current, member)), gid, ep, member, seedHex, claimSig);
  }
  function startRoll(gid: string, name: string, ep: number, finalMembers: string[], tellList: string[]): void {
    const prev = rollsRef.current.get(gid);
    if (prev !== undefined) { window.clearTimeout(prev.timer); rollsRef.current.delete(gid); }
    const selfSeed = randomSeedHex();
    const selfSig = signClaim(identRef.current!.mldSecret, gid, ep, selfUserRef.current, selfSeed);
    const budget = {
      gid, name, ep, members: finalMembers,
      claims: new Map([[selfUserRef.current, { seed: selfSeed, sig: selfSig }]]),
      timer: window.setTimeout(() => finalizeRoll(gid), 6000),
    };
    rollsRef.current.set(gid, budget);
    for (const m of tellList) {
      if (m === selfUserRef.current || !engine.peerInfo.has(m)) continue;
      const chan = engine.sessions.get(m);
      if (chan === undefined) { ensureSession(m, true); continue; }
      dispatchWire('cntl', m, chan, `groll|${gid}|${name}|${selfUserRef.current}|${ep}|${finalMembers.join(',')}`);
    }
    pushLog('sys', '*', `[#g] roll to ep=${ep} dispatched; collecting signed claims (≤6s)`);
  }
  function finalizeRoll(gid: string): void {
    const b = rollsRef.current.get(gid);
    if (b === undefined) return;
    rollsRef.current.delete(gid);
    const ring = new Map<string, { seed: string; claim: string }>();
    for (const [m, c] of b.claims) ring.set(m, { seed: c.seed, claim: c.sig });
    const payload: EpochPayload = { gid: b.gid, name: b.name, creator: selfUserRef.current, ep: b.ep, members: b.members, ring };
    const applied = applyEpoch(groupsRef.current.get(gid), payload, selfUserRef.current, claimGate(gid, b.ep));
    if (applied === null) { pushLog('warn', '*','[#g] finalizeRoll rejected by gates — epoch kept'); return; }
    groupsRef.current.set(gid, applied);
    persistSoon();
    pushLog('sys', '*', `[#g] '${b.name}' epoch → ${applied.ep}（成员自造种子+声明签名；claims=${applied.members.length}）`);
    dispatchEpoch(applied, encodeEpoch(payload));
    refreshLists();
  }
  function dispatchEpoch(g: Group, announce: string): void {
    let missed = 0;
    for (const m of g.members) {
      if (m === selfUserRef.current) continue;
      const chan = engine.sessions.get(m);
      if (chan === undefined || !engine.peerInfo.has(m)) { missed++; continue; }
      dispatchWire('cntl', m, chan, announce);
    }
    if (missed > 0) pushLog('warn', '*', `[#g] ${missed} member(s) missed the epoch — re-add later`);
  }
  function onControl(payload: string, from: string): void {
    if (payload.startsWith('groll|')) {
      const f = payload.split('|');
      if (f.length !== 6) return;
      const gid = f[1] as string; const name = f[2] as string; const creator = f[3] as string;
      const ep = Number(f[4]); const members = (f[5] as string).split(',');
      const cur = groupsRef.current.get(gid);
      if (cur !== undefined && from !== cur.creator) { pushLog('warn', '*', `[#g ${gid}] groll from non-creator rejected`); return; }
      if (cur !== undefined && ep <= cur.ep) return;
      const selfSeed = randomSeedHex();
      const sig = signClaim(identRef.current!.mldSecret, gid, ep, selfUserRef.current, selfSeed);
      const chan = engine.sessions.get(from);
      if (chan === undefined) return;
      dispatchWire('cntl', from, chan, `gclaim|${gid}|${ep}|${selfUserRef.current}|${selfSeed}|${sig}`);
      pushLog('sys', '*', cur === undefined ? `[#g] invited to '${name}'/${gid} by '${from}' — replied signed seed claim` : `[#g] roll ep=${ep} responded`);
      return;
    }
    if (payload.startsWith('gclaim|')) {
      const f = payload.split('|');
      if (f.length !== 6) return;
      const gid = f[1] as string; const ep = Number(f[2]);
      const member = f[3] as string; const seed = f[4] as string; const sig = f[5] as string;
      const b = rollsRef.current.get(gid);
      if (b === undefined || ep !== b.ep) return;
      if (from !== member || !claimGate(gid, b.ep)(member, seed, b.ep, sig)) {
        pushLog('warn', '*', `[#g ${gid}] gclaim signature/origin mismatch — dropped`); return;
      }
      b.claims.set(member, { seed, sig });
      pushLog('sys', '*', `[#g] claim ${b.claims.size}/${b.members.length} for ep=${b.ep} (from '${member}')`);
      if (b.members.every((m) => m === selfUserRef.current || b.claims.has(m))) finalizeRoll(gid);
      return;
    }
    const epoch = parseEpoch(payload);
    if (epoch !== null) {
      const applied = applyEpoch(groupsRef.current.get(epoch.gid), epoch, selfUserRef.current, claimGate(epoch.gid, epoch.ep));
      if (applied === null) { pushLog('warn', '*', `[#g ${epoch.gid}] gepoch rejected (gate)`); return; }
      groupsRef.current.set(applied.gid, applied);
      persistSoon();
      pushLog('sys', '*', `[#g] group '${applied.name}' joined/advanced: epoch ${applied.ep}, members ${applied.members.join(',')}`);
      refreshLists();
      return;
    }
    pushLog('warn', '*', 'unknown control payload (fail-closed)');
  }

  // ── 发送 ──
  function onSend(): void {
    const input = chatRef.current;
    if (input === null || target === null) return;
    const text = input.value.trim();
    if (text.length === 0) return;
    input.value = '';
    if (target.startsWith('[g]')) {
      const gid = target.slice(3);
      const g = groupsRef.current.get(gid);
      const chan = g?.chains.get(selfUserRef.current);
      if (chan === undefined) { pushLog('warn', '*', 'no self chain (epoch glitch)'); return; }
      const f = chan.seal(text, g.gid, selfUserRef.current);
      const sig = signGmsg(identRef.current!.mldSecret, g.gid, selfUserRef.current, f.seq, f.nonce, f.ct);
      for (const m of g.members) {
        if (m === selfUserRef.current) continue;
        const wire: unknown = { kind: 'gmsg', from: selfUserRef.current, to: m, gid: g.gid, v: 4, seq: f.seq, nonce: f.nonce, ct: f.ct, sig };
        if (engine.peerInfo.has(m)) {
          const infl = engine.inflight.get(m) ?? []; infl.push(wire); engine.inflight.set(m, infl);
          wsRef.current?.send(JSON.stringify(wire));
        } else {
          const q = engine.pending.get(m) ?? []; q.push(wire); engine.pending.set(m, q);
        }
      }
      persistSoon();
      pushLog('group', `${g.name} @me`, `#${f.seq} ${text}`);
    } else {
      const chan = engine.sessions.get(target);
      if (chan === undefined) { pushLog('warn', '*', 'awaiting handshake'); ensureSession(target, true); return; }
      dispatchWire('msg', target, chan, text);
      pushLog('msg', `me→${target}`, text);
    }
  }

  function onCreateGroup(): void {
    const gid = (gGidRef.current?.value ?? '').trim();
    const name = (gNameRef.current?.value ?? '').trim();
    const members = (gMembersRef.current?.value ?? '').split(',').map((s) => s.trim()).filter((s) => s.length > 0);
    if (gid.length === 0 || name.length === 0) { pushLog('warn', '*', t('groupCreate.needGidName')); return; }
    const missing = members.filter((m) => !engine.peerInfo.has(m));
    if (missing.length > 0) {
      pushLog('warn', '*', t('groupCreate.missing', { list: missing.join(',') })); return;
    }
    startRoll(gid, name, 1, [...new Set([selfUserRef.current, ...members])].sort(), members);
  }

  // ── 连接 ──
  function onConnect(): void {
    const url = (srvRef.current?.value || 'ws://localhost:9090').trim();
    selfUserRef.current = (userRef.current?.value || '').trim();
    devicePassRef.current = passRef.current?.value ?? '';
    if (selfUserRef.current.length === 0) { pushLog('warn', '*', t('boot.needName')); return; }
    const ident = ensureBrowserIdentity(selfUserRef.current, devicePassRef.current);
    identRef.current = ident;
    const myAtt = makeAttestation({
      user: selfUserRef.current, xPub: ident.xPub, kemPublic: ident.kemPublic,
      mldSecret: ident.mldSecret, mldPublic: ident.mldPublic,
      wSecret: ident.wSecret, wPublic: ident.wPub,
    });
    trustRef.current = webTrust.load();
    const leaf = dirLeafHex({ user: selfUserRef.current, w: ident.wPub, x: ident.xPub, kem: ident.kemPublic, mld: ident.mldPublic, sw: myAtt.sw, sp: myAtt.sp });
    webAnchor.publish(selfUserRef.current, leaf, ident.wPub);
    restoreEncryptedState();

    const ws = new WebSocket(url);
    wsRef.current = ws;
    ws.onopen = () => {
      ws.send(JSON.stringify({ kind: 'hello', entry: { user: selfUserRef.current, ...myAtt } }));
      pushLog('sys', '*', `connected as "${selfUserRef.current}"（argon2id 信封已解封）`);
      setConnected(true);
      refreshLists();
    };
    ws.onerror = () => pushLog('warn', '*', 'connection error（服务器未开？）');
    ws.onmessage = (ev) => onWire(String(ev.data));
    ws.onclose = () => { setConnected(false); pushLog('warn', '*', 'connection closed'); };
  }

  useEffect(() => { timelineRef.current?.scrollTo({ top: timelineRef.current.scrollHeight }); });

  // ─────────── 渲染（Notion Style 令牌） ───────────
  const logRows = log.filter((r) => r.peer === target || r.peer === '*' || target !== null && r.peer.startsWith('me→')).slice(-80);
  void logRows;
  const shown: LogRow[] = target === null
    ? log.slice(-20)
    : log.filter((r) => target.startsWith('[g]')
      ? (r.kind === 'group' || r.kind === 'sys' || r.kind === 'warn')
      : (r.peer === target || r.peer === `me→${target}` || r.peer === '*' || r.kind === 'warn'))
      .slice(-80);

  return (
    <>
      <nav className="bg-white border-b border-gray-200 px-4 md:px-6">
        <div className="flex items-center justify-between max-w-6xl mx-auto gap-4 h-12">
          <div className="font-semibold text-gray-900 text-lg">pqe2e-chat</div>
          <div className="flex items-center gap-3 text-sm text-gray-600">
            <span className={'w-2 h-2 rounded-sm inline-block ' + (connected ? 'bg-[#0f7b6c]' : 'bg-[#eb5757]')}></span>
            <span>{connected ? t('nav.connected', { name: selfUserRef.current }) : t('nav.disconnected')}</span>
            <span className="font-mono text-gray-400">{merkle}</span>
            {/* 语言切换（Notion 克制式：仅背景加深，无位移） */}
            <div className="flex gap-1">
              {(['zh', 'en'] as const).map((lng) => (
                <button key={lng} onClick={() => { document.documentElement.lang = lng; void i18n.changeLanguage(lng); localStorage.setItem('pqe2e.lang', lng); }}
                  aria-label={`language ${lng}`}
                  className={'rounded-md px-2 py-1 text-xs transition-colors duration-150 ' + (i18n.language === lng ? 'bg-[#e3e1db] text-gray-900' : 'text-gray-600 hover:bg-[#efedea] active:bg-[#e3e1db]')}>
                  {lng === 'zh' ? '中' : 'EN'}
                </button>
              ))}
            </div>
          </div>
        </div>
      </nav>
      <main className="max-w-6xl mx-auto px-4 md:px-6 py-6">
        <section className="bg-white rounded-lg border border-gray-200 p-4 md:p-6">
          <h1 className="font-semibold text-gray-900 text-xl mb-1">{t('boot.title')}</h1>
          <p className="text-sm text-gray-600 mb-4">{t('boot.subtitle')}</p>
          <div className="flex flex-col md:flex-row gap-4">
            <input ref={srvRef} defaultValue="ws://localhost:9090" placeholder={t('boot.srv')} aria-label={t('boot.srv')}
              className="md:w-56 py-1 bg-transparent border-b border-transparent text-gray-900 text-sm focus:outline-none focus:border-b-2 focus:border-b-[#2383e2] transition-colors duration-150" />
            <input ref={userRef} placeholder={t('boot.username')} aria-label={t('boot.username')}
              className="md:w-40 py-1 bg-transparent border-b border-transparent text-gray-900 text-sm focus:outline-none focus:border-b-2 focus:border-b-[#2383e2] transition-colors duration-150" />
            <input ref={passRef} type="password" placeholder={t('boot.pass')} aria-label={t('boot.pass')}
              className="md:w-48 py-1 bg-transparent border-b border-transparent text-gray-900 text-sm focus:outline-none focus:border-b-2 focus:border-b-[#2383e2] transition-colors duration-150" />
            <button onClick={onConnect}
              className="rounded-md text-sm font-medium transition-colors duration-150 bg-[#2eaadc] text-white hover:bg-[#2896c4] active:bg-[#2383e2] px-3 py-1.5">
              {t('boot.connect')}
            </button>
          </div>
        </section>
        <section className="flex flex-col md:flex-row gap-4 mt-4 items-start">
          <aside className="w-full md:w-64 shrink-0 border border-gray-200 rounded-lg bg-[#f7f6f3] overflow-hidden">
            <div className="px-3 py-2 text-xs font-semibold text-gray-500 border-b border-gray-200">{t('side.contacts')}</div>
            <div>
              {selfUserRef.current !== '' && (
                <div className="group flex items-center gap-2 px-3 py-2 text-sm">
                  <span className="opacity-0 group-hover:opacity-100 transition-opacity duration-150 text-gray-400 select-none">⋮⋮</span>
                  <span className="font-semibold">{selfUserRef.current}</span><span className="text-gray-400 text-xs">{t('side.me')}</span>
                </div>
              )}
              {roster.map((r) => (
                <div key={r.user} onClick={() => setTarget(r.user)}
                  className={'group flex items-center gap-2 px-3 py-2 rounded-md cursor-pointer transition-colors duration-150 ' + (target === r.user ? 'bg-[#e3e1db]' : 'hover:bg-[#efedea]')}>
                  <span className="opacity-0 group-hover:opacity-100 transition-opacity duration-150 text-gray-400 select-none">⋮⋮</span>
                  <span className={'text-sm ' + (target === r.user ? 'font-semibold text-gray-900' : 'text-[#37352f]')}>{r.user}</span>
                  <span className={'text-xs ' + (r.session ? 'text-[#0f7b6c]' : 'text-gray-400')}>{r.session ? 'session' : '…'}</span>
                </div>
              ))}
            </div>
            <div className="px-3 py-2 text-xs font-semibold text-gray-500 border-b border-t border-gray-200 mt-2">{t('side.groups')}</div>
            <div>
              {groups.map((g) => (
                <div key={g.gid} onClick={() => setTarget(`[g]${g.gid}`)}
                  className={'group flex items-center gap-2 px-3 py-2 rounded-md cursor-pointer transition-colors duration-150 ' + (target === `[g]${g.gid}` ? 'bg-[#e3e1db]' : 'hover:bg-[#efedea]')}>
                  <span className="opacity-0 group-hover:opacity-100 transition-opacity duration-150 text-gray-400 select-none">⋮⋮</span>
                  <span className="text-sm text-[#37352f]">{g.name}</span>
                  <span className="text-xs text-gray-400">ep{g.ep} · {g.members.length}</span>
                </div>
              ))}
              {groups.length === 0 && <div className="px-3 py-2 text-sm text-gray-400">{t('side.emptyGroups')}</div>}
            </div>
            <div className="p-3 space-y-2 border-t border-gray-200">
              <input ref={gGidRef} placeholder={t('side.gid')} aria-label={t('side.gid')} className="w-full py-1 bg-transparent border-b border-transparent text-sm text-gray-900 focus:outline-none focus:border-b-2 focus:border-b-[#2383e2] transition-colors duration-150" />
              <input ref={gNameRef} placeholder={t('side.gname')} aria-label={t('side.gname')} className="w-full py-1 bg-transparent border-b border-transparent text-sm text-gray-900 focus:outline-none focus:border-b-2 focus:border-b-[#2383e2] transition-colors duration-150" />
              <input ref={gMembersRef} placeholder={t('side.members')} aria-label={t('side.members')} className="w-full py-1 bg-transparent border-b border-transparent text-sm text-gray-900 focus:outline-none focus:border-b-2 focus:border-b-[#2383e2] transition-colors duration-150" />
              <button onClick={onCreateGroup}
                className="w-full rounded-md text-sm font-medium bg-transparent text-[#37352f] hover:bg-[#efedea] active:bg-[#e3e1db] transition-colors duration-150 border border-gray-200 py-1.5">
                {t('side.create')}
              </button>
            </div>
          </aside>
          <div className="flex-1 w-full bg-white rounded-lg border border-gray-200 flex flex-col h-[60vh] md:h-[560px]">
            <div className="px-4 py-2 border-b border-gray-200 text-sm text-gray-500 flex items-center justify-between">
              <span>{target === null ? t('chat.noTarget') : target.startsWith('[g]') ? `${t('side.groups')} ${groupsRef.current.get(target.slice(3))?.name ?? ''}` : target}</span>
              <span className="font-mono text-xs text-gray-400">{t('chat.e2eNote')}</span>
            </div>
            <div ref={timelineRef} className="flex-1 overflow-y-auto p-2">
              {shown.length === 0 && <div className="px-3 py-6 text-sm text-gray-400">{t('chat.empty')}</div>}
              {shown.map((r, i) => (
                <div key={i} className="flex gap-3 px-3 py-1.5">
                  <span className="text-xs text-gray-400 shrink-0 w-20 font-mono">{r.t}</span>
                  <span className={'text-sm shrink-0 w-36 truncate ' + (r.kind === 'group' ? 'text-[#2eaadc]' : 'text-gray-600')}>{r.peer}</span>
                  <span className={'text-sm break-all ' + (r.kind === 'warn' ? 'text-[#eb5757]' : r.kind === 'sys' ? 'text-gray-400' : 'text-[#37352f]')}>{r.text}</span>
                </div>
              ))}
            </div>
            <div className="p-3 border-t border-gray-200 flex gap-2">
              <input ref={chatRef} onKeyDown={(ev: React.KeyboardEvent<HTMLInputElement>) => { if (ev.key === 'Enter') onSend(); }}
                placeholder={t('chat.placeholder')} aria-label={t('chat.placeholder')}
                className="flex-1 py-1.5 bg-transparent border-b border-transparent text-gray-900 text-sm focus:outline-none focus:border-b-2 focus:border-b-[#2383e2] transition-colors duration-150" />
              <button onClick={onSend}
                className="rounded-md text-sm font-medium transition-colors duration-150 bg-[#2eaadc] text-white hover:bg-[#2896c4] active:bg-[#2383e2] px-4">{t('chat.send')}</button>
            </div>
          </div>
        </section>
        <footer className="text-xs text-gray-400 mt-6 pb-8">{t('foot')}</footer>
      </main>
    </>
  );
}
