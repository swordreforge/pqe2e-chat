# pqe2e-chat

**Anti-quantum end-to-end encrypted chat** — a course capstone that runs entirely on one host.
Wallet-as-identity, hybrid post-quantum key agreement (ML-KEM-768 + X25519, transcript-bound),
Double Ratchet per-message forward secrecy, and a server that is treated as **untrusted by design**.

**抗量子的端到端加密聊天**：钱包即身份 · 混合 PQXDH（ML-KEM-768 + X25519）· 逐消息棘轮 ·
不可信中继（密文透传）· Web3 式可验证目录 · 浏览器/CLI 双端互通。

> 授课场景：网络安全大作业（TS 线）。完整安全论证见 [REPORT.md](REPORT.md)。

## Quick start / 快速开始

```bash
pnpm install            # versions exact-pinned (pnpm 10+ / node >= 26)
pnpm typecheck && pnpm test   # 8 files / 76 tests

pnpm server             # http://localhost:9090 (WebSocket on the same port)

# CLI client (any number of terminals)
PQE2E_PASS=<min-8-chars> pnpm client -- alice
PQE2E_PASS=<min-8-chars> pnpm client -- bob
#   type a line            -> encrypted to every online peer
#   #g help               -> group commands (create / add / kick / list)
#   #<gid> <text>         -> send to a group

# Browser client (React + Vite + Tailwind v4, zero external CDN/fonts)
pnpm web:build
#   open http://localhost:9090, register with username + passphrase (device key, NOT a login)
```

Demo tip: run the server, one CLI client and one browser client **at the same time** — they speak
the identical wire protocol. Capture traffic with `tcpdump -i lo port 9090 -X`: everything between
peers is ciphertext (msg/cntl/gmsg frames); the relay never sees plaintext.

## What's inside / 安全特性

| Layer | Mechanism | Where |
|---|---|---|
| Key agreement | Hybrid PQXDH-lite: ephemeral X25519 ‖ ML-KEM-768 encapsulation, transcript-bound HKDF | `src/channel.ts` |
| Messages | Double Ratchet: per-message keys (burn after use), skipped-key cache, replay rejection | `src/m4.ts` |
| Identity | Wallet (secp256k1) + ML-DSA-65 dual attestation; TOFU pinning | `src/attestation.ts`, `src/trust.ts` |
| Directory | Merkle inclusion proofs + wallet-signed append-only anchor ledger (ENS-equivalent seam) | `src/merkle.ts`, `src/anchor.ts` |
| Groups (MLS-lite) | leaf-self-generated seeds + signed seed claims (anti-impersonation), epoch rotation on join/kick | `src/gchain.ts`, `src/ggroup.ts` |
| Persistence | argon2id (m=8MiB, t=2) + XChaCha20-Poly1305 envelopes for identity/session-state/offline queue | `src/keystore.ts` |
| Web client | React + Vite + Tailwind v4 (Notion-style UI, zh/en i18n) | `web/` |

Design documentation: [README](REPORT.md) is the full thesis (threat→defense→test table,
protocol formulas, honest limitations). Engineering notes live in [NOTES.md](NOTES.md)
(append-only), toolchain pins in [TOOLCHAIN.md](TOOLCHAIN.md), milestone state in [PLAN.md](PLAN.md).

## Honest limitations / 诚实限界

- The anchor ledger is a **local** append-only log (ENS-equivalent protocol seam; a real chain
  needs an RPC + funded key — `AnchorProvider.publish/latest` is the swap point).
- Single-host relay; no metadata protection (pseudonymity ≠ anonymity).
- Groups are MLS-lite, not RFC 9420 (no tree-KEM; kicked members are silently disabled).
- argon2id params are course-tier compromises (m=8MiB, t=2); production should use ≥19MiB/t≥3.

## License

MIT — see `package.json`.
