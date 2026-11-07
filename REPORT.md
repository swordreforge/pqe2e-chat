# 抗量子端到端加密聊天 — 课程结题报告

> 项目 `pqe2e-chat` · M1–M5 全部完成 · 38 单测 + 两轮端到端冒烟
> 配套活文档：`PLAN.md`（里程碑状态回填）、`TOOLCHAIN.md`（工具链与库 API 形状）、
> `NOTES.md`（10 条工程问题只增日志）
> 提交序列：`c277222`→`61c5d58`→`eb5cbc7`→`4ff6183`→`ba8ab46`→`f88c6ac`

---

## 1. 选题与目标

在单主机上构建端到端加密（E2EE）即时聊天原型，突出两个主题：

1. **Web3 式身份**：钱包（secp256k1）作为"账户层"，通过双签 attestation 绑定抗量子密钥，
   TOFU 钉柱模拟链上不可变绑定（ENS/合约锚定的本地抽象）；
2. **抗量子端到端加密**：混合 PQXDH-lite（临时 X25519 + ML-KEM-768）抵御
   "先采集后破译"（HNDL）对手，Double Ratchet 提供逐消息**前向保密（FS）**与
   重放/乱序防御；妥协恢复（PCS）由对端重连自愈再握手实现。

设计纪律：**不发明新密码学原语**（noble 系列全用 NIST FIPS 203/204 已标準算法），
协议结构对齐 Signal 的 PQXDH/Double Ratchet 语义，工程问题全部落档可追溯。

## 2. 系统架构（终态）

```
┌──────────────────────────────────────────────────────────────┐
│ 中继服务器（不可信）：hello→名单→dir 广播；invite/msg 仅按 to 透传 │
└──────────────┬──────────────────────────┬────────────────────┘
               ▼                          ▼
 alice（发起恒定者，字典序小）             bob
 ─ 身份 identity.ts                       ─ 同
   x25519 + ML-KEM-768 + ML-DSA-65 + secp256k1
 ─ 目录验证 dir（双向防线）:                ─
   ① 双签 fail-closed (attestation.ts)
   ② TOFU wallet 钉柱   (trust.ts)
 ─ 会话 (M2) invite:                       ─ accept:
   eph=X25519()                            dh=X25519(my.x, ephX)
   dh =X25519(eph, bob.xPub)               ss =KEM768.decapsulate(ct)
   (ss,ct)=KEM768.env(bob.kemPub)          root = HKDF(dh‖ss‖eph‖ct)
   root= HKDF(dh‖ss‖eph‖ct)                → M4Channel（root 同一）
   → M4Channel ──────── 逐消息 ratchet 帧─────────────▶
     mk_i = SHA256(chain_i‖MK)      每帧：XChaCha20-Poly1305
     chain_{i+1} = SHA256(mk_i‖MK_NEXT)             AAD ‖ from‖to‖seq
```

模块与行数规模：`codec/identity/channel/m4/gchain/ggroup/attestation/trust/keystore/server/client + version` 约 1050 行 TS（不含注释与测试 350 行）。

### 2.1 群聊层（P1 · MLS-lite）

- **GChain（群链）**：每成员一条对称棘轮链 `mk_i = SHA256(chain_i‖MK)`，seed 经
  pairwise E2EE 分发副本，N 人共同消费同一流；AAD 绑定 `gid|sender`。
- **epoch（成员治理，唯一端侧权限角色 = creator）**：成员表 + 全新种子环整轮替换
  （入群/踢人都旋转全员）→ 踢人后旧链 fail-closed（被踢者**新消息当场拒收**，冒烟实证）；
  epoch 血线校验：creator 一致 / ep 严格递增 / ring 覆盖全员。
- 控制面复用 pairwise M4 通道（新增 `cntl` 帧）；群文本 `gmsg` 帧 GChain 直密封、服务器按 to 单播；
- 群状态持久化与 pairwise 会话同信封（`sessions_<user>.enc` 的 `groups` 字段）。

## 3. 威胁模型 → 机制 → 测试 映射表（论文核心论据）

| # | 威胁/攻击 | 防御机制 | 关键代码 | 测试证据 |
|---|---|---|---|---|
| T1 | HNDL 量子对手（今天抓包、未来破密钥） | 混合协商：X25519 与 ML-KEM-768 **任一被破仍守住另一侧**；root = HKDF(dh‖ss‖eph‖ct) | `channel.ts initiator/responderHandshake` | `handshake.test` 对称性/错误 KEM 私钥分叉 |
| T2 | 中继替换目录公钥（目录投毒/MITM） | ① ML-DSA-65 + wallet ECDSA **双签**条目（fail-closed）② wallet 公钥 TOFU 钉柱变更即拒 | `attestation.ts`/`trust.ts` | `attestation.test`（含"全新钥匙自称 alice"→ 双签过但 TOFU 捕获） |
| T3 | 降级攻击/跨通道重排 | 算法域常量进 HKDF info；payload 域分隔定序 | `channel.ts m2Info`、`attestationBytes` | 换通道名密钥必分叉测试 |
| T4 | 重放攻击 | M4 棘轮已消费序号拒绝 + 窗口外丢弃 | `m4.ts consumeIn` | `ratchet.test` 全帧重放全抛 |
| T5 | 密文/nonce/AAD 篡改 | XChaCha20-Poly1305 tag 校验，AAD 绑 `sorted(from,to)+seq` | `m4.ts seal/open` | 篡改矩阵 5 项全 fail-closed |
| T6 | 密钥泄露→过去消息泄密（FS） | 逐消息 mk **用后即焚**，链单向不可逆 | `m4.ts` | 快照 `skippedKeys=[]`、重放测试即"PAST 已不可解" |
| T7 | 会话泄露→后续消息持续暴露（PCS） | 对端重连 → dir 刷新自愈 → 新握手新链（旧链废弃） | `client.ts ensureSession` | 冒烟：bob 重启后新 root tag ≠ 旧 tag |
| T8 | 会话互相串扰/移花接木 | 通道方向排序 + per-session root；方向域独立 | `m4.ts` 构造 | 双向交织不串扰 + 跨会话帧永远打不开 |
| T9 | 别名劫持/重复连接 | 重连接管语义 + 身份真实性由 T2 层承担 | `server.ts hello` | 冒烟 graceful-exit 无 takeover 需要 |
| T10 | 时序侧信道比较 | 恒时比较惯例 | `channel.ts keyEqual` | `channel.test` |

## 4. 关键实现细节

- **握手（M2）**：一轮式"邀请"。发起方 `eph=X25519()` → `dh=X25519(eph.sk, A.xPub)`、
  `(ss, ct)=ML-KEM768.encapsulate(A.kemPub)`、`root = HKDF(sha256, dh‖ss‖eph‖ct, salt, "pqe2e/m2/<min>/<max>")`；
  transcript 全绑定（eph 公钥与密文一并进 ikm）→ 篡改/降级/重排任一 → 双端密钥分叉。
- **身份（M3）**：payload = `pqe2e/att/v1|user|x|kem|mld|w`；`sw`=钱包 ECDSA、`sp`=ML-DSA-65，
  验证须两签同时成立；攻击者必须同时攻破经典与 PQC 两个签名域。
- **棘轮（M4）**：双向独立链由 root 经 HKDF 64B 切分（名字排序定方向）；发送 `mk` 用后立刻
  `sha(mk‖MK_NEXT)` 前推；接收端 skipped-cache 容忍乱序（窗口 1000），迟到可解、重放/缺口超窗必拒。
- **密钥不落日志**：所有打印只有 sha256 前 12 hex tag；`NOTES.md` #6 对 EADDRINUSE 收窄处理。

## 5. 验收结果

- `pnpm typecheck`（strict 全开，含 noUncheckedIndexedAccess）零错误；
- `pnpm test`：**38/38**（channel 11 / handshake 7 / attestation 9 / ratchet 11）；
- 两轮端到端冒烟：常规互通 + 对端重启自愈（新会话 tag、老 tag 放弃）；
- 冒烟中服务器日志只见 name/route 事件与 base64 密文 → T1 采集根基可控演示。

## 6. 诚实限界（与真实产品的差距，答辩必备）

1. **TOFU ≠ 链上信任根**：本作品把"wallet→公钥"绑定存本地 JSON，首次见面即信任；
   真实方案应由 ENS/合约把绑定上链（不可变锚点 + 轮换需交易）。本作品仅做本质抽象。
2. **没有真正的分布式**：中继仍在单机；传输层未接入 Waku/libp2p；元数据（流量画像）未保护。
3. **状态持久化（P0 已解决）**：M4 链位置/乱序缓存/离线补发队列已加密持久化
   （argon2id 信封，决策见 PLAN §7）——重启零丢失；剩余 gap：正在发送中未确认帧
   无投递回执（服务器无回执协议），极端时刻可能重复入队（由接收端重放防御兜住）。
4. **密钥落盘已整定加密（P0 已解决）**：identity/会话状态均进 argon2id 信封
   （m=8MiB、t=2 折中参数；生产建议 m≥19MiB、t≥3）；trust.json 仅存公钥故仍明文；
   口令回显可见（课程语境限制），生产应 using no-echo getpass。
5. **群聊 MLS-lite（P1 已实现，与真 MLS 的差距）**：seed 由 **creator 代生成**（MLS 为叶自造
   → creator 可冒充他人群消息，属诚实限界）；被踢者不获通知（静默失能）；入群成员必须
   在线接收 epoch（离线入群需重发）；无正式 RFC 9420 的 tree-KEM 与双棘轮路径更新。
6. **旁路安全边界**：内存密钥擦除（zeroize）、RNG 独立性论证、防故障注入未覆盖；
   已覆盖的是恒时比较惯例与 fail-closed 的错误处理面。

## 7. 运行手册

```bash
pnpm install        # 版本钉死（TOOLCHAIN.md）
pnpm typecheck && pnpm test
pnpm server                          # 终端1（先 fuser -k 9090/tcp 清残留）
PQE2E_PASS=... pnpm client -- alice  # 终端2；bob/carl 同理（口令=设备解锁密钥）
# 1:1 聊天：直接输入一行 → 自动逐对端加密群发
# 群聊（P1）：#g help / #g create <gid> <name> <成员...> / #<gid> <text>
#            #g add <gid> <m>（creator·新成员须在线）/ #g kick <gid> <m> / #g list
# 抓包演示：tcpdump -i lo port 9090 -X —— 全程 base64 密文（msg/cntl/gmsg 均不可读）
```

## 8. 后续工作（对 PLAN.md §7 的优先级复述）

- P0：客户端重启消息队列零丢失；identity/skipped-cache 本地落盘加密（argon2id）；
- P1：真实链上锚定（测试网 ENS）、群聊 MLS（RFC 9420）树状密钥、目录 merkle 化；
- P2：Rust 协议核心（oqs + tokio）对照实现与内存/性能对比；
- P3：`ink` TUI 加分演示、附件加密（IPFS 模拟目录）、对抗性 fuzz。

---

*报告 v1.0 · 2026-11-07 · 由 PLAN/NOTES/TOOLCHAIN 三文档共同支撑的活文档*
