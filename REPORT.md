# 抗量子端到端加密聊天应用 — 结题报告（完整版）

> 项目：`pqe2e-chat` · v0.1 · 2026-11
> 形态：TypeScript 单语言全栈（Node 中继 + CLI 端 + 浏览器端），单主机部署
> 代码：src 14 模块 2040 行 · web 3 文件 551 行 · 测试 7 文件 929 行（**73 用例全绿**）
> 过程资产：16 次提交、12 条工程问题日志（NOTES.md）、工具链冻结文档（TOOLCHAIN.md）
> 配套活文档：PLAN.md（里程碑+验证清单）、NOTES.md（只增日志）、TOOLCHAIN.md（钉死版本与库 API 形状）

---

## 1. 摘要

本项目在单主机上构建了一个**抗量子的端到端加密（E2EE）聊天系统**，三项核心安全设计：

1. **混合抗量子密钥协商（PQXDH-lite）**：临时 X25519 与 ML-KEM-768（FIPS 203）并联，
   transcript 全量绑定后 HKDF 派生会话根密钥——X25519 或 ML-KEM 任一侧被破（含量子攻击），
   另一侧仍守住机密性，对抗"先采集后破译"（Harvest-now-Decrypt-later, HNDL）；
2. **逐消息前向保密（Double Ratchet）**：会话根密钥之上展开双向棘轮链，消息密钥
   用后即焚、乱序容忍（跳号缓存）、重放必拒；
3. **Web3 式可验证身份**：钱包（secp256k1）+ ML-DSA-65（FIPS 204）双签 attestation、
   Merkle 目录包含证明、钱包签名 append-only 锚定账本（ENS 等价协议面）、
   TOFU 钉柱后备——**目录篡改在客户端离线可判**。

群聊以 MLS-lite 形态达成**最小完备**：成员自造种子（叶主权）+ 签名声明（抗协调者伪造）+
逐消息可见签名（抗种子泄露冒名）+ epoch 整轮旋转（踢人即失效）。系统遵循**权限随密钥走、
服务器仅作不可信中继**的 Web3 架构原则：无登录系统、无服务器侧 RBAC。

## 2. 选题背景与目标

### 2.1 问题定义

量子计算对现行公钥密码构成两类威胁：其一，破译非对称算法（ECDH/RSA）；其二，**记录今天的
密文，待具备量子算力后回头破译**（HNDL）。后者的可怕在于它不需要展望未来算力就能开始行动。
经典 E2EE（如 Signal 的 X3DH）的密钥协商完全依赖椭圆曲线，无法抵挡 HNDL。

### 2.2 目标（M1-M4 主线 + P0-P2 提升）

| 阶段 | 目标 | 完成状态 |
|---|---|---|
| M1 | 端到端加密聊天跑通（服务器只见密文） | ✅ `61c5d58` |
| M2 | 混合 PQXDH（ML-KEM-768 + transcript 绑定） | ✅ `4ff6183` |
| M3 | Web3 身份层（双签 attestation + TOFU） | ✅ `ba8ab46` |
| M4 | Double Ratchet（FS/乱序/重放） | ✅ `f88c6ac` |
| P0 | 会话状态加密持久化 → 重启零丢失 | ✅ `9717c17` |
| P1 | 群聊三次升级 → 冒名权彻底根除 | ✅ `a09bdb6`/`177398c`/`0024e3a` |
| P2.1 | Merkle 目录 + 钱包签名锚定账本 | ✅ `d117469` |
| P2.2 | 浏览器前端（Notion Style） | ✅ `acc41f0` |

### 2.3 设计纪律

- **不发明新密码学原语**：全部使用 NIST 已标准化算法与经探针实测的成熟库（noble 系）；
- **协议结构对齐 Signal 语义**（PQXDH / Double Ratchet / sender-key 演进），简化处均声明；
- **服务器零信任是设计前提也是验证点**（抓包演示全密文）；一切信任判定在客户端；
- 工程问题全部落档（NOTES.md 只增追加），两处安全级 bug 被自己的冒烟测试抓住并修复。

## 3. 总体设计

### 3.1 部署形态与信任声明

```
┌─────────────────────────────────────────────────────────────────┐
│ 中继服务器（不可信方 · src/server.ts）                            │
│  · hello→在线名单→dir 广播（含 merkle root + 各条目包含证明）       │
│  · invite/msg/cntl/gmsg 按 to 单播透传，绝不解析密文与握手包         │
│  · 同名连接重连接管（stale socket terminate）                      │
│  · 同端口挂载浏览器前端静态资源（web/，含目录穿越防护）              │
└───────────┬──────────────────────────┬──────────────────────────┘
            ▼ ws                       ▼ ws
      CLI 端（PQ框架同内核）        浏览器端（Notion Style · web/）
      身份/会话/群组三态            localStorage 加密信封 + 纯模块复用
```

"端"是唯一的信任主体；中继连邀请信令都不解析。**登录与 RBAC 的缺席是架构必然**
（决策记录 PLAN §7）：签名即凭证（M3 attestation 已是 Web3 登录的本质形态）；权限随密钥走，
不随服务器走；群管理权是**端侧 creator 角色**，不是服务器角色。

### 3.2 模块布局（src/ 2040 行）

| 模块 | 行数 | 职责 |
|---|---|---|
| `codec.ts` | 114 | 7 种线帧定义 + 服务器转来帧的最小结构校验（不保证内容可信） |
| `identity.ts` | 146 | 身份五密钥生成/加载；旧明文 → argon2id 信封迁移 |
| `channel.ts` | 134 | M1 静态通道 + **M2 混合 PQXDH-lite 握手**（initiator/responder） |
| `m4.ts` | 169 | **Double Ratchet**：双向轮换链、跳号缓存（窗口 1000）、已消费序号拒绝 |
| `gchain.ts` | 131 | **群发链**：共享 seed 副本消费，乱序/重放语义与 M4 同门 |
| `ggroup.ts` | 177 | 群组两阶段 epoch（groll/gclaim/gepoch）+ 四重闸门（creator/ep/ring/claims） |
| `attestation.ts` | 111 | 目录双签（wallet ECDSA + ML-DSA-65）、群消息可见签名 |
| `trust.ts` | 81 | TOFU 钉柱（wallet+mld 双锚点） |
| `keystore.ts` | 79 | **argon2id + XChaCha20-Poly1305 加密信封**（设备解锁密钥 → KEK） |
| `merkle.ts` | 63 | 目录树构建与包含证明（确定排序、odd 自配对） |
| `anchor.ts` | 165 | 目录叶哈希、锚定账本（append-only 哈希链 + 钱包签名）、三态比对 |
| `server.ts` | 134 | 不可信中继 + merkle 广播 + 静态挂载 |
| `client.ts` | 632 | CLI 全流程（会话自愈/离线补发/群命令/逐 seal 持久化） |
| `version.ts` | 5 | 里程碑常量 |

### 3.3 线协议（7 帧，JSON over WebSocket）

| 帧 | 方向 | 内容 | 安全面 |
|---|---|---|---|
| `hello` | C→S 完整身份条目 | user/x/kem/mld/w + 双签 sw/sp | 客户端自行验证（T2） |
| `dir` | S→众 root + 名册 | 各条目 + merkle 包含证明 | 客户端四层校验（T2） |
| `invite` | C→S→C | ephX + KEM 密文 | transcript 全绑定（T1） |
| `msg` | C→S→C | v/seq/nonce/ct | M4 棘轮 + AEAD AAD 绑 from\|to\|seq（T4/T5） |
| `cntl` | C→S→C | 同 msg 信封但载荷为控制明文（经 pairwise 加密） | 群组两阶段密钥面（T11） |
| `gmsg` | C→S→C | 同 msg + gid + **ML-DSA 可见签名** | 群链 + 防冒名（T8/T11） |
| `error` | S→C | 路由失败原因 | 触发离线回灌（P0） |

## 4. 协议分层详解（公式 → 实现 → 证据）

### 4.1 混合 PQXDH-lite（M2 · `channel.ts`）

```
发起方 B:  eph = X25519.keygen()
           dh   = X25519(eph.sk, A.xPub)                    经典侧
           (ss, ct) = ML-KEM768.encapsulate(A.kemPub)       量子侧
           ikm  = concat(dh ‖ ss ‖ eph.pk ‖ ct)             ← transcript 全绑定
           root = HKDF-SHA256(ikm, salt, "pqe2e/m2/<min>/<max>")
           ── invite{ephX, kem=ct} ──▶
响应方 A:  dh   = X25519(A.xSecret, ephX)；ss = KEM768.decapsulate(ct, A.kemSecret)
           同一 ikm 派生 → 同一 root（两侧通道上下文排序防角色混淆）
```

混合意图：X25519 与 ML-KEM **任一被破仍守住另一侧**。transcript 把临时公钥与密文一并纳入
IKM——篡改/降级/重排任一 → 双端密钥分叉（fail-closed）。
测试：`handshake.test.ts` 7 例（对称性、KEM 私钥错误分叉、隐式拒绝、eph 篡改、通道上下文隔离）。

### 4.2 Double Ratchet（M4 · `m4.ts`）

```
mk_i        = SHA256(chain_i ‖ "pqe2e/m4/mk")
chain_{i+1} = SHA256(mk_i ‖ "pqe2e/m4/mk/next")
```

- 双向链从 root 经 HKDF 64B 切分（双方名字排序定方向，防角色混淆）；
- 发送端每次 seal **用后即焚**并前推链头；接收端 skipped-cache 容忍乱序（窗口 1000）；
- **已消费序号重放必拒**——这是"前向保密"的可观测形态（旧帧密钥已不在任何状态中）；
- AAD 绑定 `sorted(from,to)|seq`（跨通道换向移动花接木必败）。

测试：`ratchet.test.ts` 11 例（顺序/乱序/迟到/全帧重放/五路篡改矩阵/快照无已用密钥/双向交织）。

### 4.3 Web3 身份层（M3 + P2.1 · `attestation.ts`/`trust.ts`/`merkle.ts`/`anchor.ts`）

**目录四层验证链**（客户端对 dir 广播每条目依次过闸）：

```
① Merkle 包含证明    leaf = SHA256("pqe2e/dirleaf/v1|user|w|x|kem|mld|sw|sp")
                     root 随 dir 广播；重放证明 → 视区一致性（T2 深化）
② 双签 attestation   sw = secp256k1(wallet, payload)；sp = ML-DSA65(mldsk, payload)
                     payload = "pqe2e/att/v1|user|x|kem|mld|w" → 两签同真才算数
③ 锚定账本比对       锚定叶 = 钱包签名 SHA256(...) 追加进 append-only 哈希链
                     （ENS 等价：setText=walletSigned publish / 最新值 / 轮换=再发布）
④ TOFU 钉柱          wallet+mld 双锚点；任一变更即 conflict（后备层）
```

- **离线可判**：服务器改一个字节（公钥替换）→ ①证明失败或③锚定冲突，客户端当场地拒；
- **owner 自愈**（冒烟实证的特殊性质）：历史块被改后，所有者下一次诚实发布会覆盖之
  （ENS 最新值语义）；诚实持续状态下攻击窗口只在篡改瞬间；
- **ENS 迁移缝线**：真链只需替换 `AnchorProvider.publish/latest` 两个函数
  （替换 `LedgerAnchor` → viem/ethers 的合约调用；映射见 §5 T2 注）。

测试：`attestation.test.ts` 9 例 + `anchored.test.ts` 9 例（奇偶叶证明/链签名/三态/序列化往返）。

### 4.4 会话与密钥的持久化（P0 · `keystore.ts` + client 生命周期）

```
KEK = argon2id(passphrase, salt, m=8MiB, t=2, dkLen=32)   ← 设备解锁密钥（非登录！）
ct  = XChaCha20-Poly1305(KEK, nonce24, aad=域)
```

- identity / M4 链状态（outSeq/inCursor/skipped-cache）/群组快照 → 加密信封；
- **每次 seal/open 后立即持久化链头**——冒烟曾抓到"重启从同链位重封 = mk 复用"的安全级
  bug（NOTES #11）；`gracefulExit` 同步落盘关闭退出竞态；
- 对端离线：帧入 pending 队列，dir 快照转在线时 FIFO 补发；WS error 回灌中标帧。

冒烟实证：alice 重启 → 链续接（seq 0→1→2 连续、无重握手）；bob 离线 → alice 入队 →
bob 上线补发解密。测试：`persistence.test.ts` 11 例（恢复续链/信封 fail-closed/迁移）。

### 4.5 群聊 MLS-lite（P1 三级升级 · `gchain.ts`/`ggroup.ts`）

**目标要害：creator 冒充他人群消息的权力必须被彻底拿掉**——路径 P1→P1.1→P1.2：

| 级 | 机制 | 消除的攻击面 |
|---|---|---|
| P1 | GChain：共享 seed 的对称棘轮流，副本消费，逐消息轮换 | 一次定终身的静态群钥 |
| P1.1 | **逐消息 ML-DSA 可见签名**（gid\|sender\|seq\|nonce\|ct） | **seed 泄露也无法冒名** |
| P1.2 | **叶自造 seed + 种子声明签名**：两阶段 groll(成员表+ep) → 成员自造 seed 回签
       claim(gid\|ep\|member\|seed) → creator 聚合 gepoch → **每位成员 apply 时逐条验 claim** | creator 从
       "代生成种子"降为纯协调者——**无内容伪造权**，仅余可用性权（缺席 roll 窗口即被弃，CLI 告警） |

剩余防盗逻辑：epoch 血线（creator 一致 / ep 严格递增 / ring 覆盖全员 / claim 逐条验签）；
踢人 = 不邀请进新 roll → 新 epoch 无他 → 其旧知识对新链失效（fail-closed，冒烟实证
"被踢者仍发消息 → 双端当场拒收"）。

测试：`group.test.ts` 15 例（流语义/乱序/旋转/闸门四组/快照/trust-store 缺陷 fail-closed/
假 claim 交互必败/持群 seed 冒名必败）。

### 4.6 浏览器端（P2.2 · `web/`）

**密码内核零重写**：`web/main.ts` 直接 import `../src/*` 纯协议模块；浏览器化仅两块垫片——
`Buffer` polyfill（noble 兼容）与 `esbuild --alias:node:fs=web/fsshim.ts`（内存垫片）。
持久化走 localStorage 内的 argon2id 信封（同 CLI 语义）；锚定账本为浏览器本机视角
（跨设备账本共识 = 真 ENS Provider 事，见 §8 限界）。
UI 按 Notion Style 令牌实现：`#f7f6f3` 底、`#efedea`/`#e3e1db` hover/active、
⋮⋮ 拖柄幻影（`opacity-0 group-hover:opacity-100`）、无渐变/无大圆角/无 translate/scale、
`prefers-reduced-motion` 全禁过渡。中继同端口挂载静态资源并做目录穿越防护。

## 5. 威胁模型 → 防御 → 证据（核心论据表）

| # | 威胁 | 防御机制 | 关键代码 | 测试证据 |
|---|---|---|---|---|
| T1 | HNDL 量子对手 | 混合 PQXDH-lite（X25519 ‖ ML-KEM-768）；transcript 全绑定 HKDF | `channel.ts` | `handshake.test` |
| T2 | 目录投毒/MITM | ① Merkle 包含证明 ② 双签 attestation ③ 锚定账本比对（含 owner 自愈）④ TOFU | `merkle.ts`/`attestation.ts`/`anchor.ts`/`trust.ts` | `anchored.test`/`attestation.test` |
| T3 | 降级/跨通道重排 | 域分隔 + 算法域进 HKDF info + transcript 绑定 | `channel.ts m2Info` | 通道名分叉用例 |
| T4 | 重放 | M4/GChain 已消费序号拒 + 窗口外丢弃 | `m4.ts consumeIn` | `ratchet.test` 全帧重放 |
| T5 | 篡改（ct/nonce/seq/AAD） | XChaCha20-Poly1305；AAD 绑 `sorted(from,to)+seq` / 群帧绑 `gid+sender` | `m4.ts`/`gchain.ts` | 篡改矩阵 |
| T6 | 泄钥→过去消息（FS） | 逐消息 mk 用后即焚、链单向 | `m4.ts` | 快照无已用密钥 |
| T7 | 泄钥→后续持续暴露（PCS） | 重连自愈再握手 / 群 epoch 整轮旋转 | `client.ts ensureSession`、`ggroup.ts` | 冒烟：重启后新 root tag |
| T8 | 会话/群串扰 | per-session root + 方向排序 + AAD 定向 | `m4.ts`/`gchain.ts` | 双向交织/跨群拒帧 |
| T9 | 别名劫持 | 重连接管 + 上层身份验证承担 | `server.ts hello` | 冒烟 graceful-exit |
| T10 | 时序侧信道比较 | 恒时比较惯例 | `channel.ts keyEqual` | `channel.test` |
| T11 | creator 代生成种子 → 冒充他人 | **叶自造 + 签名 claim + 逐条验签**（P1.2）；再加逐消息可见签名（P1.1）兜底 seed 泄露 | `ggroup.ts`/`attestation.ts` | `group.test` 假 claim/冒名用例 |
| T12 | 设备窃取 / 重启状态回退 | argon2id 信封 + **逐 seal 落盘**（回退会制造 mk 复用即破毁证据链） | `keystore.ts`/client 持久化 | `persistence.test` + NOTES #11 |

**T2 注（ENS 迁移映射）**：`AnchorProvider.publish/latest` 现为本地 `LedgerAnchor`；
接真链时 publish = 对 ENS 域名合约的 `setText("pqe2e-dirleaf", leafHex)` 交易（钱包签名在
链内天然存在），latest = provider 读最新值。Merkle/atf/TOFU 三层不变。
**诚实声明**：本地账本无全局共识与拜占庭写入者——这不是"真链"，是等价协议面（§8.1）。

## 6. 测试与验证（73/73 全绿）

| 文件 | 用例 | 覆盖 |
|---|---|---|
| `channel.test.ts` | 11 | 密钥对称/通道隔离/AEAD 三向篡改/恒时比较/身份持久化 |
| `handshake.test.ts` | 7 | 混合握手对称/错 key 分叉/隐式拒绝/transcript 绑定 |
| `attestation.test.ts` | 9 | 双签/字段篡改/单边伪造/名称置换/TOFU 三态/遗留迁移 |
| `ratchet.test.ts` | 11 | 顺序/乱序/重放/五路篡改矩阵/状态无已钥匙/跨会话隔离 |
| `persistence.test.ts` | 11 | 链位置恢复/信封 fail-closed(4)/身份迁移 |
| `group.test.ts` | 15 | 群流/乱序/重放/rotation/闸门四组/trust 缺陷/可见签名三例 |
| `anchored.test.ts` | 9 | merkle(1,3,5)/确定性/篡改/账本链/三态/全路径集成 |

**端到端冒烟（人工验证链）**：
1. M1：双向互通 + 服务器日志全密文（抓包演示）；
2. M2/M3：双端 root tag 一致；重启自愈新 tag ≠ 旧 tag；
3. P0：三连 seq 0→1→2 零丢失；离线补发收到 `#1 queued-while-bob-offline`；
4. P1.2：建群 claims 2/3→3/3→epoch1 apply；kick → epoch2 仅剩成员收发；被踢者拒收；
5. P2.1：3 块锚定账本（哈希链+签名）、merkle root 打印、"not yet anchored"→锚定 match；
   篡改账本 → owner 重发布自愈；
6. P2.2：`pnpm web:build`（334KB bundle + Minified tw.css，**零外部 CDN**）→ 同端口
   静态挂载、404/穿越防护、UI 装配自检（NOTES #13）、外部引用计数=0 验证（NOTES #14）。

## 7. 工程实践资产

1. **NOTES.md（12 条，只增日志）**：每条含现象/根因/修复/教训。代表性两条——
   #11 逐 seal 落盘缺失导致 mk 复用（安全级，冒烟抓住）；
   #7 `pkill -f` 自伤式匹配（先 pgrep 看命中再杀）。
2. **TOOLCHAIN.md**：依赖 exact-pin（`@noble/{curves,hashes,ciphers} 2.4.0`、
   `@noble/post-quantum 0.7.1`、TS 7.0.2 原生、pnpm 12.17.0）+ noble 2.x 实测 API 形状速查表。
3. **设计决策记录（PLAN §7）**：无登录（签名即凭证）、无服务器 RBAC（权限随密钥走）、
   假名定位（可溯源，元数据未保护）、浏览器端节奏（P2 末）。
4. **过程质量纪律**：类型门禁 `tsc --noEmit`（strict 全开）逐提交；提交按 Conventional
   Commits；冒烟先 `fuser -k <port>` 清残留（NOTES #6/#7）。

## 8. 诚实限界（答辩都比代码更先讲清楚的部分）

1. **锚定层**：本地账本**无全局共识**（无拜占庭写入者、无链间一致）——它是"ENS 等价
   协议面"而非真链；真链 Provider 需 RPC+资金私钥（课程环境外），接缝已留（§5 T2 注）；
   轻客户端状态根证明未做。
2. **无真分布式**：中继单机；传输层未接 Waku/libp2p；**元数据**（时长画像/在线时段/IP）
   未保护（假名≠匿名，PLAN 决策③）。
3. **投递回执缺席**：WS error 触发的离线入队是"known-failure"近似，无 ACK 协议；
   极端时序可能重复入队（接收端重放防御兜住，表现为一条 dropped 提示）。
4. **KDF 参数折中**：argon2id m=8MiB/t=2（生产 ≥19MiB/t≥3）；口令可见回显（课程语境）；
   trust.json 仅存公钥故明文。
5. **群聊与 RFC 9420 的差距**：无 tree-KEM/双棘轮路径更新；被踢者**静默失能**（不获通知）；
   入群成员必须在线应答 roll（6s 窗口，缺席即弃）。
6. **旁路安全**：无内存密钥擦除（zeroize）、无 RNG 独立性论证、无防故障注入；
   已覆盖恒时比较与 fail-closed 错误处理面。
7. **浏览器端**：锚定账本本机视角（见 §6.1）；样式与 bundle 已是**零外部 CDN 的本地
   产物**（Tailwind v4 本地构建，NOTES #14），限界剩余：浏览器端 UI 未做 add/kick。
   UI 未做 add/kick 按钮（CLI 全量可用，浏览器被动流转全通）。
8. **单主机范围**：分布式部署、对抗性 fuzz、正式协议形式化验证（ProVerif 级）均在范围外。

## 9. 运行手册

```bash
pnpm install                              # 版本钉死（TOOLCHAIN.md）
pnpm typecheck && pnpm test               # 7 文件 73 用例
pnpm web:build                            # css+bundle 本地构建（零外部 CDN）
pnpm server                               # http://localhost:9090（WS 同端口；先 fuser -k 清残留）

# CLI 端（多终端）
PQE2E_PASS=... pnpm client -- alice       # bob/carl 同理；直接打字 = 1:1 加密祈使
# 群聊：#g help / #g create <gid> <name> <成员...> / #<gid> <text> /
#       #g add <gid> <m>（creator·须在线）/ #g kick <gid> <m> / #g list

# 浏览器端：http://localhost:9090 → 用户名/设备口令/连接（与 CLI 同协议互通）
# 抓包演示：tcpdump -i lo port 9090 -X —— msg/cntl/gmsg 全为 base64 不可读
```

## 10. 结题评估与未来工作

**目标达成率**：M1-M4 全部验收、P0/P1/P2.1/P2.2 超出原计划范围完成；每条威胁都有可现场
运行的测试指认（§5 表）；两处安全级 bug 由自家冒烟抓住并留档——"调试手段即安全设计"
（同一口令解剖自己的加密 store）。

**未来工作（按价值排序）**：
1. 真 ENS Provider（测试网 Sepolia 合约调用，替换 AnchorProvider 两函数）；
2. Waku/libp2p 传输 + 元数据填充（cover traffic）；
3. tree-KEM 级群密钥树（向 RFC 9420 靠拢）、被踢者显式通知协议；
4. Rust 协议核心对照实现（`oqs`+`tokio`，内存/性能对比——PLAN 原始选型预案）；
5. `ink` TUI / 浏览器 add/kick UI、对抗性 fuzz、zeroize、投递 ACK 协议。

## 附录 A · 提交史（16 项，Conventional Commits）

```
c277222 chore: freeze toolchain        e0bdb0c chore: retire API probe
61c5d58 feat: M1 static e2ee chat      eb5cbc7 docs: engineering notes(10)
4ff6183 feat: M2 hybrid PQXDH-lite     ba8ab46 feat: M3 web3 identity layer
f88c6ac feat: M4 double ratchet        23f23e4 docs: REPORT v1
9717c17 feat: P0 persistence           ae6092a docs: design decision record
a09bdb6 feat: P1 mls-lite groups       177398c feat: P1.1 per-message mg-signatures
0024e3a feat: P1.2 leaf-self seeds     d117469 feat: P2.1 merkle+anchored directory
acc41f0 feat: P2.2 browser client      （本提交）docs: REPORT 完整版
```

## 附录 B · 依赖清单（exact pin，TOOLCHAIN.md 权威）

依赖：`@noble/ciphers 2.4.0`、`@noble/curves 2.4.0`、`@noble/hashes 2.4.0`、
`@noble/post-quantum 0.7.1`、`ws 8.22.1`、`buffer 6.0.3`；
开发：`typescript 7.0.2`（原生）、`tsx 4.23.15`、`vitest 5.1.0`、`esbuild 0.28.2`、
`@types/node 26.6.6`、`@types/ws 8.18.2`；平台 Node ≥26（实测 v26.13.0）/ pnpm 12.17.0。

---

*报告 v2.0（完整版）· 由 PLAN / TOOLCHAIN / NOTES 三文档支撑的活文档；行数与测试数字
皆为 2026-11-07 工作区实测（`wc -l` / `pnpm test`）。*
