# 工程问题修复日志（Engineering Notes）

> 记录开发中真实踩到并已修复的工程/环境问题。
> 追加条目请复制下面的模板，**只增不改**（结论性内容如有反转，新条目覆盖说明，不删旧条目）。
> 最新条目在最下方。

```markdown
### <编号> <一句话标题>            （日期 · 提交号）
- 现象：
- 根因：
- 修复：
- 教训/复用：
```

---

### 1 pnpm 12 把构建脚本白名单迁出 package.json        （2026-11-07 · c277222）
- 现象：`pnpm install` 报 `ERR_PNPM_IGNORED_BUILDS`，esbuild 的 postinstall 被拦截；
  按 pnpm 10 的旧经验写 `package.json` 的 `pnpm.onlyBuiltDependencies` 无效。
- 根因：pnpm 12 改为从 `pnpm-workspace.yaml` 读 `allowBuilds`（**映射格式** `包名: true`），
  且旧的 `pnpm` 字段直接被忽略并告警。
- 修复：`pnpm-workspace.yaml` 中配置 `allowBuilds: { esbuild: true }`。
- 教训/复用：之后每次大版本工具链升级先跑 `pnpm install` 看告警；新增带构建脚本的依赖
  （如未来原生模块）同样走这里。白名单见 `TOOLCHAIN.md` §1。

### 2 noble 2.x API 面与旧资料差异大                  （2026-11-07 · c277222）
- 现象：手写示例代码按 1.x 记忆的说法直接崩（字段名/参数顺序/构造方式不对）。
- 根因：noble 家族 2.0 更新了统一命名与部分签名：
  - 统一 `secretKey`（不再有 `privateKey`）；ML-KEM 输出字段为 `cipherText`（大写 T）；
  - ML-DSA 是 `sign(msg, secretKek)` 强序、`verify(sig, msg, publicKey)`；
  - AEAD 的 AAD 在**工厂函数**绑定（`xchacha20poly1305(key, nonce, aad)`），
    `encrypt/decrypt` 不再单独收 AAD 参数；
  - hashes 的小哈希模块迁到 `@noble/hashes/sha2` 路径。
- 修复：写 `test/_probe.mjs` 逐一实测真实形态并留档，调用形状誊入 `TOOLCHAIN.md` §3。
- 教训/复用：接入新密码库，**先探针后编码**，把实测形状写进工具链文档，编码时对照抄。
  探针已退役，规则保留。

### 3 pnpm 的 `--` 分隔符会传进 node 进程 argv        （2026-11-07 · 61c5d58）
- 现象：`pnpm client -- bob` 启动的客户端把用户名解析成了 `--`，
  直接触发身份模块的用户名合法性报错。
- 根因：`pnpm run <script> -- <args>` 会原样保留 `--`；argv 为
  `[node, src/client.ts, "--", "bob"]`。
- 修复：客户端入口 `process.argv.slice(2).filter((a) => a !== '--')` 后取第一个参数。
- 教训/复用：写 CLI 入口先在冒烟脚本里打 `process.argv`，再写解析逻辑。

### 4 TS 7（原生）不把类型窄化传播进闭包              （2026-11-07 · 61c5d58）
- 现象：模块顶层 `typeof x !== 'string'` 早退守卫后，`x` 在 `ws.on('message', ...)` 等
  回调内仍被推断为 `string | undefined`，strict 下报错。
- 根因：原生 TS 编译器对跨函数边界的 CFA（控制流分析）窄化传播比旧编译器更保守；
  且 `process.exit()` 的 never-return 窄化在该版本未生效。
- 修复：守卫后显式固化 `const selfUser: string = argvName;`（带声明注解），闭包内一律用固化常量。
- 教训/复用：跨回调共享的"经校验值"用**显式类型注解的常量**承载，不依赖窄化生效范围。

### 5 stdin EOF 后进程不退出（挂住冒烟测试）          （2026-11-07 · 61c5d58）
- 现象：`( echo msg ) | pnpm client -- alice` 发完消息后进程悬挂 60s 超时。
- 根因：readline 结束了但 WebSocket 保持 open 状态，libuv 事件循环仍有句柄，进程不退出。
- 修复：`rl.on('close')` 里主动 `ws.close()` 并 `process.exit(0)`。
- 教训/复用：设计 CLI 客户端时把"输入通道结束"当作一等退出信号处理；
  管道式冒烟测试靠它。

### 6 服务端双开 → EADDRINUSE 裸崩且无诊断            （2026-11-07 · M2 起点）
- 现象：冒烟第二轮，第二个 server 实例 `listen EADDRINUSE:::9090` 无提示崩掉；
  真正服务请求的是第一次冒烟残留的旧实例（其日志混进新日志，误导定位）。
- 根因：① 第一次的 `pkill` 模式没杀干净 tsx 子进程；② server 对 `error` 事件无处理器。
- 处置：当场用 `fuser -k 9090/tcp` 按端口清理；测试统一先清端口再启动。
- 教训/复用：（待改进，M2 起实现）常驻服务应显式处理 EADDRINUSE，打印友好提示并退出；
  进程清理优先按**端口/套接字**，不用宽泛的 `pkill -f`（见问题 7）。

### 7 `pkill -f` 宽匹配会杀死执行脚本自身             （2026-11-07 · 61c5d58）
- 现象：`pkill -f "server.ts"` 后整个冒烟 shell 立即被 SIGKILL，后续步骤全部没跑。
- 根因：`-f` 匹配整条命令行，当前 shell 的命令字符串里本身就包含 "server.ts" 字样。
- 修复：改用 `fuser -k <port>/tcp` / `lsof -ti :<port>` 按端口杀；
  必须用 pkill 时先 `pgrep -fa <pattern>` 看命中名单再杀。
- 教训/复用：杀进程的操作**先列出目标、确认再杀**，避免自伤式匹配。

### 8 冒烟消息在连接握手前被 stdin 读走              （2026-11-07 · 61c5d58）
- 现象：alice 的消息在 `[chat] no peers online yet` 分支被吞掉，bob 始终收不到。
- 根因：readline 立刻可读，而 WS 连接 + hello + dir 广播是异步的——管道灌入时机早于
  "对端上线"事件。
- 修复：冒烟脚本在 echo 前加 `sleep`；更普适的修法是发送路径对"无会话"先握手再发送
  （M2 的会话自愈正好覆盖该场景，见 src/client.ts）。
- 教训/复用：异步系统的冒烟断言要钉在**事件边界**上，而不是秒级 sleep 拍脑袋；
  语义上的修复（按需握手）优于脚本时序的补丁。

### 9 EOF 退出时 close 帧未送达 → 服务器名单残留"幽灵用户"   （2026-11-07 · M2）
- 现象：冒烟第二轮 bob 重连报 `alias already online` 永久拒绝，alice 实际把消息
  发给了一个不存在的会话。
- 根因：客户端 `ws.close()` 后**立即** `process.exit(0)`，close 握手帧没机会发出；
  服务器端 roster 里旧连接一直挂着，重名保护误判为新冲突。
- 修复：客户端改为 `gracefulExit()`（先 close，等 close 事件或 250ms 兜底再退出）；
  服务器 hello 改为**重连接管**语义：同名连接直接 terminate 旧 socket、接受新连接
  （注脚：身份伪造防护由 M3 ML-DSA attestation 承担，接管语义已在 src/server.ts 文档化）。
- 教训/复用：**任何网络进程的退出路径都要过"关闭是否完成"这一关**；
  与问题 5 同根不同枝，EOF 语义 = 触发优雅退出流程，而不是硬 exit。

### 10 字典序大的一端重启后无会话，且自身被禁止发起 → 死角     （2026-11-07 · M2）
- 现象（推演+冒烟验证）：发起恒定规则下，若字典序大的一端（如 bob）重启丢会话，
  字典序小的一端（alice）缓存仍在、不会重握手，bob 又被"等对方发起"规则挡住 → 死锁。
- 根因：`selfUser >= peer → 不发起` 的防竞态规则只有一半的自愈敞口。
- 修复：握手路径保留字典序发起（防 dir 刷新时的双向竞争）；**聊天路径**遇
  "有消息、无会话"时 `ensureSession(peer, force=true)` 兜底发起（后到 invite 覆盖会话，
  FIPS 203 决议下竞态无害：最坏丢零星消息，无安全面）。
- 教训/复用：把"发起恒定"设计成**默认策略而非硬约束**，为恢复路径留受控敞口。

### 11 会话持久化缺逐 seal 落盘 → 重启后一次性密钥复用（安全级）  （2026-11-07 · P0）
- 现象：冒烟里 alice 重启后发消息，接收端还原链回退并成功解密"第二次加密"的帧；
  定位时用 test 脚本直接解剖加密 store 文件：alice `outSeq=1` 而 bob 已消费到 2。
- 根因：P0 持久化只在"建会话/入队/离线"触发；逐消息 seal 前推的链头（headOut）与
  接收侧 open 前推的链头（headIn/inCursor）**没有立即落盘**。重启后从旧链位置重新
  封包 = 一次性密钥 mk 被复用两次（同链位重放加密），棘轮大忌。
- 修复：①发送/接收路径每次 seal/open 成功后 `persistSoon()`（20ms 防抖合并突发）；
  ②退出竞态：`gracefulExit` 里 **同步** `persistNow()`——20ms 防抖会被 close→exit
  抢跑（冒烟第二遍顿悟的次级 bug）。
- 教训/复用：**逐消息推进的密码学状态必须在"每次使用后"持久化**（写放大是安全的正代价）；
  调试手段：用同一口令脚本化解剖自己的加密 store 验证状态字段（fail-closed 设计
  反过来帮了定位——只有真同事能读懂）。

### 12 群 epoch 成员表不去重 → creator 在新成员表重复出现（功能级）      （2026-11-07 · P1）
- 现象：`#g kick room1 carl` 后 epoch 日志显示 `members=alice,alice,bob`；
  dispatchEpoch 报 "members=3"（实际 2 人）。
- 根因：`newEpochRoster` 里 `[...members, creator]` 直接拼接（creator 已在 members 里），
  忘了 Set 去重；group 状态靠 Map 键天然去重掩盖了此错误。
- 修复：`[...new Set([...members, creator])].sort()`。
- 教训/复用：**去重在"数据结构入口"做，别在各消费点祈祷**；群成员表是集合语义
  而列表语义，排序只用做展示与确定性编码。

### 13 浏览器 UI 装配的"bundle/DOM 失配"故障类                 （2026-11-07 · P2.2）
- 现象：用户点击按钮 → `Cannot read properties of null (reading 'value')`（bundle 行号
  对应 g-create handler 读 `#g-gid`）；本地 DOM 检查 id 全在，难以从行号直判。
- 根因：**脚本与页面 DOM 的装配时序/缓存失配**类故障——顶层立即绑定，浏览器可能以
  旧缓存页面 + 新 bundle（或反之）组合加载；一旦元素缺失，崩溃点表现为千里之外的
  click 回调读 null。
- 修复（三层）：① REQUIRED_IDS 启动自检——缺任何 id 直接页面顶部红条列出，故障
  从"考古"变"自诊"；② 全部绑定挪进 `initUI()`，`document.readyState === 'loading'`
  时挂 DOMContentLoaded，杜绝早绑；③ 每个点击 handler 经 `safe()` 包装——UI 异常
  打上时间线与控制台，不再静默。另给 esbuild 加 `--sourcemap`，下次报错行号直通源码。
- 教训/复用：**浏览器 bundle 的 UI 故障先查"页面与 bundle 版本配对"**；交付形态必须
  自带装配自检（配置校验是前端的 healthcheck）。