# 工具链固化清单（v1.0 · 2026-11-07 验证落盘）

> 本文件是项目工具链的**唯一权威依据**。所有版本经实测钉死（exact pin），
> 并附已验证的库 API 调用形状，供编码时直接对照，避免踩到 noble 2.x 的 API 变更。

## 1. 运行时与包管理

| 工具 | 固化版本 | 说明 |
|---|---|---|
| Node.js | **v26.13.0** | 当前 LTS；`engines: node >= 26` 已写入 package.json |
| pnpm | **12.17.0** | 包管理器（npm/yarn 均弃用）；锁文件 `pnpm-lock.yaml` 必须提交 |
| TypeScript | **7.0.2**（原生版） | `tsc --noEmit` 做类型门禁 |
| tsx | **4.23.15** | 开发期直接跑 `.ts`（`pnpm server` / `pnpm client`） |
| vitest | **5.1.0** | 单元/安全测试框架 |

### pnpm 12 配置要点（与其他版本不同）

- 构建脚本白名单已迁出 package.json 的 `pnpm` 字段，**配置在 `pnpm-workspace.yaml`**：

```yaml
# pnpm-workspace.yaml（已配置）
allowBuilds:
  esbuild: true
```

- 若未来新增带构建脚本的依赖，安装报 `ERR_PNPM_IGNORED_BUILDS` 时按此处理。

## 2. 锁定的依赖（exact pin）

| 包 | 版本 | 用途 |
|---|---|---|
| `@noble/curves` | 2.4.0 | X25519（经典 DH）、secp256k1（模拟钱包） |
| `@noble/post-quantum` | 0.7.1 | ML-KEM-768（FIPS 203）、ML-DSA-65（FIPS 204） |
| `@noble/hashes` | 2.4.0 | SHA-256、HKDF、随机数、hex 工具 |
| `@noble/ciphers` | 2.4.0 | XChaCha20-Poly1305（AEAD） |

传输层 `ws` 与 CLI/测试辅助工具留给 M1 实现时按同样流程"安装→验证→钉死"。

## 3. 已验证的 API 调用形状（noble 2.x 实测，编码对照用）

```js
import { x25519 } from '@noble/curves/ed25519.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

// 统一字段命名：secretKey / publicKey（没有 privateKey！）
x25519.keygen()      // => { secretKey(32B), publicKey(32B) }
x25519.getSharedSecret(secretKey, peerPublicKey)   // => Uint8Array(32)

secp256k1.keygen()   // => { secretKey(32B), publicKey(33B 压缩) }

// ML-KEM-768：字段是 cipherText（大写 T）
ml_kem768.keygen()   // => { publicKey(1184B), secretKey(2400B) }
ml_kem768.encapsulate(pub)         // => { cipherText(1088B), sharedSecret(32B) }
ml_kem768.decapsulate(cipherText, secretKey)  // => sharedSecret(32B)

// ML-DSA-65：注意参数顺序 —— **sign(msg, secretKey)**；verify(sig, msg, publicKey)
ml_dsa65.keygen()    // => { publicKey(1952B), secretKey(4032B) }
ml_dsa65.sign(msg, secretKey)      // => Uint8Array(3309B)
ml_dsa65.verify(sig, msg, publicKey)  // => boolean

// HKDF：hkdf(hash, ikm, salt, info, length)
hkdf(sha256, ikm, salt, info, 32)  // => Uint8Array(32)

// AEAD：AAD 在**工厂函数**绑定，encrypt/decrypt 顺序参数不含 AAD
const aead = xchacha20poly1305(key, nonce24, aadBytes);
aead.encrypt(plaintext)            // => 密文(+16B tag)，篡改/nullify 时 decrypt 抛异常
```

以上每条均通过 `test/_probe.mjs`（已留档于 git 历史）在 2026-11-07 实测通过。

## 4. 工程约定（固化）

- **语言**：TypeScript strict（`noUncheckedIndexedAccess` 等已开，见 tsconfig.json）；
- **模块**：ESM（`"type": "module"` + `NodeNext`）；导入 noble 一律带 `.js` 子路径后缀；
- **提交规范**：Conventional Commits（`feat:` / `fix:` / `test:` / `docs:` / `chore:`）；
- **命令**：`pnpm typecheck`（类型门禁）→ `pnpm test`（安全测试清单）→ 手动联调；
- **安全红线**：密钥材料不落日志、不进链上原文；`PLAN.md` §5 的验证清单为核心测试用例来源。

## 5. 版本升级策略

- 课程周期内（作业交付前）**禁止**升级这四个 noble 包与 TS 版本，避免 API 再变；
- 锁文件是唯一事实：换机器一律 `pnpm install`（自动按 lockfile 解析），不要手改版本号。
