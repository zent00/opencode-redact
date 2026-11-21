# opencode-redact

[![CI](https://github.com/zent00/opencode-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/zent00/opencode-redact/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![OpenCode v2](https://img.shields.io/badge/OpenCode-v2.0%2B-black.svg)](https://opencode.ai)

**简体中文** | [English](./README.md)

面向 **OpenCode v2** 的本地双向隐私与密钥脱敏插件，核心设计借鉴 [yetone/magpie](https://github.com/yetone/magpie) 的 `internal/redact` 架构。

所有敏感信息（API Key、私钥、数据库连接密码、加密货币钱包私钥与助记词、邮箱、手机号、身份证、银行卡以及自定义敏感词）都会在请求离开本机**之前**被替换为确定性占位符，并在模型响应（含流式 SSE 与 WebSocket）返回本机时**实时无损还原**——OpenCode 本地界面、历史记录与工具执行始终看到真实值，上游模型供应商看不到敏感明文。

## 核心特性

- **双向透明传输拦截**：基于 OpenCode v2 的 `http.request` / `http.response` 与 `experimental.ws.send` / `experimental.ws.receive` Hook，无缝兼容 OpenAI-Compatible、Anthropic、OpenAI Responses（HTTP & WebSocket）、Gemini 等各类 Provider。
- **确定性占位符与仿形伪装（Format-Preserving）**：
  - 使用本地 32 字节密钥对 `kind + "\0" + value` 计算 HMAC-SHA256 + Base32，生成跨轮稳定的 `{{KIND_xxxxxxxx}}` 占位符。
  - 可选 `shape: true` 密钥仿形模式：保留原密钥前缀、长度、分隔符与字符类别（大小写/数字/hex），通过格式校验同时降低模型干扰。
  - `USERNAME` 替换为 8 位小写伪登录名（如 `/home/qmzvkrta`），公网 `IP` 替换为 `public-ip-xxxxxxxx`，避免模型将 `{{...}}` 误判为临时目录或拒绝执行 `ssh` 等工具调用。
- **协议感知 JSON 遍历与签名块保护**：
  - 自动跳过协议控制与关联 ID 字段（`id` / `*_id` / `model` / `role` / `data:` URI）。
  - 工具与输出 Schema 定义区（`tools` / `response_format` 等）仅脱敏 `description`，不破坏 Schema 或语法定义。
  - 保护供应商签名思考块（Anthropic `thinking.signature`、Gemini `thoughtSignature`、Responses `encrypted_content`），不运行常规规则，仅回填已知映射，防止上游报签名校验 400。
  - 工具参数区启用字段名识密（`namedSecret`）与嵌套 JSON 转义/引号边界裁剪（`outsideEscapes` + `inStrings`），确保嵌套 JSON 参数始终合法。
- **低误报多层规则引擎**：
  - **Secrets**：OpenAI / Anthropic / GitHub / Google / Slack / Stripe / AWS / HuggingFace / Cloudflare / Volcano Ark 等 API Key、PEM 私钥、JWT、URL 密码、环境变量与配置赋值、`Authorization`/`Cookie` 头、中日韩自然语言密码/密钥上下文，以及 13 类 Crypto 钱包私钥（含 Base58Check、Ed25519 派生、CRC16-XModem 校验）和 BIP-0039 助记词。
  - **Personal**：邮箱、中国手机号/身份证（含校验码与订单号区分）、银行卡（Luhn），以及可独立开关的 `ssn`、`passport`、`iban`（Mod-97）、`birthday`、`mac`、`serial`、`home`、`userhost`、`ip`、`bucket`。
  - **自定义词表与规则**：日期型自定义词多格式等价匹配（如 `1990-05-12` 自动等价匹配 `1990/5/12`、`1990年5月12日`、`19900512`、`May 12, 1990`）、整词/忽略大小写、自定义前缀/正则规则、白名单（`allow`）与按类型动作（`mask` / `warn` / `block`）。
- **Prompt Cache 前缀稳定**：`knownSpans` 已知值回溯、按路由隔离的 `sentKnownMemo` / `allowKeptMemo`（保证历史消息前缀不被新知识或白名单变更打穿缓存）以及长文本 `ruleMemo` 两代缓存。
- **SSE 与 WebSocket 流式还原**：跨事件 `partialTail` 尾缀暂存（无损拼接被切分的占位符）、`ping`/注释心跳直通、容错还原（容忍模型改大小写/加空格/丢花括号）及工具参数 JSON 二次转义。
- **本地交互命令与无明文审计**：提供 `/redact` 命令（`resume: false` 绝不唤醒模型）和按日轮转 JSONL 审计日志（绝不落盘任何敏感原文）。

## 安装与配置

> 需要 **OpenCode v2.0+**（已在 `opencode v2.3.2` 端到端实测通过）与 **Bun 1.3+**（源码构建）。

### 从源码构建并作为本地插件加载

```bash
git clone https://github.com/zent00/opencode-redact.git
cd opencode-redact
bun install
bun run build
```

在全局 `~/.config/opencode/opencode.jsonc` 或项目级 `opencode.json` 的 `plugins` 数组中添加：

```jsonc
{
  "plugins": [
    {
      "package": "file:///path/to/opencode-redact",
      "options": {
        "enabled": true,
        "secrets": true,
        "personal": true,
        "shape": false,
        "skipProviders": ["ollama", "magpie"],
        "kinds": {
          "home": false,
          "userhost": false,
          "ip": false,
          "bucket": false
        },
        "words": ["ProjectNightjar", "1990-05-12"],
        "wordsWhole": true,
        "rules": [
          { "kind": "CORP_TOKEN", "prefix": "corp_tok_" }
        ],
        "actions": {
          "PRIVATE_KEY": "block",
          "EMAIL": "warn"
        },
        "allow": ["public@acme.io"],
        "failClosed": true,
        "audit": {
          "enabled": true
        }
      }
    }
  ]
}
```

> **提示**：如果你同时通过本地 Magpie 网关访问模型且 Magpie 已开启脱敏，建议将 `"magpie"` 加入 `skipProviders` 以避免重复扫描。

## 配置项说明

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `enabled` | `boolean` | `true` | 初始运行开关（可通过 `/redact toggle` 动态切换）。 |
| `secrets` | `boolean` | `true` | 开启密钥、私钥、Token 与 Crypto 钱包脱敏。 |
| `personal` | `boolean` | `true` | 开启个人信息脱敏（邮箱、手机、身份证、银行卡及下方 `kinds`）。 |
| `kinds` | `Record<CategoryId, boolean>` | 见右 | Personal 细分开关。默认开启：`ssn`、`passport`、`iban`、`birthday`、`mac`、`serial`；默认关闭：`home`、`userhost`、`ip`、`bucket`。 |
| `words` | `string[]` | `[]` | 自定义敏感词列表（脱敏为 `TERM`），日期格式词自动展开为多格式等价匹配。 |
| `wordsAnyCase` | `boolean` | `false` | 自定义词忽略大小写匹配。 |
| `wordsWhole` | `boolean` | `false` | 自定义词仅整词匹配（中文/日文仍支持句中匹配）。 |
| `rules` | `Array<{ kind, prefix? \| regex? }>` | `[]` | 最多 32 条自定义规则（`prefix` 与 `regex` 二选一）。 |
| `actions` | `Record<string, "mask" \| "warn" \| "block">` | `{}` | 按类型覆盖动作：`mask`（默认脱敏）、`warn`（明文放行仅记录）、`block`（拦截请求）。 |
| `allow` | `string[]` | `[]` | 忽略大小写的整值白名单（最多 200 条）；显式 `words` 优先级高于 `allow`。 |
| `shape` | `boolean` | `false` | 对密钥启用同形假密钥伪装，而非 `{{KIND_xxxxxxxx}}`。 |
| `skipProviders` | `string[]` | `[]` | 跳过脱敏的 Provider ID 列表（忽略大小写）。 |
| `includeProviders` | `string[]` | `[]` | 若非空，则仅对列表中的 Provider 生效。 |
| `failClosed` | `boolean` | `true` | 脱敏处理异常时中断请求，拒绝泄露明文。 |
| `persistKey` | `boolean` | `false` | 将 32 字节 HMAC 密钥持久化到 `<stateDir>/redact.key`（权限 `0600`），跨重启保持一致占位符。 |
| `keyPath` | `string` | `undefined` | 自定义 HMAC 密钥文件路径。 |
| `stateDir` | `string` | `~/.config/opencode/opencode-redact` | 审计日志与可选持久化密钥的存储目录。 |
| `audit.enabled` | `boolean` | `true` | 开启无明文按日 JSONL 审计日志。 |
| `audit.dir` | `string` | `<stateDir>/audit` | `YYYY-MM-DD.jsonl` 日志目录。 |
| `audit.keepDays` | `number` | `30` | 审计日志保留天数（`1..365`）。 |
| `audit.keepBytes` | `number` | `104857600` | 审计日志总容量上限（默认 100 MiB）。 |

## Slash Commands

所有 `/redact` 命令均通过本地合成消息（`resume: false`）执行，绝不触发模型调用：

- `/redact status`：查看运行状态、启用规则、内存映射表与审计统计。
- `/redact preview <文本>`：本地预览脱敏结果与命中明细（不写入映射表、不发往模型）。
- `/redact toggle` / `/redact on` / `/redact off`：动态开关当前运行期脱敏。
- `/redact recent [数量]`：查看最近 `N` 条（默认 10 条）脱敏/拦截/还原记录。
- `/redact clear`：清空审计日志与统计计数（保留内存映射表，不影响在途会话还原）。
- `/redact help`：查看命令帮助。

## 本地开发

```bash
bun install
bun test          # 运行单元测试与插件集成测试
bun run typecheck # TypeScript 严格类型检查
bun run lint      # Biome 代码风格与静态检查
bun run build     # 编译 dist/
```

## 致谢

- 架构设计、规则体系、防误报策略、仿形伪装与 SSE 流式还原思路深度借鉴自 [yetone/magpie](https://github.com/yetone/magpie)（MIT License）。
- 助记词校验采用标准 [BIP-0039](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt) 英文词表。

## License

[MIT](./LICENSE)
