# opencode-redact

[![CI](https://github.com/zent00/opencode-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/zent00/opencode-redact/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![OpenCode v2](https://img.shields.io/badge/OpenCode-v2.0%2B-black.svg)](https://opencode.ai)

[简体中文](./README.zh-CN.md) | **English**

Bidirectional local privacy & secret redaction plugin for **OpenCode v2**, inspired by [yetone/magpie](https://github.com/yetone/magpie)'s `internal/redact` architecture.

Sensitive values (API keys, private keys, database passwords, crypto wallet keys, emails, phone numbers, IDs, and your own custom terms) are replaced with deterministic placeholders **before** requests leave your machine and transparently restored **as responses stream back**—so your local UI, session history, and tool executions always see the real values while upstream LLM vendors never do.

## Highlights

- **Bidirectional Transport Interception**: Hooks OpenCode v2's `http.request` / `http.response` and `experimental.ws.send` / `experimental.ws.receive`, working transparently across OpenAI-compatible, Anthropic, OpenAI Responses (HTTP & WebSocket), Gemini, and other providers.
- **Deterministic Placeholders & Format-Preserving Stand-Ins**:
  - Uses local HMAC-SHA256 + Base32 to generate stable `{{KIND_xxxxxxxx}}` placeholders across turns.
  - Optional `shape: true` mode replaces secrets with format-preserving fake keys (preserving prefix, length, separators, and character classes / hex case).
  - Replaces `USERNAME` with deterministic 8-letter login names (e.g., `/home/qmzvkrta`) and public `IP` addresses with `public-ip-xxxxxxxx` so agents can run paths and SSH commands without tripping on template braces.
- **Protocol-Aware JSON & Signed Thinking Block Protection**:
  - Preserves protocol control & correlation fields (`id`, `*_id`, `model`, `role`, `data:` URIs).
  - Redacts only `description` inside tool/schema definitions (`tools`, `response_format`, etc.) without breaking schemas or grammars.
  - Protects vendor-signed thinking/reasoning blocks (Anthropic `thinking.signature`, Gemini `thoughtSignature`, Responses `encrypted_content`) by only re-applying known mappings instead of running general rules.
  - Supports field-name secret detection (`namedSecret`) inside tool arguments plus escape/quote-safe boundary trimming (`outsideEscapes` + `inStrings`) for nested JSON strings.
- **Low-False-Positive Rule Engine**:
  - **Secrets**: OpenAI, Anthropic, GitHub, Google, Slack, Stripe, AWS, HuggingFace, Cloudflare, Volcano Ark, PEM private keys, JWT, URL passwords, `.env`/config assignments, `Authorization`/`Cookie` headers, CJK password/key contexts, and 13 crypto wallet formats (EVM, Bitcoin WIF Base58Check, BIP-0032, Solana Ed25519 key derivation, Stellar CRC16-XModem, NEAR, Sui, Aptos, Nostr, age, Zcash, and BIP-0039 seed phrases).
  - **Personal Data**: Emails, mainland China phone numbers & ID cards (checksum validated), Luhn bank cards, plus per-category toggles (`ssn`, `passport`, `iban`, `birthday`, `mac`, `serial`, `home`, `userhost`, `ip`, `bucket`).
  - **Custom Words & Rules**: Multi-format date equivalence matching (e.g. `1990-05-12` also matches `1990/5/12`, `1990年5月12日`, `19900512`, `May 12, 1990`), whole-word & case-insensitive options, custom prefix/regex rules, allowlist, and per-kind actions (`mask` / `warn` / `block`).
- **Prompt Cache Stability**: `knownSpans` cross-turn consistency, route-scoped `sentKnownMemo` & `allowKeptMemo` so historical prompt prefixes stay byte-identical for vendor prompt caching, and two-generation `ruleMemo` caching for long histories.
- **Streaming SSE & WebSocket Restoration**: Cross-chunk `partialTail` buffering (handles placeholders split across arbitrary SSE/WS deltas), keepalive/comment passthrough, tolerant restoration (handles altered braces/spaces/casing), and automatic JSON escaping for streamed tool arguments.
- **Slash Commands & Plaintext-Free Audit Logs**: Built-in `/redact` command (`status`, `preview`, `toggle`, `recent`, `clear`) that never wakes the LLM (`resume: false`), plus daily rotated JSONL audit logs that never write raw sensitive values to disk.

## Architecture

```text
OpenCode Session (real text & real tool args)
        │
        ├── Outbound: session.hook("http.request") / "experimental.ws.send"
        │     ├── Skip if disabled or filtered by skipProviders / includeProviders
        │     ├── Protocol-aware JSON walker (kept / defs / signed / args)
        │     ├── Rules + custom words/rules + knownSpans + allowlist
        │     ├── Action handling: mask | warn | block (fail-closed)
        │     └── Record plaintext-free audit entry (placeholder, kind, hint, count)
        ▼
  Upstream LLM Provider (only sees placeholders / stand-ins)
        │
        ├── Inbound: session.hook("http.response") / "experimental.ws.receive"
        │     ├── SSE TransformStream / WS frame restorer with partialTail carry-over
        │     ├── Tolerant placeholder & stand-in restoration + JSON arg escaping
        │     └── Update in-memory restored counts
        ▼
OpenCode UI & Tool Execution (restored real values)
```

## Installation

> Requires **OpenCode v2.0+** (verified on `opencode v2.3.2`) and **Bun 1.3+** to build from source.

### From Source (Local Plugin)

```bash
git clone https://github.com/zent00/opencode-redact.git
cd opencode-redact
bun install
bun run build
```

Then add it to your global `~/.config/opencode/opencode.jsonc` or project `opencode.json`:

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

> **Tip for Magpie users**: If OpenCode connects to a local Magpie gateway that already has masking enabled, add `"magpie"` to `skipProviders` to avoid redundant double scanning.

## Configuration Reference

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | `boolean` | `true` | Initial runtime enable flag (can be toggled via `/redact toggle`). |
| `secrets` | `boolean` | `true` | Enable secret & crypto wallet key redaction rules. |
| `personal` | `boolean` | `true` | Enable personal data rules (email, phone, ID card, bank card, and enabled `kinds`). |
| `kinds` | `Record<CategoryId, boolean>` | See below | Per-category toggle under `personal`. Default on: `ssn`, `passport`, `iban`, `birthday`, `mac`, `serial`. Default off: `home`, `userhost`, `ip`, `bucket`. |
| `words` | `string[]` | `[]` | Custom words/terms to redact as `TERM`. Date strings expand to multi-format equivalents automatically. |
| `wordsAnyCase` | `boolean` | `false` | Case-insensitive matching for `words`. |
| `wordsWhole` | `boolean` | `false` | Match `words` only on word boundaries (Latin/digits; CJK matches inline). |
| `rules` | `Array<{ kind, prefix? \| regex? }>` | `[]` | Up to 32 custom rules (specify either `prefix` or `regex`, not both). |
| `actions` | `Record<string, "mask" \| "warn" \| "block">` | `{}` | Override per-kind behavior: `mask` (default), `warn` (send plaintext + audit), `block` (abort request). |
| `allow` | `string[]` | `[]` | Case-insensitive whole-value allowlist (up to 200 entries). Explicit `words` take precedence over `allow`. |
| `shape` | `boolean` | `false` | Replace eligible secrets with format-preserving fake keys instead of `{{KIND_xxxxxxxx}}`. |
| `skipProviders` | `string[]` | `[]` | Provider IDs to bypass redaction (case-insensitive). |
| `includeProviders` | `string[]` | `[]` | If non-empty, only redact requests targeting these provider IDs. |
| `failClosed` | `boolean` | `true` | Abort outbound requests if redaction encounters an unexpected error. |
| `persistKey` | `boolean` | `false` | Persist the 32-byte HMAC placeholder key to `<stateDir>/redact.key` (mode `0600`) across restarts. |
| `keyPath` | `string` | `undefined` | Custom path for the persistent HMAC key file. |
| `stateDir` | `string` | `~/.config/opencode/opencode-redact` | Base directory for audit logs and optional key file. |
| `audit.enabled` | `boolean` | `true` | Enable plaintext-free daily JSONL audit logs. |
| `audit.dir` | `string` | `<stateDir>/audit` | Directory for `YYYY-MM-DD.jsonl` audit files. |
| `audit.keepDays` | `number` | `30` | Maximum days to retain audit log files (`1..365`). |
| `audit.keepBytes` | `number` | `104857600` | Maximum total audit log size in bytes (100 MiB). |

## Slash Commands

All `/redact` subcommands execute locally via `session.synthetic(..., { resume: false })` and never trigger an LLM call:

- `/redact status` — Show runtime status, active rules/categories, in-memory mapping stats, and audit summary.
- `/redact preview <text>` — Preview redaction output and hit details locally without modifying the mapping store.
- `/redact toggle` | `/redact on` | `/redact off` — Dynamically pause or resume redaction at runtime.
- `/redact recent [N]` — Show the latest `N` (default `10`) audit records with masked/restored counts and latency.
- `/redact clear` — Clear audit log files and counters (preserves in-memory mappings so ongoing sessions keep restoring).
- `/redact help` — Display command usage.

## Development

```bash
bun install
bun test          # Run unit & plugin integration tests
bun run typecheck # TypeScript strict check
bun run lint      # Biome lint & format check
bun run build     # Compile dist/
```

## Acknowledgments

- Architecture, rule design, false-positive heuristics, format-preserving stand-ins, and streaming restoration mechanics are heavily inspired by [yetone/magpie](https://github.com/yetone/magpie) (MIT License).
- Seed phrase detection uses the standard [BIP-0039](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt) English wordlist.

## License

[MIT](./LICENSE)
