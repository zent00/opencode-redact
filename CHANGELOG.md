# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-21

### Added

- Bidirectional OpenCode v2 transport redaction via `http.request`, `http.response`, `experimental.ws.send`, and `experimental.ws.receive`.
- Deterministic HMAC-SHA256 + Base32 placeholders (`{{KIND_xxxxxxxx}}`) with bounded in-memory LRU mapping and optional persistent key file (`persistKey` / `keyPath`).
- Format-preserving stand-ins: `shape` mode for secrets, 8-letter pseudo usernames (`USERNAME`), and `public-ip-xxxxxxxx` stand-ins for public IPs.
- Protocol-aware JSON string walker preserving protocol control/ID fields (`kept` / `isID`), tool schema definitions (`defs`), signed thinking/reasoning blocks (`signed`), and nested JSON tool arguments (`args` with `namedSecret`, `outsideEscapes`, and `inStrings`).
- Comprehensive built-in rule engine with false-positive guards:
  - Secrets (API keys, PEM private keys, JWT, URL passwords, field assignments, uppercase `_KEY`/`_PASS`, `Authorization`/`Cookie` headers, CJK password/key contexts, and 13 crypto wallet key formats + BIP-0039 seed phrases).
  - Personal data (emails, mainland China phone & ID cards, Luhn bank cards, plus configurable `ssn`, `passport`, `iban`, `birthday`, `mac`, `serial`, `home`, `userhost`, `ip`, `bucket`).
  - Custom words (with whole-word, case-insensitive, and multi-format date equivalence matching), custom prefix/regex rules, allowlist, and per-kind `mask` / `warn` / `block` actions.
- Prompt cache stability across turns via `knownSpans`, route-scoped `sentKnownMemo` / `allowKeptMemo`, and `ruleMemo`.
- Streaming SSE `TransformStream` and WebSocket frame restorers with cross-chunk `partialTail` buffering, keepalive passthrough, tolerant restoration, and nested JSON escaping.
- Local-only `/redact` slash command (`status`, `preview`, `toggle`, `on`, `off`, `recent`, `clear`, `help`).
- Plaintext-free daily rotated JSONL audit logs with automatic retention pruning.
