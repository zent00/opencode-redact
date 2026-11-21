# Security Policy

## Security Guarantees

`opencode-redact` is designed to minimize sensitive data exposure when using external LLM providers through OpenCode v2:

1. **In-Memory Mapping Only**: Raw secret/PII values mapped to placeholders are kept strictly in process memory (bounded by an LRU table of 200,000 entries) and are never persisted to disk.
2. **Plaintext-Free Audit Logs**: Audit records written to daily `.jsonl` files (mode `0600`) contain only deterministic placeholders, category kinds, finder tags, character length, and safe prefix hints—never raw values or surrounding prompt snippets.
3. **Fail-Closed by Default**: With `failClosed: true` (the default), unexpected errors during request redaction abort the outbound request rather than leaking unredacted plaintext.
4. **Local-Only Slash Commands**: `/redact` subcommands (including `/redact preview`) post synthetic notices with `resume: false` and never wake or contact upstream LLM providers.

## Scope & Limitations

- `opencode-redact` operates on OpenCode v2 session transport hooks (`http.request` / `http.response` and `experimental.ws.send` / `experimental.ws.receive`). Local shell commands, MCP servers, file reads/writes, and web search tools outside session LLM transport are outside this plugin's interception boundary.
- Rule-based detection cannot guarantee 100% recall on unstructured free-text secrets or personal names; combine built-in rules with `words`, custom `rules`, and `actions` (`block`) for sensitive workflows.

## Reporting a Vulnerability

If you discover a redaction bypass, plaintext leakage in audit logs, or any other security issue, please report it via [GitHub Security Advisories](https://github.com/zent00/opencode-redact/security/advisories/new) rather than opening a public issue.
