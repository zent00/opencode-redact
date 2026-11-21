import { afterEach, describe, expect, test } from "bun:test"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { AuditLogger } from "../src/audit.js"
import { parseConfig, toMaskOptions } from "../src/config.js"
import { RedactEngine } from "../src/engine/engine.js"

const tmpDirs: string[] = []
function makeTempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "opencode-redact-audit-"))
  tmpDirs.push(dir)
  return dir
}

afterEach(() => {
  for (const dir of tmpDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

describe("无明文本地 JSONL 审计日志", () => {
  test("落盘 JSONL 绝不含敏感原文，且正确聚合命中、回填还原计数与清理", () => {
    const dir = makeTempDir()
    const now = () => new Date("2026-11-21T08:00:00Z")
    const audit = new AuditLogger({
      enabled: true,
      dir,
      keepDays: 7,
      keepBytes: 10 * 1024 * 1024,
      now,
    })
    const engine = new RedactEngine({ key: new Uint8Array(32).fill(9) })
    const secret = "sk-proj-RealSuperSecretValue1234567890"
    const res = engine.mask(`first=${secret} second=${secret}`, toMaskOptions(parseConfig(), { sent: false }))

    const rec = audit.record({
      what: "http",
      sessionID: "ses_1",
      agent: "build",
      provider: "openai",
      model: "gpt-5",
      hits: res.hits,
      tookUs: 420,
    })
    expect(rec).toBeDefined()
    expect(rec!.n).toBe(2)
    expect(rec!.values).toHaveLength(1)
    expect(rec!.values[0]!.n).toBe(2)

    const logFiles = fs.readdirSync(dir)
    expect(logFiles).toHaveLength(1)
    const rawDisk = fs.readFileSync(path.join(dir, logFiles[0]!), "utf8")
    // 严格校验：真实密钥原文绝不能出现在审计日志中
    expect(rawDisk).not.toContain(secret)
    expect(rawDisk).not.toContain("RealSuperSecretValue")
    expect(rawDisk).toContain(res.hits[0]!.placeholder)
    expect(rawDisk).toContain('"k":"API_KEY"')

    // 回填响应还原计数（仅更新内存）
    audit.noteRestored(rec!.key, new Map([[res.hits[0]!.placeholder, 2]]))
    expect(audit.totalRestoredHits).toBe(2)
    expect(audit.recentRecords(5)[0]?.back?.[res.hits[0]!.placeholder]).toBe(2)

    // 清理日志
    const removed = audit.clear()
    expect(removed).toBe(1)
    expect(fs.readdirSync(dir)).toHaveLength(0)
    expect(audit.recentRecords(5)).toHaveLength(0)
  })
})
