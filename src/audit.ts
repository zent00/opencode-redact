// 无明文本地审计日志（借鉴 Magpie internal/maskrec/maskrec.go）。
// 严格遵循“绝不落盘任何敏感原文”原则：仅记录占位符、类别、检测源、首字符 Hint、长度、命中次数与耗时。
import fs from "node:fs"
import path from "node:path"
import type { Finder, Hit, NonDefaultAction } from "./engine/types.js"

export interface AuditValue {
  readonly p: string
  readonly k: string
  readonly b: Finder
  readonly h?: string
  readonly l: number
  n: number
  a?: NonDefaultAction
}

export interface AuditRecord {
  readonly key: number
  readonly t: string
  readonly what: "http" | "ws" | "blocked"
  readonly sessionID?: string
  readonly agent?: string
  readonly provider?: string
  readonly model?: string
  readonly n: number
  readonly warned?: number
  readonly blocked?: boolean
  readonly tookUs?: number
  readonly values: AuditValue[]
  /** 仅存内存：响应阶段还原回来的占位符计数 */
  back?: Record<string, number>
}

export interface AuditLoggerOptions {
  readonly enabled: boolean
  readonly dir: string
  readonly keepDays: number
  readonly keepBytes: number
  readonly now?: () => Date
}

const MAX_RECENT = 200

function formatDay(date: Date): string {
  const y = date.getFullYear()
  const m = String(date.getMonth() + 1).padStart(2, "0")
  const d = String(date.getDate()).padStart(2, "0")
  return `${y}-${m}-${d}`
}

function mergeHits(hits: readonly Hit[]): { values: AuditValue[]; maskedCount: number; warnedCount: number } {
  const byPlaceholder = new Map<string, AuditValue>()
  const out: AuditValue[] = []
  let maskedCount = 0
  let warnedCount = 0

  for (const h of hits) {
    if (h.action === "warn") warnedCount++
    else maskedCount++

    const existing = byPlaceholder.get(h.placeholder)
    if (existing) {
      existing.n++
      if (existing.b === "known" && h.by !== "known") {
        ;(existing as { b: Finder }).b = h.by
      }
      if (h.action === "block") {
        existing.a = "block"
      }
      continue
    }
    const item: AuditValue = {
      p: h.placeholder,
      k: h.kind,
      b: h.by,
      ...(h.head ? { h: h.head } : {}),
      l: h.len,
      n: 1,
      ...(h.action ? { a: h.action } : {}),
    }
    byPlaceholder.set(h.placeholder, item)
    out.push(item)
  }
  return { values: out, maskedCount, warnedCount }
}

export class AuditLogger {
  private readonly now: () => Date
  private lastKey = 0
  private lastPrunedAt = 0
  private readonly recent: AuditRecord[] = []

  // 运行期汇总统计（方便 /redact status 瞬时展示）
  totalChecked = 0
  totalMaskedRequests = 0
  totalMaskedHits = 0
  totalWarnedHits = 0
  totalBlockedRequests = 0
  totalRestoredHits = 0

  constructor(private readonly options: AuditLoggerOptions) {
    this.now = options.now ?? (() => new Date())
  }

  noteChecked(): void {
    this.totalChecked++
  }

  record(input: {
    what: "http" | "ws" | "blocked"
    sessionID?: string
    agent?: string
    provider?: string
    model?: string
    hits: readonly Hit[]
    blocked?: boolean
    tookUs?: number
  }): AuditRecord | undefined {
    if (input.hits.length === 0) return undefined
    const { values, maskedCount, warnedCount } = mergeHits(input.hits)
    const now = this.now()
    let key = now.getTime() * 1000
    if (key <= this.lastKey) key = this.lastKey + 1
    this.lastKey = key

    if (input.blocked) {
      this.totalBlockedRequests++
    } else if (maskedCount > 0) {
      this.totalMaskedRequests++
    }
    this.totalMaskedHits += maskedCount
    this.totalWarnedHits += warnedCount

    const rec: AuditRecord = {
      key,
      t: now.toISOString(),
      what: input.blocked ? "blocked" : input.what,
      ...(input.sessionID ? { sessionID: input.sessionID } : {}),
      ...(input.agent ? { agent: input.agent } : {}),
      ...(input.provider ? { provider: input.provider } : {}),
      ...(input.model ? { model: input.model } : {}),
      n: maskedCount,
      ...(warnedCount > 0 ? { warned: warnedCount } : {}),
      ...(input.blocked ? { blocked: true } : {}),
      ...(input.tookUs !== undefined ? { tookUs: input.tookUs } : {}),
      values,
    }

    this.recent.push(rec)
    if (this.recent.length > MAX_RECENT) {
      this.recent.splice(0, this.recent.length - MAX_RECENT)
    }

    if (this.options.enabled) {
      this.appendToDisk(rec, now)
    }
    return rec
  }

  /** 将响应流还原的占位符计数回填到内存记录中（不改写磁盘日志） */
  noteRestored(recordKey: number | undefined, counts: ReadonlyMap<string, number>): void {
    if (counts.size === 0) return
    let sum = 0
    for (const c of counts.values()) sum += c
    this.totalRestoredHits += sum
    if (recordKey === undefined) return
    const rec = this.recent.find((r) => r.key === recordKey)
    if (!rec) return
    const back: Record<string, number> = { ...(rec.back ?? {}) }
    for (const [p, c] of counts) {
      back[p] = (back[p] ?? 0) + c
    }
    rec.back = back
  }

  recentRecords(limit = 10): AuditRecord[] {
    const n = Math.max(1, Math.min(limit, MAX_RECENT))
    return this.recent.slice(-n).reverse()
  }

  clear(): number {
    this.recent.length = 0
    this.totalChecked = 0
    this.totalMaskedRequests = 0
    this.totalMaskedHits = 0
    this.totalWarnedHits = 0
    this.totalBlockedRequests = 0
    this.totalRestoredHits = 0
    if (!this.options.enabled) return 0
    let removed = 0
    try {
      for (const file of this.dayFiles()) {
        fs.rmSync(file.fullPath, { force: true })
        removed++
      }
    } catch {
      // 目录不存在时静默忽略
    }
    return removed
  }

  private appendToDisk(rec: AuditRecord, now: Date): void {
    try {
      fs.mkdirSync(this.options.dir, { recursive: true, mode: 0o700 })
      const diskRec = { ...rec }
      delete diskRec.back
      const filePath = path.join(this.options.dir, `${formatDay(now)}.jsonl`)
      fs.appendFileSync(filePath, `${JSON.stringify(diskRec)}\n`, { encoding: "utf8", mode: 0o600 })
      if (now.getTime() - this.lastPrunedAt > 3600_000) {
        this.lastPrunedAt = now.getTime()
        this.prune(now)
      }
    } catch {
      // 审计写盘失败不得中断主请求链路
    }
  }

  private dayFiles(): Array<{ day: string; fullPath: string; size: number }> {
    let entries: string[]
    try {
      entries = fs.readdirSync(this.options.dir)
    } catch {
      return []
    }
    const out: Array<{ day: string; fullPath: string; size: number }> = []
    for (const name of entries) {
      if (!/^\d{4}-\d{2}-\d{2}\.jsonl$/.test(name)) continue
      const fullPath = path.join(this.options.dir, name)
      try {
        const st = fs.statSync(fullPath)
        out.push({ day: name.slice(0, 10), fullPath, size: st.size })
      } catch {
        // 忽略并发删除的文件
      }
    }
    out.sort((a, b) => a.day.localeCompare(b.day))
    return out
  }

  private prune(now: Date): void {
    const cutoff = new Date(now.getTime())
    cutoff.setDate(cutoff.getDate() - this.options.keepDays)
    const oldestAllowed = formatDay(cutoff)
    const files = this.dayFiles()
    let totalBytes = files.reduce((acc, f) => acc + f.size, 0)
    for (const f of files) {
      if (f.day >= oldestAllowed && totalBytes <= this.options.keepBytes) break
      try {
        fs.rmSync(f.fullPath, { force: true })
        totalBytes -= f.size
      } catch {
        // 忽略删除失败
      }
    }
  }
}
