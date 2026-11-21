// 脱敏状态存储（实例级隔离，无全局可变状态）。
// 包含：HMAC-SHA256 密钥管理、占位符/仿形 LRU 映射表、已知值 Bloom+前缀索引、
// 按 Route 的 sentSpans/allowKept 缓存（保护供应商 Prompt Cache）、长文本 ruleMemo 两代缓存。
import crypto from "node:crypto"
import fs from "node:fs"
import path from "node:path"
import { MIN_KNOWN, type Span } from "./types.js"

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

/** RFC 4648 无填充 Base32 编码（仅需编码前若干字节即可生成 8 位占位符哈希） */
export function encodeBase32NoPad(bytes: Uint8Array): string {
  let bits = 0
  let value = 0
  let out = ""
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i]!
    bits += 8
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31]!
      bits -= 5
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 31]!
  }
  return out
}

/** 两代淘汰缓存（cur 满时整体降级为 old，命中 old 时晋升回 cur，避免单次全量抖动） */
export class TwoGenCache<V> {
  private cur = new Map<string, V>()
  private old = new Map<string, V>()

  constructor(private readonly maxEntries: number) {}

  get(key: string): V | undefined {
    const v = this.cur.get(key)
    if (v !== undefined) return v
    const ov = this.old.get(key)
    if (ov !== undefined) {
      this.set(key, ov)
      return ov
    }
    return undefined
  }

  has(key: string): boolean {
    if (this.cur.has(key)) return true
    const ov = this.old.get(key)
    if (ov !== undefined) {
      this.set(key, ov)
      return true
    }
    return false
  }

  set(key: string, value: V): void {
    if (this.cur.size >= this.maxEntries) {
      this.old = this.cur
      this.cur = new Map()
    }
    this.cur.set(key, value)
  }

  clear(): void {
    this.cur.clear()
    this.old.clear()
  }

  get size(): number {
    return this.cur.size + this.old.size
  }
}

export interface KnownValue {
  readonly v: string
  readonly p: string
  readonly kind: string
}

export interface RedactStoreOptions {
  /** 可选固定密钥（仅用于单元测试或持久化加载） */
  readonly key?: Uint8Array
  /** 可选本地密钥文件路径（权限 0600），跨重启保持相同占位符 */
  readonly keyPath?: string
  /** 内存映射表上限，默认 200_000 */
  readonly maxValues?: number
}

const DEFAULT_MAX_VALUES = 200_000
const SENT_MEMO_MAX = 1 << 15
const ALLOW_KEPT_MAX = 1 << 15
const RULE_MEMO_MAX = 1 << 14

/** 4 字节 20-bit 哈希，用于 knownBits 快速跳过无关位置 */
export function gram4(s: string, i: number): number {
  const g =
    ((s.charCodeAt(i) & 0xff) |
      ((s.charCodeAt(i + 1) & 0xff) << 8) |
      ((s.charCodeAt(i + 2) & 0xff) << 16) |
      ((s.charCodeAt(i + 3) & 0xff) << 24)) >>>
    0
  return Math.imul(g, 2654435761) >>> 12
}

export class RedactStore {
  private keyBuf: Buffer | undefined
  private readonly keyPath: string | undefined
  private readonly maxValues: number

  /** placeholder / shape -> 原文 */
  readonly values = new Map<string, string>()
  /** shape / stand-in -> kind */
  readonly shapes = new Map<string, string>()
  /** 已出现过的占位符类型名（用于 wordTail 与 heldIn 快速检测） */
  readonly kinds = new Set<string>()
  /** placeholder -> 最近使用逻辑时钟，用于 LRU 淘汰 */
  private readonly used = new Map<string, number>()
  private clock = 0

  /** 已知值 8 字符前缀索引 + 20-bit Bloom 位图 */
  readonly known = new Map<string, KnownValue[]>()
  readonly knownBits = new Uint32Array(1 << 15) // 1 << 20 bits

  /** 按路由缓存历史文本的 knownSpans（避免新学到的敏感值改写旧轮次破坏 Prompt Cache） */
  readonly sentKnownMemo = new TwoGenCache<Span[]>(SENT_MEMO_MAX)
  /** 按路由记住某段历史文本中哪些值曾被脱敏（避免中途新增 Allow 破坏旧轮次缓存） */
  readonly allowKeptMemo = new TwoGenCache<true>(ALLOW_KEPT_MAX)
  /** 长文本正则扫描两代缓存 */
  readonly ruleMemo = new TwoGenCache<Span[]>(RULE_MEMO_MAX)
  /** 测试可观测：长文本实际执行规则扫描的次数 */
  ruleRuns = 0

  constructor(options: RedactStoreOptions = {}) {
    if (options.key) {
      this.keyBuf = Buffer.from(options.key)
    }
    this.keyPath = options.keyPath
    this.maxValues = options.maxValues ?? DEFAULT_MAX_VALUES
  }

  getKey(): Buffer {
    if (this.keyBuf) return this.keyBuf
    if (this.keyPath) {
      try {
        const existing = fs.readFileSync(this.keyPath)
        if (existing.length >= 32) {
          this.keyBuf = existing.subarray(0, 32)
          return this.keyBuf
        }
      } catch {
        // 文件不存在或不可读时重新生成
      }
    }
    const fresh = crypto.randomBytes(32)
    if (this.keyPath) {
      try {
        fs.mkdirSync(path.dirname(this.keyPath), { recursive: true, mode: 0o700 })
        fs.writeFileSync(this.keyPath, fresh, { mode: 0o600 })
      } catch {
        // 写入失败时退化为仅内存持有，不阻塞主链路
      }
    }
    this.keyBuf = fresh
    return fresh
  }

  /** 生成确定性占位符但不写入内存表（用于 Preview 与 Warn） */
  tag(kind: string, value: string): string {
    const digest = crypto.createHmac("sha256", this.getKey()).update(`${kind}\0${value}`).digest()
    return `{{${kind}_${encodeBase32NoPad(digest).slice(0, 8).toLowerCase()}}}`
  }

  /** 生成并记住占位符映射 */
  rememberPlaceholder(kind: string, value: string): string {
    const p = this.tag(kind, value)
    if (!this.values.has(p)) {
      this.makeRoom()
      this.values.set(p, value)
      this.kinds.add(kind)
      this.addKnown(p, value, kind)
    }
    this.touch(p)
    return p
  }

  /** 记住仿形密钥或伪登录名 / 伪公网 IP；若与其他原文冲突则返回 false */
  rememberShape(shape: string, kind: string, value: string): boolean {
    const existing = this.values.get(shape)
    if (existing !== undefined) {
      if (existing !== value) return false
      this.touch(shape)
      return true
    }
    this.makeRoom()
    this.values.set(shape, value)
    this.kinds.add(kind)
    this.shapes.set(shape, kind)
    this.addKnown(shape, value, kind)
    this.touch(shape)
    return true
  }

  getValue(placeholder: string): string | undefined {
    return this.values.get(placeholder)
  }

  hasValues(): boolean {
    return this.values.size > 0
  }

  hasShapes(): boolean {
    return this.shapes.size > 0
  }

  touch(placeholder: string): void {
    this.clock += 1
    this.used.set(placeholder, this.clock)
  }

  private makeRoom(): void {
    if (this.values.size < this.maxValues) return
    const entries = [...this.values.keys()]
    entries.sort((a, b) => (this.used.get(a) ?? 0) - (this.used.get(b) ?? 0))
    const evictCount = Math.floor(entries.length / 2)
    for (let i = 0; i < evictCount; i++) {
      const p = entries[i]!
      this.values.delete(p)
      this.shapes.delete(p)
      this.used.delete(p)
    }
    this.reindexKnown()
  }

  private addKnown(p: string, v: string, kind: string): void {
    if (kind === "TERM" || v.length < MIN_KNOWN) return
    const head = v.slice(0, MIN_KNOWN)
    let bucket = this.known.get(head)
    if (bucket) {
      for (let i = 0; i < bucket.length; i++) {
        if (bucket[i]!.v === v) {
          // 同一原文对应多个类型时按占位符字典序确定胜出者，保证重建索引后一致
          if (p < bucket[i]!.p) {
            bucket[i] = { v, p, kind }
          }
          return
        }
      }
      bucket.push({ v, p, kind })
    } else {
      bucket = [{ v, p, kind }]
      this.known.set(head, bucket)
    }
    const g = gram4(v, 0)
    this.knownBits[g >>> 5] = (this.knownBits[g >>> 5] ?? 0) | (1 << (g & 31))
  }

  private reindexKnown(): void {
    this.known.clear()
    this.knownBits.fill(0)
    for (const [p, v] of this.values) {
      const kind = this.kindOf(p)
      if (kind) this.addKnown(p, v, kind)
    }
  }

  kindOf(placeholder: string): string {
    const sk = this.shapes.get(placeholder)
    if (sk) return sk
    const idx = placeholder.lastIndexOf("_")
    if (idx > 2 && placeholder.startsWith("{{")) {
      return placeholder.slice(2, idx)
    }
    return ""
  }

  /** 生成前缀稳定记忆的哈希键 */
  hashKey(parts: readonly string[]): string {
    const h = crypto.createHash("sha256")
    for (const part of parts) {
      h.update(part)
      h.update("\0")
    }
    return h.digest("base64url")
  }

  stats(): {
    values: number
    shapes: number
    kinds: number
    knownBuckets: number
    sentMemo: number
    ruleMemo: number
  } {
    return {
      values: this.values.size,
      shapes: this.shapes.size,
      kinds: this.kinds.size,
      knownBuckets: this.known.size,
      sentMemo: this.sentKnownMemo.size,
      ruleMemo: this.ruleMemo.size,
    }
  }
}
