// Format-Preserving 伪装与还原（借鉴 Magpie internal/redact/shape.go）：
// 1. Shape 模式：为密钥生成同前缀、同长度、同分隔符、同字符类别（大小写/数字/hex）的确定性假密钥；
// 2. USERNAME 伪登录名：将路径/登录用户名替换为 8 位小写字母（如 /home/qmzvkrta），避免 {{...}} 被误认为临时模板；
// 3. 公网 IP 伪域名：将公网 IP 替换为 public-ip-xxxxxxxx，使模型可正常发起 ssh 等工具调用并在出站前还原回真实 IP。
import crypto from "node:crypto"
import { PERSONAL_KINDS } from "./rules.js"
import type { RedactStore } from "./state.js"
import type { Span } from "./types.js"
import { lowerASCII, normalizeIP } from "./validators.js"

const MIN_SHAPE = 8
const MIN_RANDOM = 6
const STANDIN_LEN = 8
const IP_STANDIN_HEAD = "public-ip-"
const IP_STANDIN_LEN = 8

const KEY_PREFIXES = [
  "sk-ant-api03-",
  "sk-ant-oat01-",
  "sk-ant-admin01-",
  "sk-proj-",
  "sk-svcacct-",
  "sk-or-v1-",
  "github_pat_",
]

const NAMED_VALUE_RE = /^[A-Za-z_][A-Za-z0-9_.-]*[ \t]*[=:][ \t]*/

function keyHead(v: string): string {
  for (const p of KEY_PREFIXES) {
    if (v.startsWith(p)) return p
  }
  if (v.startsWith("AKIA") || v.startsWith("ASIA")) {
    return v.slice(0, 4)
  }
  for (let i = 0; i < v.length && i <= 4; i++) {
    const ch = v[i]!
    if ((ch === "-" || ch === "_") && i > 0) return v.slice(0, i + 1)
    if (!((ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z"))) break
  }
  return ""
}

export function splitNamedValue(v: string): readonly [string, string] {
  const m = NAMED_VALUE_RE.exec(v)
  if (!m) return ["", v]
  return [v.slice(0, m[0].length), v.slice(m[0].length)]
}

function isShapeChar(c: number): boolean {
  return (
    (c >= 97 && c <= 122) ||
    (c >= 65 && c <= 90) ||
    (c >= 48 && c <= 57) ||
    c === 45 || // -
    c === 95 || // _
    c === 46 // .
  )
}

/** 为密钥生成确定性同形假密钥；不符合条件则返回 undefined */
export function shapeOf(key: Buffer, kind: string, v: string): string | undefined {
  if (PERSONAL_KINDS.has(kind) || kind === "TERM" || v.length < MIN_SHAPE) return undefined
  for (let i = 0; i < v.length; i++) {
    if (!isShapeChar(v.charCodeAt(i))) return undefined
  }
  const head = keyHead(v)
  const rest = v.slice(head.length)
  let hexLower = true
  let hexUpper = true
  for (let i = 0; i < rest.length; i++) {
    const c = rest.charCodeAt(i)
    if ((c >= 48 && c <= 57) || c === 45 || c === 95 || c === 46) {
      // 数字与分隔符两边都兼容
    } else if (c >= 97 && c <= 102) {
      hexUpper = false
    } else if (c >= 65 && c <= 70) {
      hexLower = false
    } else {
      hexLower = false
      hexUpper = false
    }
  }

  const seed = crypto.createHmac("sha256", key).update(`shape\0${kind}\0${v}`).digest()
  let stream = Buffer.alloc(0)
  let offset = 0
  let counter = 0n
  const next = (mod: number): number => {
    if (offset >= stream.length) {
      const counterBuf = Buffer.alloc(8)
      counterBuf.writeBigUInt64BE(counter)
      counter += 1n
      stream = crypto.createHmac("sha256", seed).update(counterBuf).digest()
      offset = 0
    }
    return stream[offset++]! % mod
  }

  const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  const LOWER = "abcdefghijklmnopqrstuvwxyz"
  const DIGIT = "0123456789"
  let out = head
  let made = 0

  for (let i = 0; i < rest.length; i++) {
    const ch = rest[i]!
    const c = ch.charCodeAt(0)
    let charset = ""
    if (ch === "-" || ch === "_" || ch === ".") {
      out += ch
      continue
    } else if (hexLower) {
      charset = `${DIGIT}abcdef`
    } else if (hexUpper) {
      charset = `${DIGIT}ABCDEF`
    } else if (c >= 65 && c <= 90) {
      charset = UPPER
    } else if (c >= 97 && c <= 122) {
      charset = LOWER
    } else {
      charset = DIGIT
    }
    made++
    out += charset[next(charset.length)]!
  }
  if (made < MIN_RANDOM || out === v) return undefined
  return out
}

/** 为 USERNAME 生成 8 位小写确定性伪用户名 */
export function standInOfUsername(key: Buffer, v: string): string {
  const sum = crypto.createHmac("sha256", key).update(`user\0${v}`).digest()
  let out = ""
  for (let i = 0; i < STANDIN_LEN; i++) {
    out += String.fromCharCode(97 + (sum[i]! % 26))
  }
  return out
}

/** 为公网 IP 生成第 i 个候选伪主机名 public-ip-xxxxxxxx */
export function ipStandInCandidate(key: Buffer, v: string, index: number): string | undefined {
  const norm = normalizeIP(v)
  if (!norm) return undefined
  const counterBuf = Buffer.alloc(8)
  counterBuf.writeBigUInt64BE(BigInt(index))
  const sum = crypto.createHmac("sha256", key).update(`ip\0${norm}`).update(counterBuf).digest()
  let out = IP_STANDIN_HEAD
  for (let j = 0; j < IP_STANDIN_LEN; j++) {
    out += String.fromCharCode(97 + (sum[j]! % 26))
  }
  return out
}

export function foldStandIn(kind: string): boolean {
  return kind === "USERNAME" || kind === "IP"
}

function isNameChar(ch: string | undefined): boolean {
  if (!ch) return false
  const c = ch.charCodeAt(0)
  return (c >= 48 && c <= 57) || (c >= 97 && c <= 122) || (c >= 65 && c <= 90) || c === 45 || c === 95
}

function wholeAddr(s: string, a: number, z: number): boolean {
  if (a > 0 && (isNameChar(s[a - 1]) || s[a - 1] === ".")) return false
  if (z < s.length && isNameChar(s[z])) return false
  if (z + 1 < s.length && s[z] === "." && isNameChar(s[z + 1])) return false
  return true
}

function replaceStandIn(
  s: string,
  lower: string,
  f: string,
  v: string,
  put: Map<string, number> | undefined,
  whole: ((str: string, a: number, z: number) => boolean) | undefined,
): string {
  let out = ""
  let last = 0
  for (let i = 0; ; ) {
    const j = lower.indexOf(f, i)
    if (j < 0) break
    const a = j
    const z = j + f.length
    i = a + 1
    if (whole && !whole(s, a, z)) continue
    out += s.slice(last, a)
    out += v
    last = z
    i = z
    if (put) put.set(f, (put.get(f) ?? 0) + 1)
  }
  if (last === 0) return s
  return out + s.slice(last)
}

/** 将文本中的仿形密钥、伪用户名与伪公网 IP 还原回原文 */
export function restoreShapes(store: RedactStore, input: string, put?: Map<string, number>): string {
  if (!store.hasShapes()) return input
  let s = input
  let lower = ""
  let stale = true
  for (const [f, kind] of store.shapes) {
    const raw = store.values.get(f)
    if (raw === undefined) continue
    if (!foldStandIn(kind)) {
      if (s.includes(f)) {
        const parts = s.split(f)
        const count = parts.length - 1
        s = parts.join(raw)
        stale = true
        if (put && count > 0) put.set(f, (put.get(f) ?? 0) + count)
      }
      continue
    }
    if (stale) {
      lower = lowerASCII(s)
      stale = false
    }
    if (!lower.includes(f)) continue
    const replaced = replaceStandIn(s, lower, f, raw, put, kind === "IP" ? wholeAddr : undefined)
    if (replaced !== s) {
      s = replaced
      stale = true
    }
  }
  return s
}

/** 计算字符串尾部可能被流式截断的仿形密钥/伪用户名/伪 IP 前缀长度 */
export function shapeTail(store: RedactStore, s: string): number {
  if (!store.hasShapes() || !s) return 0
  const lower = lowerASCII(s)
  let whole = 0
  for (const [f, kind] of store.shapes) {
    const idx = foldStandIn(kind) ? lower.lastIndexOf(f) : s.lastIndexOf(f)
    if (idx >= 0) {
      whole = Math.max(whole, idx + f.length)
    }
  }
  let best = 0
  for (const [f, kind] of store.shapes) {
    const maxK = Math.min(f.length - 1, s.length - whole)
    for (let k = maxK; k > best; k--) {
      const prefix = f.slice(0, k)
      if (s.endsWith(prefix) || (foldStandIn(kind) && lower.endsWith(prefix))) {
        best = k
        break
      }
    }
  }
  return best
}

export function hasShapesInText(store: RedactStore, s: string): boolean {
  if (!store.hasShapes()) return false
  let lower = ""
  for (const [f, kind] of store.shapes) {
    if (s.includes(f)) return true
    if (foldStandIn(kind)) {
      if (!lower) lower = lowerASCII(s)
      if (lower.includes(f)) return true
    }
  }
  return false
}

/** 排除已处于仿形/伪装文本内部的误命中 span，避免二次脱敏 */
export function outsideShapes(store: RedactStore, s: string, found: Span[]): Span[] {
  if (!store.hasShapes() || found.length === 0) return found
  let out = found
  const lower = lowerASCII(s)
  for (const [f, kind] of store.shapes) {
    const haystack = foldStandIn(kind) ? lower : s
    for (let i = 0; ; ) {
      const a = haystack.indexOf(f, i)
      if (a < 0) break
      const z = a + f.length
      out = out.filter((x) => !(x.start < z && x.end > a))
      if (out.length === 0) return out
      i = z
    }
  }
  return out
}

/** 构造真实发往上游时使用的替换生成函数（写入 store） */
export function makePutFn(store: RedactStore, useShape: boolean): (kind: string, v: string) => string {
  const basePut = (kind: string, v: string): string => {
    if (useShape) {
      const [name, keyPart] = splitNamedValue(v)
      const f = shapeOf(store.getKey(), kind, keyPart)
      if (f && store.rememberShape(f, kind, keyPart)) {
        return name + f
      }
    }
    return store.rememberPlaceholder(kind, v)
  }

  return (kind: string, v: string): string => {
    if (kind === "IP") {
      const key = store.getKey()
      let free: string | undefined
      for (let i = 0; i < 8; i++) {
        const cand = ipStandInCandidate(key, v, i)
        if (!cand) break
        const existing = store.values.get(cand)
        if (existing === v) {
          store.touch(cand)
          return cand
        }
        if (existing === undefined && free === undefined) {
          free = cand
        }
      }
      if (free && store.rememberShape(free, "IP", v)) {
        return free
      }
      return basePut(kind, v)
    }
    if (kind === "USERNAME") {
      const f = standInOfUsername(store.getKey(), v)
      if (f !== v && store.rememberShape(f, "USERNAME", v)) {
        return f
      }
      return basePut(kind, v)
    }
    return basePut(kind, v)
  }
}

/** 构造预览模式的替换生成函数（不写入 store，也不污染 known） */
export function makePreviewPutFn(store: RedactStore, useShape: boolean): (kind: string, v: string) => string {
  const key = store.getKey()
  const basePut = (kind: string, v: string): string => {
    if (useShape) {
      const [name, keyPart] = splitNamedValue(v)
      const f = shapeOf(key, kind, keyPart)
      if (f) return name + f
    }
    return store.tag(kind, v)
  }
  return (kind: string, v: string): string => {
    if (kind === "USERNAME") return standInOfUsername(key, v)
    if (kind === "IP") {
      const cand = ipStandInCandidate(key, v, 0)
      if (cand) return cand
    }
    return basePut(kind, v)
  }
}
