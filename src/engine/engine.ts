// 双向脱敏核心引擎（借鉴 Magpie internal/redact/redact.go / known.go / allowkept.go / rulememo.go / json.go）。
import { escapeRegExp } from "../config.js"
import { DateWordMatcher } from "./dateword.js"
import {
  isNamedSecret,
  isNestedJSONField,
  jsonEscape,
  keepIn,
  scanJSONRegions,
  typeOfJSON,
  underAny,
  walkJSONStrings,
} from "./jsonWalker.js"
import { buildBuiltinRules, CustomRuleCompiler, KIND_TO_CATS, PERSONAL_KINDS } from "./rules.js"
import { hasShapesInText, makePreviewPutFn, makePutFn, outsideShapes, restoreShapes, shapeTail } from "./shape.js"
import { gram4, RedactStore, type RedactStoreOptions } from "./state.js"
import {
  ALNUM,
  CAT_PERSONAL,
  CATEGORY_DEFAULT_ON,
  type CompiledRule,
  type Hit,
  MAX_KIND,
  MAX_PLACEHOLDER_LEN,
  type MaskOptions,
  type MaskResult,
  MIN_KNOWN,
  type Span,
} from "./types.js"
import {
  filterNoIDs,
  filterNoNumbers,
  isAsciiDigit,
  isNextField,
  isSpaceChar,
  isWordByte,
  lowerASCII,
  makeHint,
  standsAlone,
} from "./validators.js"

const PLACEHOLDER_RE = /\{\{[A-Z][A-Z0-9_]*_[a-z2-7]{8}\}\}/g
const PLACEHOLDER_BODY_RE = /[A-Za-z][A-Za-z0-9_]*_[A-Za-z2-7]{8}/g
const PLACEHOLDER_BODY_EXACT_RE = /^[A-Za-z][A-Za-z0-9_]*_[A-Za-z2-7]{8}$/
const RULE_MEMO_MIN = 256
const BASE32_LOWER_RE = /^[a-zA-Z2-7]{8}$/

// 非 CJK 词字符（用于整词匹配，中/日文不要求空格分隔）
const WORD_CHAR_RE = /^[\p{L}\p{N}_]$/u
const CJK_NO_SPACE_RE = /^[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}]$/u

function isWordRune(ch: string): boolean {
  if (ch === "_") return true
  if (!WORD_CHAR_RE.test(ch)) return false
  return !CJK_NO_SPACE_RE.test(ch)
}

function isWholeWord(s: string, a: number, b: number): boolean {
  const first = Array.from(s.slice(a, Math.min(b, a + 2)))[0]
  const last = Array.from(s.slice(Math.max(a, b - 2), b)).at(-1)
  if (!first || !last) return true
  if (isWordRune(first) && a > 0) {
    const prev = Array.from(s.slice(Math.max(0, a - 2), a)).at(-1)!
    if (isWordRune(prev)) return false
    if (isAsciiDigit(first) && prev === ".") {
      const beforeDot = a - 2 >= 0 ? s[a - 2] : undefined
      if (isAsciiDigit(beforeDot)) return false
    }
  }
  if (isWordRune(last) && b < s.length) {
    const next = Array.from(s.slice(b, Math.min(s.length, b + 2)))[0]!
    if (isWordRune(next)) return false
    if (isAsciiDigit(last) && next === ".") {
      const afterDot = b + 1 < s.length ? s[b + 1] : undefined
      if (isAsciiDigit(afterDot)) return false
    }
  }
  return true
}

function coversCategory(o: MaskOptions, cat: string | undefined): boolean {
  if (!cat) return o.secrets
  if (cat === CAT_PERSONAL) return o.personal
  if (!o.personal) return false
  const explicit = o.kinds[cat]
  if (explicit !== undefined) return explicit
  return CATEGORY_DEFAULT_ON[cat] ?? false
}

function coversKind(o: MaskOptions, kind: string): boolean {
  const cats = KIND_TO_CATS.get(kind)
  if (!cats) return o.secrets
  return cats.some((c) => coversCategory(o, c))
}

function allowsValue(o: MaskOptions, v: string): boolean {
  const lower = v.toLowerCase()
  for (const a of o.allow) {
    if (a.trim().toLowerCase() === lower) return true
  }
  return false
}

function containsAnySub(s: string, subs: readonly string[]): boolean {
  for (const sub of subs) {
    if (s.includes(sub)) return true
  }
  return false
}

/** 保持长度不变的 JSON 反转义视图（让 \n 不被当作以 n 开头的单词，\uXXXX 不连词） */
export function unescapedView(s: string): string {
  if (!s.includes("\\")) return s
  const chars = s.split("")
  for (let i = 0; i + 1 < chars.length; i++) {
    if (chars[i] !== "\\") continue
    i++
    const c = chars[i]!
    if (c === "n" || c === "b" || c === "f") chars[i] = "\n"
    else if (c === "r") chars[i] = "\r"
    else if (c === "t") chars[i] = "\t"
    else if (c === "u") {
      for (let j = i; j < i + 5 && j < chars.length; j++) chars[j] = "\n"
      i += 4
    }
  }
  return chars.join("")
}

function unescapedPut(put: (kind: string, v: string) => string): (kind: string, v: string) => string {
  return (kind, v) => {
    let raw = v
    if (v.includes("\\")) {
      try {
        const parsed = JSON.parse(`"${v}"`)
        if (typeof parsed === "string") raw = parsed
      } catch {
        // 保留原值
      }
    }
    return put(kind, raw)
  }
}

/** 将所有 span 边界裁出 JSON 转义序列之外，避免截断 \n / \" / \uXXXX 导致 JSON 损坏 */
export function outsideEscapes(s: string, found: Span[]): Span[] {
  if (found.length === 0 || !s.includes("\\")) return found
  const from = new Int32Array(s.length + 1)
  const to = new Int32Array(s.length + 1)
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== "\\") continue
    const n = i + 1 < s.length && s[i + 1] === "u" ? 6 : 2
    const end = Math.min(i + n, s.length)
    for (let j = i + 1; j < end; j++) {
      from[j] = i + 1
      to[j] = end + 1
    }
    i = end - 1
  }
  const out: Span[] = []
  for (const f of found) {
    let start = f.start
    let end = f.end
    if ((to[start] ?? 0) > 0) start = to[start]! - 1
    if ((from[end] ?? 0) > 0) end = from[end]! - 1
    if (start < end) out.push({ ...f, start, end })
  }
  return out
}

function isBareJSONValue(s: string, a: number, b: number): boolean {
  if (a >= b) return false
  const seg = s.slice(a, b)
  if (/[ \t\r\n{}[\]",:]/.test(seg)) return false
  let i = a - 1
  while (i >= 0 && isSpaceChar(s[i])) i--
  let k = b
  while (k < s.length && isSpaceChar(s[k])) k++
  return i >= 0 && ":[,".includes(s[i]!) && (k === s.length || ",}]".includes(s[k]!))
}

/** 限制工具参数嵌套 JSON 中的每个 span 留在单个 JSON 字符串内（或完整裸值并加引号），避免跨引号破坏 JSON */
export function restrictInStrings(s: string, found: Span[]): Span[] {
  if (found.length === 0) return found
  try {
    JSON.parse(s)
  } catch {
    return found
  }
  const inStr = new Int32Array(s.length)
  let seq = 0
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== '"') continue
    seq++
    let j = i + 1
    while (j < s.length && s[j] !== '"') {
      inStr[j] = seq
      if (s[j] === "\\" && j + 1 < s.length) {
        j++
        inStr[j] = seq
      }
      j++
    }
    i = j
  }
  const out: Span[] = []
  for (const f of found) {
    let a = f.start
    while (a < f.end && inStr[a] === 0) a++
    if (a === f.end) {
      if (isBareJSONValue(s, f.start, f.end)) {
        out.push({ ...f, bare: true })
      }
      continue
    }
    let b = a
    while (b < f.end && inStr[b] === inStr[a]) b++
    out.push({ ...f, start: a, end: b })
  }
  return out
}

function canonicalPlaceholder(body: string): string {
  const cut = body.length - 8
  return `{{${body.slice(0, cut).toUpperCase()}${body.slice(cut).toLowerCase()}}}`
}

/** 容错扩展占位符两侧的花括号与空格（处理模型写入 {{ PHONE_xxx }} / {PHONE_xxx} / PHONE_xxx） */
function expandBraces(s: string, a: number, z: number): readonly [number, number] {
  let la = a
  let l = 0
  while (la > 0 && (s[la - 1] === " " || s[la - 1] === "\t")) la--
  while (l < 2 && la > 0 && s[la - 1] === "{") {
    la--
    l++
  }
  let rz = z
  let r = 0
  while (rz < s.length && (s[rz] === " " || s[rz] === "\t")) rz++
  while (r < 2 && rz < s.length && s[rz] === "}") {
    rz++
    r++
  }
  const finalA = l === 2 || (l === 1 && r >= 1) ? la : a
  const finalZ = r === 2 || (r === 1 && l >= 1) ? rz : z
  return [finalA, finalZ]
}

function braceTail(s: string): number {
  let i = s.lastIndexOf("{")
  if (i < 0) return 0
  if (i > 0 && s[i - 1] === "{") i--
  const t = s.slice(i)
  if (t.length >= MAX_PLACEHOLDER_LEN + 4 || t.includes("}}")) return 0
  let body = t.replace(/^\{+/, "")
  body = body.replace(/^[ \t]+/, "")
  if (body === "") return t.length
  const c0 = body.charCodeAt(0)
  if (!((c0 >= 65 && c0 <= 90) || (c0 >= 97 && c0 <= 122))) return 0
  let j = 0
  while (j < body.length && isWordByte(body[j])) j++
  const rest = body.slice(j).replace(/^[ \t]+/, "")
  if (rest !== "" && rest !== "}") return 0
  if (j < body.length && !PLACEHOLDER_BODY_EXACT_RE.test(body.slice(0, j))) return 0
  return t.length
}

/** 按长优先构造一次性替换表，用于 signed 思考块定向回填 */
function replacePairsLongestFirst(s: string, pairs: ReadonlyArray<readonly [string, string]>): string {
  const dedup = new Map<string, string>()
  for (const [v, p] of pairs) {
    if (!dedup.has(v)) dedup.set(v, p)
  }
  if (dedup.size === 0) return s
  const sorted = [...dedup.entries()].sort((a, b) => b[0].length - a[0].length)
  const re = new RegExp(sorted.map(([v]) => escapeRegExp(v)).join("|"), "g")
  return s.replace(re, (m) => dedup.get(m) ?? m)
}

export class RedactEngine {
  readonly store: RedactStore
  private readonly dateMatcher = new DateWordMatcher()
  private readonly customCompiler = new CustomRuleCompiler()
  private readonly anyCaseWordCache = new Map<string, RegExp>()
  private readonly defaultRules: readonly CompiledRule[]

  constructor(storeOrOptions?: RedactStore | RedactStoreOptions) {
    this.store = storeOrOptions instanceof RedactStore ? storeOrOptions : new RedactStore(storeOrOptions)
    this.defaultRules = buildBuiltinRules()
  }

  /** 对纯文本执行脱敏并写入内存映射表 */
  mask(text: string, options: MaskOptions): MaskResult {
    const opts: MaskOptions = { ...options, sent: options.sent ?? true }
    const hits: Hit[] = []
    const wrapped: MaskOptions = {
      ...opts,
      onHit: (h) => {
        hits.push(h)
        opts.onHit?.(h)
      },
    }
    const { text: out, count } = this.maskInternal(text, wrapped, makePutFn(this.store, opts.shape), false)
    const blocked = hits.find((h) => h.action === "block")
    return { text: out, count, hits, blocked }
  }

  /** 预览脱敏效果（不写入内存表、不污染 known / sentMemo） */
  preview(text: string, options: MaskOptions): MaskResult {
    const hits: Hit[] = []
    const wrapped: MaskOptions = {
      ...options,
      sent: false,
      onHit: (h) => {
        hits.push(h)
        options.onHit?.(h)
      },
    }
    const { text: out, count } = this.maskInternal(text, wrapped, makePreviewPutFn(this.store, options.shape), false)
    const blocked = hits.find((h) => h.action === "block")
    return { text: out, count, hits, blocked }
  }

  /** 对上游 LLM 请求 JSON 体执行协议感知脱敏（支持非 JSON 文本自动降级） */
  maskJSON(body: string, options: MaskOptions): MaskResult {
    const opts: MaskOptions = { ...options, sent: options.sent ?? true }
    const hits: Hit[] = []
    const emitHit = (h: Hit) => {
      hits.push(h)
      opts.onHit?.(h)
    }
    const wrapped: MaskOptions = { ...opts, onHit: emitHit }
    const { signed, args, defs } = scanJSONRegions(body)

    const shouldMask = (p: string, key: string, s: string): boolean =>
      !keepIn(p, key, s, args, defs) && (signed.length === 0 || !underAny(p, signed))

    let total = 0
    const seenPairs: Array<readonly [string, string]> = []
    const basePut = makePutFn(this.store, opts.shape)
    const put = (kind: string, v: string): string => {
      const p = basePut(kind, v)
      seenPairs.push([v, p])
      return p
    }

    // 第一遍：正文、消息与工具参数（工具参数开启按字段名识密 namedSecret）
    let walked = walkJSONStrings(body, (p, key, s) => {
      if (s.startsWith("data:") || (signed.length > 0 && underAny(p, signed))) return s
      if (opts.secrets && underAny(p, args) && isNamedSecret(key, s) && !this.store.shapes.has(s)) {
        if (allowsValue(opts, s)) return s
        const act = opts.actions.SECRET === "warn" || opts.actions.SECRET === "block" ? opts.actions.SECRET : ""
        const hint = makeHint("SECRET", s, PERSONAL_KINDS)
        if (act === "warn") {
          emitHit({ kind: "SECRET", by: "rule", placeholder: this.store.tag("SECRET", s), action: "warn", ...hint })
          return s
        }
        const placeholder = put("SECRET", s)
        emitHit({ kind: "SECRET", by: "rule", placeholder, action: act, ...hint })
        total++
        return placeholder
      }
      if (!shouldMask(p, key, s) || underAny(p, defs)) return s
      const res = this.maskInternal(s, wrapped, put, isNestedJSONField(key, ""))
      total += res.count
      return res.text
    })

    if (!walked.ok) {
      return this.mask(body, opts)
    }

    // 第二遍：定义区（defs 的 description），放后面让正文新学到的 known 也能覆盖描述
    if (defs.length > 0) {
      walked = walkJSONStrings(walked.text, (p, key, s) => {
        if (!shouldMask(p, key, s) || !underAny(p, defs)) return s
        const res = this.maskInternal(s, wrapped, put, isNestedJSONField(key, ""))
        total += res.count
        return res.text
      })
    }

    // 第三遍：签名块（signed，如 Anthropic thinking.signature），仅定向回填本次已脱敏值与历史已知 secrets
    let finalText = walked.text
    if (signed.length > 0) {
      const signedWalk = walkJSONStrings(finalText, (p, key, s) => {
        if (keepIn(p, key, s, args, defs) || !underAny(p, signed)) return s
        let cur = s
        if (seenPairs.length > 0) {
          const replaced = replacePairsLongestFirst(cur, seenPairs)
          if (replaced !== cur) {
            cur = replaced
            total++
          }
        }
        // 仅回填 secrets 类别的 known（不回填 personal，避免模型自造手机号/邮箱破坏签名）
        const ko: MaskOptions = {
          ...wrapped,
          personal: false,
          words: [],
          rules: [],
        }
        const knownSpans = this.sentKnownSpans(cur, ko)
        const applied = this.applySpans(cur, knownSpans, basePut, ko)
        total += applied.count
        return applied.text
      })
      finalText = signedWalk.text
    }

    const blocked = hits.find((h) => h.action === "block")
    return { text: finalText, count: total, hits, blocked }
  }

  /** 将文本中的占位符与仿形伪装还原回原文（容错大小写/空格/缺括号；escaped=true 时做 JSON 二次转义） */
  restore(input: string, escaped = false, put?: Map<string, number>): string {
    if (!this.store.hasValues()) return input
    const s = restoreShapes(this.store, input, put)
    if (!s.includes("_")) return s

    PLACEHOLDER_BODY_RE.lastIndex = 0
    let out = ""
    let last = 0
    for (const m of s.matchAll(PLACEHOLDER_BODY_RE)) {
      const a0 = m.index ?? -1
      if (a0 < last) continue
      const z0 = a0 + m[0].length
      if ((a0 > 0 && isWordByte(s[a0 - 1])) || (z0 < s.length && isWordByte(s[z0]))) continue
      const canon = canonicalPlaceholder(m[0])
      const raw = this.store.values.get(canon)
      if (raw === undefined) continue
      const [a, z] = expandBraces(s, a0, z0)
      if (a < last) continue
      if (put) put.set(canon, (put.get(canon) ?? 0) + 1)
      out += s.slice(last, a)
      out += escaped ? jsonEscape(raw) : raw
      last = z
    }
    if (last === 0) return s
    return out + s.slice(last)
  }

  /** 快速检测响应文本是否可能包含内存表中持有的占位符或仿形值 */
  heldIn(text: string): boolean {
    if (!this.store.hasValues()) return false
    if (hasShapesInText(this.store, text)) return true
    for (let i = 0; ; ) {
      const j = text.indexOf("_", i)
      if (j < 0) return false
      i = j + 1
      const z = i + 8
      if (z > text.length) return false
      if (z < text.length && isWordByte(text[z])) continue
      const hashPart = text.slice(i, z)
      if (!BASE32_LOWER_RE.test(hashPart)) continue
      const hash = hashPart.toLowerCase()
      for (const k of this.store.kinds) {
        if (i - 1 >= k.length && text.slice(i - 1 - k.length, i - 1).toUpperCase() === k) {
          if (this.store.values.has(`{{${k}_${hash}}}`)) return true
        }
      }
    }
  }

  /** 对完整 JSON 响应体执行还原（自动识别 arguments/partial_json/arguments.delta 二次转义） */
  restoreJSON(body: string, put?: Map<string, number>): string {
    if (!this.heldIn(body)) return body
    const typ = typeOfJSON(body)
    const walked = walkJSONStrings(body, (_p, key, s) => this.restore(s, isNestedJSONField(key, typ), put))
    if (!walked.ok) {
      return this.restore(body, false, put)
    }
    return walked.text
  }

  /** 检测流式文本末尾是否存在可能跨 chunk 截断的占位符/仿形前缀长度 */
  partialTail(s: string): number {
    const bt = braceTail(s)
    if (bt > 0) return bt
    return Math.max(this.wordTail(s), shapeTail(this.store, s))
  }

  private wordTail(s: string): number {
    if (this.store.kinds.size === 0) return 0
    let i = s.length
    while (i > 0 && isWordByte(s[i - 1])) i--
    const w = s.slice(i)
    if (!w || w.length > MAX_KIND + 9) return 0
    const c0 = w.charCodeAt(0)
    if (!(c0 >= 65 && c0 <= 90)) return 0
    const u = w.toUpperCase()
    for (const kind of this.store.kinds) {
      const prefix = `${kind}_`
      if (prefix.startsWith(u)) return w.length
      if (u.startsWith(prefix)) {
        const rest = u.slice(prefix.length)
        if (rest.length <= 8 && /^[A-Z2-7]*$/.test(rest)) return w.length
      }
    }
    return 0
  }

  // ---- 内部扫描与替换链路 ----

  private maskInternal(
    raw: string,
    o: MaskOptions,
    put: (kind: string, v: string) => string,
    escaped: boolean,
  ): { text: string; count: number } {
    if (raw.length < 3) return { text: raw, count: 0 }
    const s = escaped ? unescapedView(raw) : raw
    const actualPut = escaped ? unescapedPut(put) : put
    let found: Span[] = []

    // 1. 用户自定义词（含日期多格式等价匹配）
    for (const rawWord of o.words) {
      const w = rawWord.trim()
      if (w.length < 2) continue
      const dateRes = this.dateMatcher.match(s, w)
      if (dateRes.matched) {
        found.push(...dateRes.spans)
        continue
      }
      if (o.wordsAnyCase) {
        let re = this.anyCaseWordCache.get(w)
        if (!re) {
          re = new RegExp(escapeRegExp(w), "gi")
          this.anyCaseWordCache.set(w, re)
        }
        re.lastIndex = 0
        for (const m of s.matchAll(re)) {
          const a = m.index ?? -1
          if (a < 0) continue
          const b = a + m[0].length
          if (o.wordsWhole && !isWholeWord(s, a, b)) continue
          found.push({ start: a, end: b, kind: "TERM", by: "word" })
        }
      } else {
        for (let i = 0; i <= s.length; ) {
          const a = s.indexOf(w, i)
          if (a < 0) break
          const b = a + w.length
          if (o.wordsWhole && !isWholeWord(s, a, b)) {
            i = a + 1
            continue
          }
          found.push({ start: a, end: b, kind: "TERM", by: "word" })
          i = Math.max(b, a + 1)
        }
      }
    }

    // 2. 内置规则 + 用户自定义规则（带长文本两代缓存 ruleMemo）
    found.push(...this.ruleSpans(s, o))

    // 3. 历史已知值回溯（若发往真实路由，则按 route 稳定记忆 sentKnownMemo 保护 Prompt Cache）
    if (o.sent) {
      found.push(...this.sentKnownSpans(s, o))
    } else {
      found.push(...this.knownSpans(s, o))
    }

    // 4. 嵌套 JSON 安全裁剪（outsideEscapes + inStrings）与通用防误报过滤（noIDs + noNumbers）
    if (escaped) {
      found = restrictInStrings(raw, outsideEscapes(raw, found))
    }
    found = filterNoNumbers(s, filterNoIDs(s, found), PERSONAL_KINDS)

    return this.applySpans(raw, found, actualPut, o)
  }

  private ruleSpans(s: string, o: MaskOptions): Span[] {
    if (s.length < RULE_MEMO_MIN) {
      return this.scanRules(s, o)
    }
    const day = (o.now ? o.now() : new Date()).toISOString().slice(0, 10)
    const kindPairs = Object.entries(o.kinds)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join(",")
    const ruleSig = o.secrets ? o.rules.map((r) => `${r.kind}:${r.prefix ?? ""}:${r.regex ?? ""}`).join(";") : ""
    const key = this.store.hashKey([day, String(o.secrets), String(o.personal), kindPairs, ruleSig, s])
    const cached = this.store.ruleMemo.get(key)
    if (cached) {
      return cached.map((sp) => ({ ...sp }))
    }
    this.store.ruleRuns++
    const spans = this.scanRules(s, o)
    this.store.ruleMemo.set(
      key,
      spans.map((sp) => ({ ...sp })),
    )
    return spans
  }

  private scanRules(s: string, o: MaskOptions): Span[] {
    const baseRules = o.now ? buildBuiltinRules(o.now) : this.defaultRules
    const all: readonly CompiledRule[] =
      o.secrets && o.rules.length > 0 ? [...this.customCompiler.compile(o.rules), ...baseRules] : baseRules

    const found: Span[] = []
    const splitRanges: Array<readonly [number, number]> = []
    let lower = ""

    for (const r of all) {
      if (!coversCategory(o, r.cat)) continue
      if (r.markers && r.markers.length > 0 && !containsAnySub(s, r.markers)) continue
      if (r.may && !r.may(s)) continue
      if (r.fold && r.fold.length > 0) {
        if (!lower) lower = lowerASCII(s)
        if (!containsAnySub(lower, r.fold)) continue
      }

      const matches = this.ruleMatches(r, s, lower)
      for (const m of matches) {
        if (r.groups && r.groups.length > 0) {
          let took = false
          for (let g = 0; g < r.groups.length; g++) {
            const grp = m[g + 1]
            if (!grp) continue
            const [a, b] = grp
            if (this.ruleTakes(r, s, a, b, r.groupOK?.[g])) {
              found.push({ start: a, end: b, kind: r.groups[g]!, by: r.yours ? "yours" : "rule" })
              took = true
            }
          }
          if (took && m[1] && m[0]) {
            splitRanges.push([m[1][0], m[0][1]])
          }
          continue
        }

        let [a, b] = m[0]!
        for (let g = 1; g < m.length; g++) {
          const grp = m[g]
          if (grp) {
            a = grp[0]
            b = grp[1]
            break
          }
          if (!r.anyGroup) break
        }
        let ok = r.ok
        if (r.fix) {
          const [fa, fb, good] = r.fix(s, a, b)
          if (!good) continue
          a = fa
          b = fb
          ok = undefined
        }
        if (this.ruleTakes(r, s, a, b, ok)) {
          found.push({ start: a, end: b, kind: r.kind, by: r.yours ? "yours" : "rule" })
        }
      }
    }

    if (splitRanges.length > 0) {
      return found.filter(
        (f) => !(f.kind === "EMAIL" && splitRanges.some(([spStart, spEnd]) => f.start === spStart && f.end <= spEnd)),
      )
    }
    return found
  }

  private ruleMatches(r: CompiledRule, s: string, lower: string): Array<Array<readonly [number, number] | undefined>> {
    if (!r.ahead || !r.fold) {
      return this.findAllIndices(r, s)
    }
    const back = r.back ?? 0
    const wins: Array<[number, number]> = []
    for (const f of r.fold) {
      for (let i = 0; ; ) {
        const at = lower.indexOf(f, i)
        if (at < 0) break
        i = at + f.length
        let start = Math.max(0, at - back)
        const nl = s.slice(start, at).lastIndexOf("\n")
        if (nl >= 0) {
          start += nl + 1
        } else if (start > 0) {
          while (start < at && (ALNUM.includes(s[start - 1]!) || "_.-".includes(s[start - 1]!))) {
            start++
          }
          if (start === at && (ALNUM.includes(s[at - 1]!) || s[at - 1] === "_")) {
            continue
          }
        }
        wins.push([start, Math.min(s.length, i + r.ahead)])
      }
    }
    if (wins.length === 0) return []
    wins.sort((a, b) => a[0] - b[0])
    const out: Array<Array<readonly [number, number] | undefined>> = []
    for (let k = 0; k < wins.length; k++) {
      let [wStart, wEnd] = wins[k]!
      while (k + 1 < wins.length && wins[k + 1]![0] <= wEnd) {
        k++
        wEnd = Math.max(wEnd, wins[k]![1])
      }
      const subMatches = this.findAllIndices(r, s.slice(wStart, wEnd))
      for (const m of subMatches) {
        out.push(m.map((pair) => (pair ? ([pair[0] + wStart, pair[1] + wStart] as const) : undefined)))
      }
    }
    return out
  }

  private findAllIndices(r: CompiledRule, s: string): Array<Array<readonly [number, number] | undefined>> {
    if (r.field) {
      return this.fieldMatches(r.re, s)
    }
    const re = new RegExp(r.re.source, r.re.flags)
    const out: Array<Array<readonly [number, number] | undefined>> = []
    for (const m of s.matchAll(re)) {
      const indices = (m as RegExpMatchArray & { indices?: Array<[number, number] | undefined> }).indices
      if (indices?.[0]) out.push(indices)
    }
    return out
  }

  /** fieldMatches：若捕获组 1 实际是紧跟在空赋值后面的下一个字段（如 UI_PASSWORD= UI_ADDR=...），则丢弃并从下一字段重新扫 */
  private fieldMatches(baseRe: RegExp, s: string): Array<Array<readonly [number, number] | undefined>> {
    const out: Array<Array<readonly [number, number] | undefined>> = []
    for (let at = 0; ; ) {
      let again = -1
      const re = new RegExp(baseRe.source, baseRe.flags)
      const slice = s.slice(at)
      for (const m of slice.matchAll(re)) {
        const rawIndices = (m as RegExpMatchArray & { indices?: Array<[number, number] | undefined> }).indices
        if (!rawIndices?.[0]) continue
        const shifted = rawIndices.map((pair) => (pair ? ([pair[0] + at, pair[1] + at] as const) : undefined))
        const g1 = shifted[1]
        if (g1 && g1[0] > at && isNextField(s, g1[0], g1[1])) {
          again = g1[0]
          break
        }
        out.push(shifted)
      }
      if (again < 0) return out
      at = again
    }
  }

  private ruleTakes(
    r: CompiledRule,
    s: string,
    a: number,
    b: number,
    ok: ((v: string) => boolean) | undefined,
  ): boolean {
    if (b <= a) return false
    if (r.bound) {
      if ((a > 0 && r.bound.includes(s[a - 1]!)) || (b < s.length && r.bound.includes(s[b]!))) {
        return false
      }
    }
    if (ok && !ok(s.slice(a, b))) return false
    return !r.at || r.at(s, a, b)
  }

  /** 按路由缓存历史文本的 knownSpans，防止新学到的敏感值改写旧历史导致 Prompt Cache 失效 */
  private sentKnownSpans(s: string, o: MaskOptions): Span[] {
    if ((!o.secrets && !o.personal) || s.length < MIN_KNOWN) return []
    const kindPairs = Object.entries(o.kinds)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join(",")
    const key = this.store.hashKey(["known", o.route ?? "", String(o.secrets), String(o.personal), kindPairs, s])
    const cached = this.store.sentKnownMemo.get(key)
    if (cached) return cached.map((sp) => ({ ...sp }))
    const spans = this.knownSpans(s, o)
    this.store.sentKnownMemo.set(
      key,
      spans.map((sp) => ({ ...sp })),
    )
    return spans
  }

  private knownSpans(s: string, o: MaskOptions): Span[] {
    if ((!o.secrets && !o.personal) || s.length < MIN_KNOWN || this.store.known.size === 0) return []
    const out: Span[] = []
    for (let i = 0; i + MIN_KNOWN <= s.length; i++) {
      const g = gram4(s, i)
      if (((this.store.knownBits[g >>> 5] ?? 0) & (1 << (g & 31))) === 0) continue
      const bucket = this.store.known.get(s.slice(i, i + MIN_KNOWN))
      if (!bucket) continue
      let best: { v: string; kind: string } | undefined
      for (const item of bucket) {
        if (!coversKind(o, item.kind)) continue
        if (best && item.v.length <= best.v.length) continue
        if (!s.startsWith(item.v, i)) continue
        if (!standsAlone(item.kind, s, i, i + item.v.length)) continue
        best = item
      }
      if (best) {
        out.push({ start: i, end: i + best.v.length, kind: best.kind, by: "known" })
        i += best.v.length - 1
      }
    }
    return out
  }

  private applySpans(
    s: string,
    rawFound: Span[],
    put: (kind: string, v: string) => string,
    o: MaskOptions,
  ): { text: string; count: number } {
    if (rawFound.length === 0) return { text: s, count: 0 }
    let found = outsideShapes(this.store, s, rawFound)
    if (s.includes("{{")) {
      PLACEHOLDER_RE.lastIndex = 0
      const existing: Array<readonly [number, number]> = []
      for (const m of s.matchAll(PLACEHOLDER_RE)) {
        const idx = m.index ?? -1
        if (idx >= 0) existing.push([idx, idx + m[0].length])
      }
      if (existing.length > 0) {
        found = found.filter((f) => !existing.some(([p0, p1]) => f.start < p1 && f.end > p0))
      }
      if (found.length === 0) return { text: s, count: 0 }
    }

    // 起点优先、同起点长匹配优先；稳定排序确保相同位置优先保留先注册规则的类型
    found.sort((a, b) => (a.start !== b.start ? a.start - b.start : b.end - a.end))

    let out = ""
    let last = 0
    let next = 0
    let kept = 0
    let count = 0
    const remember = Boolean(o.sent && o.route)
    let textHash = ""
    const getTextHash = () => {
      if (!textHash) textHash = this.store.hashKey([o.route ?? "", s])
      return textHash
    }

    for (const f of found) {
      if (f.start < next || (f.start < kept && f.by !== "word")) continue
      const v = s.slice(f.start, f.end)
      if (f.by !== "word" && allowsValue(o, v)) {
        const allowKey = remember ? `${getTextHash()}\0${v.trim().toLowerCase()}` : ""
        if (!remember || !this.store.allowKeptMemo.has(allowKey)) {
          kept = Math.max(kept, f.end)
          continue
        }
      }
      next = f.end
      const act = o.actions[f.kind] === "warn" || o.actions[f.kind] === "block" ? o.actions[f.kind]! : ""
      const hint = makeHint(f.kind, v, PERSONAL_KINDS)
      if (act === "warn") {
        o.onHit?.({
          kind: f.kind,
          by: f.by,
          placeholder: this.store.tag(f.kind, v),
          action: "warn",
          ...hint,
        })
        continue
      }
      const placeholder = put(f.kind, v)
      out += s.slice(last, f.start)
      out += f.bare ? `"${placeholder}"` : placeholder
      if (remember) {
        this.store.allowKeptMemo.set(`${getTextHash()}\0${v.trim().toLowerCase()}`, true)
      }
      o.onHit?.({
        kind: f.kind,
        by: f.by,
        placeholder,
        action: act,
        ...hint,
      })
      last = f.end
      count++
    }

    if (count === 0) return { text: s, count: 0 }
    return { text: out + s.slice(last), count }
  }
}
