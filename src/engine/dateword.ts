// 日期型自定义词的多格式等价匹配（借鉴 Magpie internal/redact/dateword.go）。
// 当用户在自定义词表中配置如 "1990-05-12" 时，自动等价匹配 1990/5/12、1990年5月12日、19900512、May 12, 1990 等写法。
import { escapeRegExp } from "../config.js"
import type { Span } from "./types.js"

const DATE_SEP = "(?:[ \\t]*[-/.、／－][ \\t]*|[ \\t])"

const DATE_YMD = new RegExp(`^(\\d{4})${DATE_SEP}(\\d{1,2})${DATE_SEP}(\\d{1,2})\\.?$`)
const DATE_CJK = /^(\d{4})[ \t]*[年년][ \t]*(\d{1,2})[ \t]*[月월][ \t]*(\d{1,2})[ \t]*[日号號일]?$/
const DATE_DMY = new RegExp(`^(\\d{1,2})${DATE_SEP}(\\d{1,2})${DATE_SEP}(\\d{4})$`)
const DATE_NAME_F = /^([A-Za-z]+)\.?[ \t]+(\d{1,2})(?:st|nd|rd|th)?,?[ \t]+(\d{4})$/
const DATE_NAME_B = /^(\d{1,2})(?:st|nd|rd|th)?(?:[ \t]+|-)([A-Za-z]+)\.?,?(?:[ \t]+|-)(\d{4})$/

const MONTH_NAMES = [
  "January",
  "February",
  "March",
  "April",
  "May",
  "June",
  "July",
  "August",
  "September",
  "October",
  "November",
  "December",
] as const

const CJK_CHAR_RE = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}]/u
const LETTER_RE = /\p{L}/u

function monthOf(name: string): number {
  const l = name.toLowerCase()
  if (l === "sept") return 9
  for (let i = 0; i < MONTH_NAMES.length; i++) {
    const ml = MONTH_NAMES[i]!.toLowerCase()
    if (l === ml || (l.length === 3 && ml.startsWith(l))) {
      return i + 1
    }
  }
  return 0
}

function realDate(y: number, m: number, d: number): boolean {
  if (y < 1000 || y > 2999 || m < 1 || m > 12 || d < 1) return false
  const dt = new Date(Date.UTC(y, m - 1, d))
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d
}

export function parseDateWord(w: string): readonly [number, number, number] | undefined {
  let y = 0
  let m = 0
  let d = 0
  const ymd = DATE_YMD.exec(w)
  const cjk = ymd ? null : DATE_CJK.exec(w)
  const dmy = ymd || cjk ? null : DATE_DMY.exec(w)
  const nameF = ymd || cjk || dmy ? null : DATE_NAME_F.exec(w)
  const nameB = ymd || cjk || dmy || nameF ? null : DATE_NAME_B.exec(w)
  if (ymd) {
    y = Number(ymd[1])
    m = Number(ymd[2])
    d = Number(ymd[3])
  } else if (cjk) {
    y = Number(cjk[1])
    m = Number(cjk[2])
    d = Number(cjk[3])
  } else if (dmy) {
    const p = Number(dmy[1])
    const q = Number(dmy[2])
    y = Number(dmy[3])
    if (p === q) {
      m = p
      d = q
    } else if (p > 12 && q <= 12) {
      d = p
      m = q
    } else if (q > 12 && p <= 12) {
      m = p
      d = q
    } else {
      // 05/12/1990 存在美式/欧式歧义，不展开为日期词
      return undefined
    }
  } else if (nameF) {
    m = monthOf(nameF[1]!)
    d = Number(nameF[2])
    y = Number(nameF[3])
  } else if (nameB) {
    d = Number(nameB[1])
    m = monthOf(nameB[2]!)
    y = Number(nameB[3])
  } else {
    return undefined
  }
  return realDate(y, m, d) ? [y, m, d] : undefined
}

function buildDatePattern(y: number, m: number, d: number, raw: string): RegExp {
  const num = (v: number) => (v < 10 ? `0?${v}` : String(v))
  const Y = String(y)
  const M = num(m)
  const D = num(d)
  const full = MONTH_NAMES[m - 1]!
  const abbr = m === 9 ? "Sept|Sep" : full.slice(0, 3)
  const monthPat = `(?:${full}|(?:${abbr})\\.?)`
  const ord = "(?:st|nd|rd|th)?"
  const mm = String(m).padStart(2, "0")
  const dd = String(d).padStart(2, "0")

  const forms = [
    `${Y}${DATE_SEP}${M}${DATE_SEP}${D}`,
    `${Y}[ \\t]*年[ \\t]*${M}[ \\t]*月[ \\t]*${D}(?:[ \\t]*[日号號])?`,
    `${Y}[ \\t]*년[ \\t]*${M}[ \\t]*월[ \\t]*${D}(?:[ \\t]*일)?`,
    `${Y}${mm}${dd}`,
    `${monthPat}[ \\t]+${D}${ord},?[ \\t]+${Y}`,
    `${D}${ord}(?:[ \\t]+|-)${monthPat},?(?:[ \\t]+|-)${Y}`,
  ]
  if (d > 12 || d === m) {
    forms.push(`${D}${DATE_SEP}${M}${DATE_SEP}${Y}`)
    if (d !== m) {
      forms.push(`${M}${DATE_SEP}${D}${DATE_SEP}${Y}`)
    }
  }
  // 英文月份匹配需要忽略大小写；纯数字与 CJK 不受 i 标志影响
  return new RegExp(`(?:${forms.join("|")}|${escapeRegExp(raw)})`, "gi")
}

function isDigitChar(ch: string | undefined): boolean {
  return ch !== undefined && ch >= "0" && ch <= "9"
}

function dateWhole(s: string, a: number, b: number): boolean {
  if (a > 0) {
    const prev = s[a - 1]!
    if (isDigitChar(prev) || (prev === "." && a > 1 && isDigitChar(s[a - 2]))) {
      return false
    }
    const firstChar = s[a]!
    if (LETTER_RE.test(firstChar) && LETTER_RE.test(prev) && !CJK_CHAR_RE.test(prev)) {
      return false
    }
  }
  if (b < s.length) {
    const next = s[b]!
    if (isDigitChar(next) || (next === "." && b + 1 < s.length && isDigitChar(s[b + 1]))) {
      return false
    }
  }
  return true
}

/** 缓存每个日期词对应的编译正则（实例内复用） */
export class DateWordMatcher {
  private readonly cache = new Map<string, RegExp | null>()

  match(s: string, word: string): { readonly matched: boolean; readonly spans: Span[] } {
    let re = this.cache.get(word)
    if (re === undefined) {
      const parsed = parseDateWord(word)
      re = parsed ? buildDatePattern(parsed[0], parsed[1], parsed[2], word) : null
      this.cache.set(word, re)
    }
    if (!re) return { matched: false, spans: [] }
    re.lastIndex = 0
    const spans: Span[] = []
    for (const m of s.matchAll(re)) {
      const start = m.index ?? -1
      if (start < 0 || !m[0]) continue
      const end = start + m[0].length
      if (dateWhole(s, start, end)) {
        spans.push({ start, end, kind: "TERM", by: "word" })
      }
    }
    return { matched: true, spans }
  }
}
