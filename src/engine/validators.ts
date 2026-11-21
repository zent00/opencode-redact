// 上下文校验与防误报过滤器（借鉴 Magpie fieldvalue.go / ids.go / phone.go / more.go / redact.go）。
import net from "node:net"
import { ALNUM, DIGITS, type Span, TOKEN_CH } from "./types.js"

// ---- 基础字符工具 ----

export function lowerASCII(s: string): string {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c >= 65 && c <= 90) {
      let out = s.slice(0, i)
      for (let j = i; j < s.length; j++) {
        const ch = s.charCodeAt(j)
        out += ch >= 65 && ch <= 90 ? String.fromCharCode(ch + 32) : s[j]!
      }
      return out
    }
  }
  return s
}

export function isSpaceChar(ch: string | undefined): boolean {
  return ch === " " || ch === "\t" || ch === "\n" || ch === "\r"
}

export function isAsciiLetter(ch: string | undefined): boolean {
  if (!ch) return false
  const c = ch.charCodeAt(0)
  return (c >= 65 && c <= 90) || (c >= 97 && c <= 122)
}

export function isAsciiDigit(ch: string | undefined): boolean {
  if (!ch) return false
  const c = ch.charCodeAt(0)
  return c >= 48 && c <= 57
}

export function isWordByte(ch: string | undefined): boolean {
  if (!ch) return false
  const c = ch.charCodeAt(0)
  return c === 95 || (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122)
}

export function containsAnyChar(s: string, chars: string): boolean {
  for (let i = 0; i < s.length; i++) {
    if (chars.includes(s[i]!)) return true
  }
  return false
}

export function hasOnlyChars(s: string, chars: string): boolean {
  for (let i = 0; i < s.length; i++) {
    if (!chars.includes(s[i]!)) return false
  }
  return true
}

export function trimRightChars(s: string, chars: string): string {
  let end = s.length
  while (end > 0 && chars.includes(s[end - 1]!)) end--
  return s.slice(0, end)
}

export function trimLeftChars(s: string, chars: string): string {
  let start = 0
  while (start < s.length && chars.includes(s[start]!)) start++
  return s.slice(start)
}

export function trimChars(s: string, chars: string): string {
  return trimRightChars(trimLeftChars(s, chars), chars)
}

function hasAsciiLetter(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122)) return true
  }
  return false
}

function hasAsciiDigit(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c >= 48 && c <= 57) return true
  }
  return false
}

function hasUpperAscii(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c >= 65 && c <= 90) return true
  }
  return false
}

// ---- 密钥/字段上下文校验 ----

/** 过滤占位符/变量引用：${PASS}、<password>、****、xxxx */
export function notAVariable(v: string): boolean {
  if (!v) return false
  if ("$%{<[*".includes(v[0]!)) return false
  return trimChars(v, "*xX.") !== ""
}

export function keyValue(v: string): boolean {
  if (!notAVariable(v)) return false
  return hasAsciiLetter(v) && (hasAsciiDigit(v) || v.length >= 16)
}

const KEY_SEPARATORS = ["为", "為", "是", "：", ":", "=", "は", "는"]
const QUANTITY_UNITS = [
  "位",
  "比特",
  "字节",
  "字節",
  "个",
  "個",
  "次",
  "秒",
  "毫秒",
  "分钟",
  "分鐘",
  "小时",
  "小時",
  "天",
  "年",
  "bit",
  "byte",
  "ms",
  "sec",
  "min",
  "ビット",
  "バイト",
  "비트",
  "바이트",
]

export function keyAt(s: string, a: number, b: number): boolean {
  const v = s.slice(a, b)
  if (pathValue(v) || versionValue(v) || timestampValue(v)) {
    return false
  }
  if (keyValue(v)) return true
  if (v.length < 6 || !hasOnlyChars(v, DIGITS)) return false
  const before = trimRightChars(s.slice(0, a), " \t\"'“「\\")
  const after = trimLeftChars(s.slice(b), " \t")
  return KEY_SEPARATORS.some((sep) => before.endsWith(sep)) && !QUANTITY_UNITS.some((u) => after.startsWith(u))
}

export function secretValue(v: string): boolean {
  if (!notAVariable(v) || v.startsWith("process.env") || v.startsWith("os.")) return false
  return hasAsciiDigit(v) && hasAsciiLetter(v)
}

const IDENT_PATH_RE = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*$/

/** 排除代码中的函数调用与类型声明（如 privateKey: toBase64Url(...), secretKey: Uint8Array;） */
export function notCode(s: string, a: number, b: number): boolean {
  if (!IDENT_PATH_RE.test(s.slice(a, b))) return true
  const rest = trimLeftChars(s.slice(b), " \t")
  if (rest.startsWith("(")) return false
  if ((a > 0 && (s[a - 1] === '"' || s[a - 1] === "'")) || !trimRightChars(s.slice(0, a), " \t").endsWith(":")) {
    return true
  }
  return rest === "" || !";,)}]|?&<>".includes(rest[0]!)
}

/** 排除纯小写连字符 slug（如 sk-hynix-third-quarter-profit）误命中 sk- 规则 */
export function notASlug(v: string): boolean {
  if (hasUpperAscii(v)) return true
  const tail = v.startsWith("sk-") ? v.slice(3) : v
  if (/^[0-9a-f_-]+$/.test(tail)) return true
  for (const w of v.split(/[-_]/)) {
    if (w.length >= 16) return true
  }
  return false
}

export function headerValue(v: string): boolean {
  const t = v.trim()
  if (!t || !notAVariable(t)) return false
  const fields = t.split(/\s+/)
  if (fields.length === 1 || (fields.length === 2 && /^[A-Za-z]+$/.test(fields[0]!))) {
    const cred = fields[fields.length - 1]!
    return cred.length >= 8 && notAVariable(cred) && /[^A-Za-z]/.test(cred)
  }
  for (const rawKv of t.split(";")) {
    const kv = rawKv.trim()
    if (!kv) continue
    const eq = kv.indexOf("=")
    if (eq <= 0) return false
    const name = kv.slice(0, eq)
    if (/[ \t]/.test(name)) return false
  }
  return t.includes("=")
}

export function notAPlainKey(s: string, a: number): boolean {
  let i = a
  while (i > 0 && `"' \t:=`.includes(s[i - 1]!)) i--
  const end = i
  while (i > 0 && (ALNUM.includes(s[i - 1]!) || "_.-".includes(s[i - 1]!))) i--
  const name = s.slice(i, end).toLowerCase()
  return (
    !name.endsWith("sort_key") &&
    !name.endsWith("cache_key") &&
    !name.endsWith("prompt_cache_key") &&
    !name.endsWith("public_key")
  )
}

export function namedSecretAt(s: string, a: number, b: number): boolean {
  return notAPlainKey(s, a) && fieldAt(s, a, b)
}

// ---- fieldvalue.go 防误报 ----

const VERSION_RANGE_RE =
  /^(?:[~^]|[<>=!~]=?|==)?[vV]?\d+(?:\.\d+)+(?:[-+._]?(?:(?:alpha|beta|rc|pre|preview|post|dev|canary|next|nightly|snapshot|release|final|ga|stable|build|incubating)\d*|[abcmABCM]\d+|\d+))*$/i

export function versionValue(v: string): boolean {
  return VERSION_RANGE_RE.test(v)
}

const STAMP_RE = /^\d{4}-\d{1,2}-\d{1,2}[Tt]\d{1,2}(?::\d{1,2}){0,2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:?\d{2})?$/

export function timestampValue(v: string): boolean {
  return STAMP_RE.test(v)
}

const SKILL_SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)+$/

function skillName(s: string, a: number, b: number): boolean {
  const v = s.slice(a, b)
  if (a < 2 || s[a - 1] !== ":" || !SKILL_SLUG_RE.test(v) || notASlug(v)) return false
  let i = a - 1
  while (i > 0 && /[a-z0-9-]/.test(s[i - 1]!)) i--
  return (
    i < a - 1 &&
    (i === 0 || !(ALNUM.includes(s[i - 1]!) || "_.".includes(s[i - 1]!))) &&
    SKILL_SLUG_RE.test(s.slice(i, a - 1))
  )
}

const LINE_REF_RE = /^L?\d+(?:[-–:]L?\d+)*[.,;:]?$/

function lineRef(v: string): boolean {
  return LINE_REF_RE.test(v)
}

const SOURCE_EXT = new Set([
  "go",
  "ts",
  "tsx",
  "mts",
  "cts",
  "js",
  "jsx",
  "mjs",
  "cjs",
  "py",
  "pyi",
  "rb",
  "rs",
  "java",
  "kt",
  "kts",
  "swift",
  "c",
  "h",
  "cc",
  "cpp",
  "cxx",
  "hpp",
  "hh",
  "m",
  "mm",
  "cs",
  "fs",
  "php",
  "scala",
  "dart",
  "lua",
  "zig",
  "nim",
  "ex",
  "exs",
  "erl",
  "hs",
  "ml",
  "clj",
  "r",
  "jl",
  "sh",
  "bash",
  "zsh",
  "fish",
  "ps1",
  "vue",
  "svelte",
  "astro",
  "md",
  "mdx",
  "rst",
  "sql",
  "proto",
  "graphql",
  "gradle",
  "html",
  "css",
  "scss",
  "less",
  "json",
  "jsonc",
  "yaml",
  "yml",
  "toml",
  "xml",
  "tf",
  "ipynb",
])

function fileField(s: string, a: number): boolean {
  let i = a
  while (i > 0 && " \t\"'\\".includes(s[i - 1]!)) i--
  if (i === 0 || (s[i - 1] !== ":" && s[i - 1] !== "=")) return false
  i--
  while (i > 0 && " \t\"'\\".includes(s[i - 1]!)) i--
  const end = i
  while (i > 0 && (ALNUM.includes(s[i - 1]!) || "_.-".includes(s[i - 1]!))) i--
  const name = s.slice(i, end)
  if (!name) return false
  if (i > 0 && (s[i - 1] === "/" || s[i - 1] === "\\")) return true
  const dot = name.lastIndexOf(".")
  return dot > 0 && SOURCE_EXT.has(name.slice(dot + 1).toLowerCase())
}

const PATH_ROOTS = new Set([
  "Users",
  "home",
  "tmp",
  "private",
  "var",
  "etc",
  "run",
  "opt",
  "usr",
  "mnt",
  "Volumes",
  "root",
  "srv",
  "data",
  "workspace",
  "workspaces",
  "app",
  "Applications",
  "Library",
  "System",
  "proc",
  "dev",
  "sys",
  "nix",
])

export function pathValue(v: string): boolean {
  if (v.includes("+") || v.includes("=")) return false
  if (
    (v.startsWith("~/") && v.length > 2) ||
    (v.startsWith("./") && v.length > 2) ||
    (v.startsWith("../") && v.length > 3)
  ) {
    return true
  }
  if (!v.startsWith("/")) return false
  const slash = v.indexOf("/", 1)
  if (slash < 0 || slash === v.length - 1) return false
  return PATH_ROOTS.has(v.slice(1, slash))
}

const SECRET_WORDS = new Set([
  "token",
  "tokens",
  "secret",
  "secrets",
  "password",
  "passwords",
  "passwd",
  "pwd",
  "key",
  "keys",
  "apikey",
  "credential",
  "credentials",
])

const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/

export function identWords(v: string): string[] {
  const out: string[] = []
  for (const part of v.split(/[_.]/)) {
    if (!part) continue
    let start = 0
    for (let i = 1; i < part.length; i++) {
      const c = part.charCodeAt(i)
      const prev = part.charCodeAt(i - 1)
      if (c >= 65 && c <= 90 && prev >= 97 && prev <= 122) {
        out.push(part.slice(start, i))
        start = i
      }
    }
    out.push(part.slice(start))
  }
  return out
}

function namesASecret(v: string): boolean {
  if (!IDENT_RE.test(v)) return false
  const firstCode = v.charCodeAt(0)
  const startsLower = firstCode >= 97 && firstCode <= 122
  if (!startsLower && !v.includes("_") && !v.includes(".")) return false
  let words = 0
  let named = false
  for (let w of identWords(v)) {
    if (!hasAsciiLetter(w)) continue
    words++
    const dIdx = w.search(/\d/)
    if (dIdx >= 0) w = w.slice(0, dIdx)
    if (SECRET_WORDS.has(w.toLowerCase())) named = true
  }
  return words >= 2 && named
}

export function fieldAt(s: string, a: number, b: number): boolean {
  if (!notCode(s, a, b)) return false
  const v = s.slice(a, b)
  if (v.startsWith("=")) return false
  return (
    !fileField(s, a) &&
    !lineRef(v) &&
    !pathValue(v) &&
    !namesASecret(v) &&
    !skillName(s, a, b) &&
    !versionValue(v) &&
    !timestampValue(v)
  )
}

const NEXT_FIELD_RE = /^(?:[A-Z_][A-Z0-9_]*|[a-z_][a-z0-9_-]*|--?[A-Za-z][A-Za-z0-9_-]*)=[^=]/

export function isNextField(s: string, a: number, b: number): boolean {
  return a > 0 && (s[a - 1] === " " || s[a - 1] === "\t") && NEXT_FIELD_RE.test(s.slice(a, b))
}

// ---- URL 与 Email 校验 ----

export function inUserinfo(s: string, a: number): boolean {
  let i = a
  while (i > 0 && !" \t\r\n/?#\"'<>@`".includes(s[i - 1]!)) i--
  if (i < 3 || s[i - 1] !== "/" || s[i - 2] !== "/" || s[i - 3] !== ":") return false
  const j = i - 3
  let k = j
  while (k > 0 && (ALNUM.includes(s[k - 1]!) || "+.-".includes(s[k - 1]!))) k--
  while (k < j && !isAsciiLetter(s[k])) k++
  return k < j
}

export function emailAt(s: string, a: number, b: number): boolean {
  if (a > 0 && s[a - 1] === ".") return false
  if (b + 1 < s.length && s[b] === "." && TOKEN_CH.includes(s[b + 1]!)) return false
  return !inUserinfo(s, a)
}

/** URL 中 user:password@host 如果密码与用户名/主机/路径片段完全相同（如 postgres:postgres@），说明本身已暴露，不脱敏以免污染项目名 */
export function hiddenInURL(s: string, a: number, b: number): boolean {
  const pw = s.slice(a, b)
  const i = s.lastIndexOf("//", a)
  if (i < 0 || s[a - 1] !== ":") return true
  if (s.slice(i + 2, a - 1) === pw) return false
  let end = b + 1
  while (end < s.length && !" \t\r\n\"'<>`\\)]}".includes(s[end]!)) end++
  if (b + 1 > end) return true
  for (const part of s.slice(b + 1, end).split(/[/:.?#&=;,@]+/)) {
    if (part === pw) return false
  }
  return true
}

const LINKER_WORDS = new Set(["plt", "got", "sec", "iplt", "igot"])
const DOC_FILES = new Set([
  "agents.md",
  "claude.md",
  "gemini.md",
  "readme.md",
  "skill.md",
  "changelog.md",
  "contributing.md",
  "license.md",
  "lessons.md",
  "todo.md",
  "copilot-instructions.md",
  "crush.md",
  "qwen.md",
  "iflow.md",
  "warp.md",
])
const LOCAL_TLDS = new Set(["local", "internal", "lan", "corp", "home", "intranet", "localdomain"])
const FILE_EXT = new Set([
  "jpg",
  "jpeg",
  "png",
  "gif",
  "webp",
  "svg",
  "heic",
  "heif",
  "avif",
  "bmp",
  "tif",
  "tiff",
  "ico",
  "icns",
  "pdf",
  "svgz",
  "apng",
  "jxl",
  "psd",
  "eps",
  "lottie",
  "mp4",
  "m4v",
  "webm",
  "mkv",
  "avi",
  "mp3",
  "m4a",
  "wav",
  "ogg",
  "flac",
  "aac",
  "ttf",
  "otf",
  "woff",
  "woff2",
  "eot",
  "json",
  "yaml",
  "yml",
  "toml",
  "xml",
  "txt",
  "csv",
  "tsv",
  "log",
  "html",
  "htm",
  "css",
  "scss",
  "less",
  "js",
  "mjs",
  "cjs",
  "jsx",
  "ts",
  "tsx",
  "doc",
  "docx",
  "xls",
  "xlsx",
  "ppt",
  "pptx",
  "gz",
  "tgz",
  "tar",
  "rar",
  "7z",
  "dmg",
])
const SCALE_EXT = new Set(["zip", "mov", "md", "map"])
const SCALE_RE = /^[0-9]+(?:\.[0-9]+)?x$/

// 常见 IANA 通用顶级域（覆盖绝大多数真实邮箱域名，排除如 pytest.fixture 等代码属性）
const KNOWN_GTLDS = new Set([
  "com",
  "org",
  "net",
  "edu",
  "gov",
  "mil",
  "int",
  "info",
  "biz",
  "name",
  "pro",
  "aero",
  "coop",
  "museum",
  "app",
  "dev",
  "cloud",
  "tech",
  "site",
  "online",
  "store",
  "shop",
  "blog",
  "xyz",
  "top",
  "vip",
  "club",
  "fun",
  "icu",
  "work",
  "space",
  "world",
  "today",
  "life",
  "live",
  "news",
  "media",
  "email",
  "mail",
  "studio",
  "design",
  "agency",
  "digital",
  "network",
  "systems",
  "solutions",
  "services",
  "consulting",
  "finance",
  "capital",
  "ventures",
  "group",
  "team",
  "company",
  "center",
  "academy",
  "school",
  "university",
  "institute",
  "foundation",
  "community",
  "support",
  "help",
  "docs",
  "wiki",
  "tools",
  "software",
  "codes",
  "engineering",
  "science",
  "research",
  "health",
  "care",
  "bank",
  "pay",
  "money",
  "fund",
  "tax",
  "law",
  "legal",
  "run",
  "one",
  "plus",
  "link",
  "page",
  "pub",
  "win",
  "red",
  "blue",
  "green",
  "gold",
  "art",
  "ink",
  "fit",
  "bio",
  "eco",
  "earth",
  "global",
  "asia",
  "eu",
  "nyc",
  "london",
  "berlin",
  "tokyo",
  "paris",
  "zip",
  "mov",
  "map",
  "cat",
  "tel",
  "jobs",
  "mobi",
  "travel",
  "post",
  "xxx",
  "wang",
  "xin",
  "ren",
  "citic",
  "sohu",
  "baidu",
  "alibaba",
  "google",
  "apple",
  "microsoft",
  "amazon",
  "aws",
  "github",
  "gmail",
  "fastmail",
  "proton",
  "hey",
])

// 不应被当成 2 字母 ccTLD 的常见代码/文件名后缀
const NON_MAIL_TWO_LETTER = new Set([
  "js",
  "ts",
  "py",
  "rb",
  "rs",
  "go",
  "kt",
  "cs",
  "fs",
  "ex",
  "hs",
  "ml",
  "jl",
  "md",
  "tf",
  "gz",
  "7z",
  "cc",
  "hh",
  "mm",
])

function mailTLD(tld: string): boolean {
  if (LOCAL_TLDS.has(tld) || KNOWN_GTLDS.has(tld)) return true
  if (tld.length === 2 && /^[a-z]{2}$/.test(tld) && !NON_MAIL_TWO_LETTER.has(tld)) return true
  return tld.startsWith("xn--") && tld.length > 4
}

function mailHost(local: string, host: string): boolean {
  if (local.endsWith("@") || !host.includes(".") || trimChars(host, ".") !== host) return false
  let linker = true
  for (const label of host.split(".")) {
    if (!label) return false
    for (let i = 0; i < label.length; i++) {
      const c = label.charCodeAt(i)
      if (c < 0x80 && c !== 45 && !(c >= 97 && c <= 122) && !(c >= 48 && c <= 57)) {
        return false
      }
    }
    if (!LINKER_WORDS.has(label)) linker = false
  }
  return !linker
}

function fileHost(host: string): boolean {
  const dot = host.lastIndexOf(".")
  const ext = host.slice(dot + 1)
  return FILE_EXT.has(ext) || (dot > 0 && SCALE_EXT.has(ext) && SCALE_RE.test(host.slice(0, dot)))
}

function fileStem(host: string): string {
  let cur = host
  while (true) {
    const dot = cur.lastIndexOf(".")
    if (dot < 0 || !FILE_EXT.has(cur.slice(dot + 1))) return cur
    cur = cur.slice(0, dot)
  }
}

const FAKE_MAIL_HOSTS = ["example.com", "example.org", "example.net", "localhost", ".test", ".invalid", ".example"]

export function realEmail(v: string): boolean {
  const at = v.lastIndexOf("@")
  if (at <= 0) return false
  const local = v.slice(0, at)
  if (local.toLowerCase() === "git") return false
  let host = v.slice(at + 1).toLowerCase()
  if (!mailHost(local, host)) return false
  if (fileHost(host)) {
    host = fileStem(host)
    if (!host.includes(".") || fileHost(host) || !mailHost(local, host)) return false
  }
  const tld = host.slice(host.lastIndexOf(".") + 1)
  if (DOC_FILES.has(host) || !mailTLD(tld)) return false
  for (const fake of FAKE_MAIL_HOSTS) {
    const bare = fake.startsWith(".") ? fake.slice(1) : fake
    if (host === bare || host.endsWith(fake)) return false
  }
  return !host.startsWith("noreply") && !v.toLowerCase().includes("noreply@")
}

// ---- 证件/银行卡/电话校验 ----

const ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
const ID_CHECK = "10X98765432"

export function chineseID(v: string): boolean {
  if (v.length !== 18) return false
  let sum = 0
  for (let i = 0; i < 17; i++) {
    sum += (v.charCodeAt(i) - 48) * ID_WEIGHTS[i]!
  }
  return v[17]!.toUpperCase() === ID_CHECK[sum % 11]
}

export function luhn(v: string): boolean {
  const ds: number[] = []
  for (let i = 0; i < v.length; i++) {
    const c = v.charCodeAt(i)
    if (c >= 48 && c <= 57) ds.push(c - 48)
  }
  if (ds.length < 15 || ds.length > 19) return false
  let sum = 0
  for (let i = 0; i < ds.length; i++) {
    let d = ds[ds.length - 1 - i]!
    if (i % 2 === 1) {
      d *= 2
      if (d > 9) d -= 9
    }
    sum += d
  }
  return sum % 10 === 0
}

const PHONE_WORDS = new Set([
  "phone",
  "phones",
  "mobile",
  "mobiles",
  "tel",
  "telephone",
  "cell",
  "cellphone",
  "contact",
  "contacts",
  "whatsapp",
  "sms",
  "msisdn",
  "fax",
])
const PHONE_MARKS = ["手机", "电话", "電話", "联系", "聯繫", "联络"]
const ID_WORDS = [
  "order",
  "id",
  "uid",
  "no",
  "no.",
  "#",
  "number",
  "ticket",
  "invoice",
  "订单",
  "订单号",
  "单号",
  "编号",
  "流水号",
  "工单",
  "工单号",
  "运单号",
  "快递单号",
  "订单编号",
  "交易号",
  "序号",
  "账单号",
  "id号",
]

export function nameWords(name: string): string[] {
  const out: string[] = []
  let w = ""
  const flush = () => {
    if (w) {
      out.push(w)
      w = ""
    }
  }
  for (let i = 0; i < name.length; i++) {
    const ch = name[i]!
    const c = ch.charCodeAt(0)
    if (ch === "_" || ch === "-" || ch === ".") {
      flush()
    } else if (c >= 65 && c <= 90) {
      if (i > 0) {
        const prev = name.charCodeAt(i - 1)
        if (prev >= 97 && prev <= 122) flush()
      }
      w += String.fromCharCode(c + 32)
    } else {
      w += ch
    }
  }
  flush()
  return out
}

function phoneName(name: string): boolean {
  for (const w of nameWords(name)) {
    if (PHONE_WORDS.has(w)) return true
  }
  for (const m of PHONE_MARKS) {
    if (name.includes(m)) return true
  }
  return false
}

function nameStart(s: string, i: number): number {
  let j = i
  while (j > 0) {
    const ch = s[j - 1]!
    const code = ch.charCodeAt(0)
    const ok = (code < 0x80 && (ALNUM.includes(ch) || "_.-".includes(ch))) || (code >= 0x4e00 && code <= 0x9fff)
    if (!ok) break
    j--
  }
  return j
}

function hasCJK(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code >= 0x4e00 && code <= 0x9fff) return true
  }
  return false
}

function phoneFieldName(s: string, a: number): { name: string; prev: string } | undefined {
  let i = a
  while (i > 0 && " \t\"'".includes(s[i - 1]!)) i--
  if (i > 0 && s[i - 1] === ">") {
    const startSearch = Math.max(0, i - 65)
    const k = s.lastIndexOf("<", i - 2)
    if (k < startSearch) return undefined
    let tag = s.slice(k + 1, i - 1)
    const sp = tag.search(/[ \t]/)
    if (sp >= 0) tag = tag.slice(0, sp)
    if (!tag || !/^[A-Za-z0-9_.:-]+$/.test(tag)) return undefined
    return { name: tag, prev: "" }
  }
  if (i > 0 && (s[i - 1] === ":" || s[i - 1] === "=" || s[i - 1] === "：")) {
    i--
  } else {
    return undefined
  }
  while (i > 0 && " \t\"'".includes(s[i - 1]!)) i--
  const j = nameStart(s, i)
  if (j === i) return undefined
  let name = s.slice(j, i)
  if (name.length > 6 && hasCJK(name)) {
    name = name.slice(-6)
  }
  let prev = ""
  if (j >= 2 && s[j - 1] === " " && s[j - 2] !== " ") {
    prev = s.slice(nameStart(s, j - 1), j - 1)
  }
  return { name, prev }
}

export function phoneAt(s: string, a: number, b: number): boolean {
  if (b - a > 11) return true // 带 +86 / 86 前缀
  const field = phoneFieldName(s, a)
  if (field) {
    return (
      phoneName(field.name) || (field.prev !== "" && phoneName(field.prev)) || field.name.toLowerCase() === "number"
    )
  }
  if (a > 0 && s[a - 1] === "#") return false
  let before = trimRightChars(s.slice(Math.max(0, a - 32), a), " \t(\"'“「").toLowerCase()
  for (const c of ["是", "为", "為"]) {
    if (before.endsWith(c)) {
      before = trimRightChars(before.slice(0, -c.length), " \t")
    }
  }
  for (const w of ID_WORDS) {
    if (!before.endsWith(w)) continue
    let rest = before.slice(0, before.length - w.length)
    if (rest.length > 0 && w.charCodeAt(0) < 0x80 && isWordByte(rest[rest.length - 1])) {
      continue
    }
    if (w === "no" || w === "no." || w === "number") {
      rest = trimRightChars(rest, " ")
      if (phoneName(rest.slice(nameStart(rest, rest.length)))) return true
    }
    return false
  }
  return true
}

// ---- Personal 细分分类校验（SSN / Passport / IBAN / Birthday / MAC / Serial / Home / User@Host / IP / Bucket）----

export function ssnOK(v: string): boolean {
  const d = v.replace(/[- ]/g, "")
  if (
    d.length !== 9 ||
    d.startsWith("000") ||
    d.startsWith("666") ||
    d[0] === "9" ||
    d.slice(3, 5) === "00" ||
    d.slice(5) === "0000"
  ) {
    return false
  }
  if (d === "123456789" || d === "078051120" || d === "219099999") return false
  return trimChars(d, d[0]!) !== ""
}

export function passportOK(v: string): boolean {
  // 护照号本体必须为大写字母与数字组合
  if (v !== v.toUpperCase()) return false
  let digitCount = 0
  for (let i = 0; i < v.length; i++) {
    if (isAsciiDigit(v[i])) digitCount++
  }
  return digitCount >= 5 && trimChars(v, v[0]!) !== ""
}

const IBAN_LEN: Readonly<Record<string, number>> = {
  AD: 24,
  AE: 23,
  AL: 28,
  AT: 20,
  AZ: 28,
  BA: 20,
  BE: 16,
  BG: 22,
  BH: 22,
  BI: 27,
  BR: 29,
  BY: 28,
  CH: 21,
  CR: 22,
  CY: 28,
  CZ: 24,
  DE: 22,
  DJ: 27,
  DK: 18,
  DO: 28,
  EE: 20,
  EG: 29,
  ES: 24,
  FI: 18,
  FK: 18,
  FO: 18,
  FR: 27,
  GB: 22,
  GE: 22,
  GI: 23,
  GL: 18,
  GR: 27,
  GT: 28,
  HN: 28,
  HR: 21,
  HU: 28,
  IE: 22,
  IL: 23,
  IQ: 23,
  IS: 26,
  IT: 27,
  JO: 30,
  KW: 30,
  KZ: 20,
  LB: 28,
  LC: 32,
  LI: 21,
  LT: 20,
  LU: 20,
  LV: 21,
  LY: 25,
  MC: 27,
  MD: 24,
  ME: 22,
  MK: 19,
  MN: 20,
  MR: 27,
  MT: 31,
  MU: 30,
  NI: 28,
  NL: 18,
  NO: 15,
  OM: 23,
  PK: 24,
  PL: 28,
  PS: 29,
  PT: 25,
  QA: 29,
  RO: 24,
  RS: 22,
  RU: 33,
  SA: 24,
  SC: 31,
  SD: 18,
  SE: 24,
  SI: 19,
  SK: 24,
  SM: 27,
  SO: 23,
  ST: 25,
  SV: 28,
  TL: 23,
  TN: 24,
  TR: 26,
  UA: 29,
  VA: 22,
  VG: 24,
  XK: 20,
  YE: 30,
}

function ibanOK(raw: string): boolean {
  const v = raw.replaceAll(" ", "")
  const expected = IBAN_LEN[v.slice(0, 2)]
  if (expected === undefined || expected !== v.length) return false
  const r = v.slice(4) + v.slice(0, 4)
  let m = 0
  for (let i = 0; i < r.length; i++) {
    const c = r.charCodeAt(i)
    if (c >= 48 && c <= 57) {
      m = (m * 10 + (c - 48)) % 97
    } else if (c >= 65 && c <= 90) {
      m = (m * 100 + (c - 65) + 10) % 97
    } else {
      return false
    }
  }
  return m === 1
}

export function ibanAt(s: string, a: number, b: number): readonly [number, number, boolean] {
  let end = b
  while (true) {
    if (ibanOK(s.slice(a, end))) return [a, end, true]
    const sp = s.slice(a, end).lastIndexOf(" ")
    if (sp < 0) return [0, 0, false]
    end = a + sp
  }
}

const SHORT_MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]

export function birthdayDateOK(v: string, now: () => Date = () => new Date()): boolean {
  const ns = v.match(/\d+/g)
  if (!ns) return false
  const yearAgo = new Date(now().getTime())
  yearAgo.setFullYear(yearAgo.getFullYear() - 1)
  const valid = (y: number, m: number, d: number): boolean => {
    if (y < 1900 || y > 2099 || m < 1 || m > 12 || d < 1 || d > 31) return false
    const dt = new Date(y, m - 1, d)
    return dt.getFullYear() === y && dt.getMonth() === m - 1 && dt.getDate() === d && dt.getTime() < yearAgo.getTime()
  }
  if (ns.length === 2) {
    const l = v.toLowerCase()
    for (let i = 0; i < SHORT_MONTHS.length; i++) {
      if (l.includes(SHORT_MONTHS[i]!)) {
        let d = Number(ns[0])
        let y = Number(ns[1])
        if (ns[0]!.length === 4) {
          d = Number(ns[1])
          y = Number(ns[0])
        }
        return valid(y, i + 1, d)
      }
    }
    return false
  }
  if (ns.length !== 3) return false
  if (ns[0]!.length === 4) {
    return valid(Number(ns[0]), Number(ns[1]), Number(ns[2]))
  }
  const p = Number(ns[0])
  const q = Number(ns[1])
  const y = Number(ns[2])
  return valid(y, p, q) || valid(y, q, p)
}

const FAKE_MACS = new Set([
  "00:00:00:00:00:00",
  "ff:ff:ff:ff:ff:ff",
  "00:11:22:33:44:55",
  "aa:bb:cc:dd:ee:ff",
  "01:23:45:67:89:ab",
  "12:34:56:78:9a:bc",
  "xx:xx:xx:xx:xx:xx",
])

export function macOK(v: string): boolean {
  const l = v.replaceAll("-", ":").toLowerCase()
  if (FAKE_MACS.has(l)) return false
  return /[abcdef]/.test(l)
}

export function serialOK(v: string): boolean {
  return v.length >= 6 && hasAsciiDigit(v) && trimChars(v, v[0]!) !== ""
}

const NOT_NAMES = new Set([
  "shared",
  "public",
  "guest",
  "default",
  "default user",
  "all users",
  "user",
  "username",
  "user_name",
  "yourname",
  "your-name",
  "your_name",
  "yourusername",
  "you",
  "me",
  "name",
  "example",
  "foo",
  "bar",
  "someone",
  "john",
  "jdoe",
  "runner",
  "node",
  "vscode",
  "codespace",
  "linuxbrew",
  "...",
])

export function homeAt(s: string, a: number, b: number): readonly [number, number, boolean] {
  let end = b
  while (end > a && s[end - 1] === ".") end--
  if (end === a || s[a] === "." || NOT_NAMES.has(s.slice(a, end).toLowerCase())) {
    return [0, 0, false]
  }
  return [a, end, true]
}

const NOT_USERS = new Set([
  "git",
  "root",
  "ec2-user",
  "ubuntu",
  "admin",
  "postgres",
  "www-data",
  "nobody",
  "centos",
  "debian",
  "fedora",
  "azureuser",
  "opc",
  "core",
  "vagrant",
  "docker",
  "str",
  "string",
  "int",
  "bool",
  "any",
  "none",
  "null",
  "nil",
  "true",
  "false",
  "undefined",
  "hi",
  "hello",
  "hey",
  "yes",
  "no",
  "ok",
  "okay",
  "thanks",
  "continue",
  "go",
  "stop",
  "help",
  "test",
  "y",
  "n",
])

const CODE_OBJECTS = new Set([
  "self",
  "this",
  "os",
  "process",
  "request",
  "req",
  "ctx",
  "context",
  "config",
  "cfg",
  "conf",
  "settings",
  "env",
  "args",
  "opts",
  "options",
  "props",
  "params",
  "session",
  "socket",
  "platform",
  "window",
  "location",
  "url",
  "u",
  "r",
  "c",
  "s",
  "m",
  "p",
  "x",
  "data",
  "info",
  "user",
])

const CHAT_WORDS = new Set([
  "done",
  "why",
  "what",
  "how",
  "sure",
  "please",
  "retry",
  "next",
  "again",
  "great",
  "good",
  "nice",
  "cool",
  "fix",
  "go-ahead",
  "proceed",
  "lgtm",
  "required",
  "optional",
  "unknown",
  "anonymous",
  "guest",
  "current",
  "me",
])

const PUBLIC_HOSTS = new Set([
  "github.com",
  "gitlab.com",
  "bitbucket.org",
  "ssh.dev.azure.com",
  "vs-ssh.visualstudio.com",
  "localhost",
  "host",
  "hostname",
  "server",
  "remote",
  "example",
  "your-server",
  "str",
  "string",
  "none",
  "null",
  "true",
  "false",
  "undefined",
])

const IDENT_PARTS = new Set([
  "user",
  "users",
  "usr",
  "username",
  "name",
  "names",
  "login",
  "logname",
  "account",
  "acct",
  "owner",
  "author",
  "member",
  "person",
  "profile",
  "current",
  "cur",
  "default",
  "target",
  "new",
  "old",
  "my",
  "the",
  "obj",
  "object",
  "info",
  "id",
  "model",
  "data",
  "record",
  "entity",
  "row",
  "item",
  "input",
  "arg",
  "args",
  "param",
  "value",
  "val",
  "str",
  "type",
  "dto",
  "db",
  "auth",
  "session",
  "self",
])

export function userOK(v: string): boolean {
  const l = v.toLowerCase()
  return v.length >= 2 && !NOT_USERS.has(l) && !NOT_NAMES.has(l)
}

export function unixUserOK(v: string): boolean {
  return v === v.toLowerCase() && userOK(v)
}

function inCode(v: string): boolean {
  const dot = v.indexOf(".")
  if (dot < 0) return false
  const first = v.slice(0, dot).toLowerCase()
  const last = v.slice(v.lastIndexOf(".") + 1).toLowerCase()
  return (
    CODE_OBJECTS.has(first) ||
    NOT_USERS.has(last) ||
    NOT_NAMES.has(last) ||
    PUBLIC_HOSTS.has(last) ||
    last === "login" ||
    last === "username"
  )
}

const VERSION_HOST_RE = /^v?\d+(?:\.\d+)+(?:-[0-9A-Za-z.-]+)?$/

function versionHost(h: string): boolean {
  return VERSION_HOST_RE.test(h) && net.isIP(h) === 0
}

export function notPackagePin(s: string, a: number, b: number): boolean {
  if (b < s.length && s[b] === "@") {
    let e = b + 1
    while (e < s.length && (ALNUM.includes(s[e]!) || "-.".includes(s[e]!))) e++
    return !versionHost(trimRightChars(s.slice(b + 1, e), "."))
  }
  return !(a > 0 && s[a - 1] === "@" && versionHost(s.slice(a, b)))
}

export function lineUserOK(v: string): boolean {
  const l = v.toLowerCase()
  return userOK(v) && !inCode(v) && !CHAT_WORDS.has(l) && !IDENT_PARTS.has(l)
}

export function notLineIdent(s: string, a: number, b: number): boolean {
  if (a > 0 && (s[a - 1] === '"' || s[a - 1] === "'")) return true
  const ws = identWords(s.slice(a, b))
  if (ws.length < 2) return true
  return !ws.some((x) => IDENT_PARTS.has(x.toLowerCase()))
}

export function hostOK(v: string): boolean {
  const l = trimRightChars(v, ".").toLowerCase()
  if (l.length < 2 || PUBLIC_HOSTS.has(l) || l.startsWith("process.") || l.startsWith("os.") || l.startsWith("env.")) {
    return false
  }
  if (net.isIP(l) !== 0) return false
  for (const ex of ["example.com", "example.org", "example.net", ".example", ".test", ".invalid", ".localhost"]) {
    const bare = ex.startsWith(".") ? ex.slice(1) : ex
    if (l === bare || l.endsWith(ex)) return false
  }
  return true
}

export function lineHostOK(v: string): boolean {
  return hostOK(v) && !inCode(v)
}

const PARAM_REST_RE = /^(?:[,):]|[*[\]]*[A-Za-z_][\w.*[\]]*[ \t]*[,)])/
const DECL_WORDS = [
  "const",
  "let",
  "var",
  "val",
  "def",
  "func",
  "fn",
  "function",
  "class",
  "struct",
  "interface",
  "enum",
  "return",
  "import",
  "typeof",
]

/** 防止作为 known 回溯的用户名误匹配代码变量/函数/JSON 键 */
export function nameAlone(s: string, a: number, b: number): boolean {
  const identChar = (ch: string | undefined) => isWordByte(ch) || ch === "$"
  if ((a > 0 && identChar(s[a - 1])) || (b < s.length && identChar(s[b]))) return false
  if (
    (a > 1 && (s[a - 1] === "." || s[a - 1] === "-") && identChar(s[a - 2])) ||
    (b + 1 < s.length && (s[b] === "." || s[b] === "-") && identChar(s[b + 1]))
  ) {
    return false
  }
  const quoted = a > 0 && b < s.length && (s[a - 1] === '"' || s[a - 1] === "'") && s[b] === s[a - 1]
  if (quoted) {
    return !trimLeftChars(s.slice(b + 1), " \t").startsWith(":")
  }
  if (a > 0 && (s[a - 1] === '"' || s[a - 1] === "'" || s[a - 1] === "`")) return true
  const rest = trimLeftChars(s.slice(b), " \t")
  if (rest && ("([=".includes(rest[0]!) || rest.startsWith(":="))) return false
  const head = trimRightChars(s.slice(0, a), " \t")
  if (head.length < a) {
    for (const kw of DECL_WORDS) {
      if (head.endsWith(kw) && (head.length === kw.length || !identChar(head[head.length - kw.length - 1]))) {
        return false
      }
    }
  }
  if (head.endsWith(" =") || head.endsWith("\t=") || head.endsWith(":=")) return false
  if (head && (head[head.length - 1] === "(" || head[head.length - 1] === ",") && PARAM_REST_RE.test(rest)) {
    return head[head.length - 1] === "(" && head.length > 1 && isAsciiDigit(head[head.length - 2])
  }
  return true
}

// ---- 公网 IPv4 / IPv6 校验 ----

const RESOLVERS = new Set([
  "8.8.8.8",
  "8.8.4.4",
  "1.1.1.1",
  "1.0.0.1",
  "9.9.9.9",
  "149.112.112.112",
  "208.67.222.222",
  "208.67.220.220",
  "114.114.114.114",
  "223.5.5.5",
  "223.6.6.6",
  "119.29.29.29",
  "180.76.76.76",
  "2001:4860:4860::8888",
  "2001:4860:4860::8844",
  "2606:4700:4700::1111",
  "2606:4700:4700::1001",
])

function parseIPv4Int(ip: string): number | undefined {
  const parts = ip.split(".")
  if (parts.length !== 4) return undefined
  let n = 0
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || (p.length > 1 && p.startsWith("0"))) return undefined
    const v = Number(p)
    if (v > 255) return undefined
    n = (n << 8) | v
  }
  return n >>> 0
}

function isPublicIPv4(ip: string): boolean {
  if (RESOLVERS.has(ip)) return false
  const n = parseIPv4Int(ip)
  if (n === undefined) return false
  const a = (n >>> 24) & 0xff
  const b = (n >>> 16) & 0xff
  const c = (n >>> 8) & 0xff
  // 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8
  if (a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127)) return false
  // 169.254.0.0/16, 172.16.0.0/12
  if ((a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)) return false
  // 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16
  if (a === 192 && ((b === 0 && (c === 0 || c === 2)) || b === 168)) return false
  // 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24
  if (
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113)
  ) {
    return false
  }
  // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved/broadcast
  if (a >= 224) return false
  return true
}

/** 将 IPv6 展开为 8 个 16-bit 整数，支持 :: 压缩与内嵌 IPv4 */
export function parseIPv6Groups(raw: string): number[] | undefined {
  if (!net.isIPv6(raw)) return undefined
  let s = raw.toLowerCase()
  const lastColon = s.lastIndexOf(":")
  if (s.includes(".")) {
    const v4 = parseIPv4Int(s.slice(lastColon + 1))
    if (v4 === undefined) return undefined
    s = `${s.slice(0, lastColon + 1)}${((v4 >>> 16) & 0xffff).toString(16)}:${(v4 & 0xffff).toString(16)}`
  }
  const halves = s.split("::")
  if (halves.length > 2) return undefined
  const left = halves[0] ? halves[0].split(":").map((x) => Number.parseInt(x, 16)) : []
  const right = halves.length === 2 && halves[1] ? halves[1].split(":").map((x) => Number.parseInt(x, 16)) : []
  const fill = 8 - left.length - right.length
  if (fill < 0 || (halves.length === 1 && fill !== 0)) return undefined
  return [...left, ...new Array<number>(fill).fill(0), ...right]
}

export function normalizeIP(v: string): string | undefined {
  if (net.isIPv4(v)) return v
  const g = parseIPv6Groups(v)
  if (!g) return undefined
  // ::ffff:a.b.c.d -> IPv4
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff) {
    return `${(g[6]! >>> 8) & 0xff}.${g[6]! & 0xff}.${(g[7]! >>> 8) & 0xff}.${g[7]! & 0xff}`
  }
  return g.map((x) => x.toString(16)).join(":")
}

export function isPublicIP(v: string): boolean {
  if (net.isIPv4(v)) return isPublicIPv4(v)
  const g = parseIPv6Groups(v)
  if (!g) return false
  // IPv4-mapped IPv6
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff) {
    const v4 = `${(g[6]! >>> 8) & 0xff}.${g[6]! & 0xff}.${(g[7]! >>> 8) & 0xff}.${g[7]! & 0xff}`
    return isPublicIPv4(v4)
  }
  // 仅允许全局单播 2000::/3
  if ((g[0]! & 0xe000) !== 0x2000) return false
  // 2001:db8::/32 文档地址
  if (g[0] === 0x2001 && g[1] === 0x0db8) return false
  // 跳过已知公共 DNS
  const full = v.toLowerCase()
  if (RESOLVERS.has(full)) return false
  const canonical = normalizeIP(full)
  if (canonical) {
    for (const r of RESOLVERS) {
      if (r.includes(":") && normalizeIP(r) === canonical) return false
    }
  }
  return true
}

const VERSION_PREFIX_WORDS = ["version", "ver", "release", "build", "rev", "版本"]

export function ipv4At(s: string, a: number, b: number): boolean {
  if (a > 0) {
    const c = s[a - 1]!
    if (ALNUM.includes(c) || "._-=~^".includes(c)) return false
    if (c === "/" && a >= 2 && (ALNUM.includes(s[a - 2]!) || "._-".includes(s[a - 2]!))) return false
  }
  if (b < s.length) {
    const c = s[b]!
    if (ALNUM.includes(c) || "_-".includes(c) || (c === "." && b + 1 < s.length && isAsciiDigit(s[b + 1]))) {
      return false
    }
  }
  const before = trimRightChars(s.slice(Math.max(0, a - 16), a), " \t:=\"'").toLowerCase()
  for (const w of VERSION_PREFIX_WORDS) {
    if (before.endsWith(w)) {
      const idx = before.length - w.length - 1
      if (idx < 0 || !(ALNUM.includes(before[idx]!) || before[idx] === "_")) return false
    }
  }
  return isPublicIPv4(s.slice(a, b))
}

export function ipv6OK(v: string): boolean {
  let colons = 0
  for (let i = 0; i < v.length; i++) if (v[i] === ":") colons++
  if (colons < 2) return false
  return net.isIPv6(v) && isPublicIP(v)
}

const NOT_BUCKETS = new Set([
  "bucket",
  "my-bucket",
  "mybucket",
  "bucket-name",
  "bucketname",
  "my-bucket-name",
  "your-bucket",
  "your-bucket-name",
  "yourbucket",
  "example-bucket",
  "examplebucket",
  "amzn-s3-demo-bucket",
  "doc-example-bucket",
  "s3",
  "www",
  "storage",
  "container",
  "mycontainer",
  "my-container",
  "mystorageaccount",
  "account",
  "upload",
  "download",
  "batch",
  "b",
  "v1",
  "v2",
  "api",
])

export function bucketOK(v: string): boolean {
  const l = v.toLowerCase()
  return l.length >= 3 && !NOT_BUCKETS.has(l) && !hasOnlyChars(l, DIGITS)
}

// ---- noIDs 与 noNumbers（ids.go / redact.go）----

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function isHexOrHyphen(ch: string | undefined): boolean {
  if (!ch) return false
  const c = ch.charCodeAt(0)
  return c === 45 || (c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70)
}

function digestShaped(v: string): boolean {
  if (v.length < 16 || v.length >= 32) return false
  let lower = 0
  let upper = 0
  let digits = 0
  for (let i = 0; i < v.length; i++) {
    const c = v.charCodeAt(i)
    if (c >= 48 && c <= 57) digits++
    else if (c >= 97 && c <= 102) lower++
    else if (c >= 65 && c <= 70) upper++
    else return false
  }
  const letters = lower + upper
  const minPart = Math.max(3, Math.floor(v.length / 8))
  return (lower === 0 || upper === 0) && letters >= minPart && digits >= minPart
}

function idShaped(v: string): boolean {
  return UUID_RE.test(v) || (v.length >= 32 && !v.includes("-")) || digestShaped(v)
}

function fieldWordsAt(s: string, at: number): string[] {
  let i = at
  while (i > 0 && " \t\"'\\".includes(s[i - 1]!)) i--
  if (i === 0 || (s[i - 1] !== ":" && s[i - 1] !== "=")) return []
  i--
  while (i > 0 && " \t\"'\\".includes(s[i - 1]!)) i--
  let j = i
  while (j > 0 && (ALNUM.includes(s[j - 1]!) || "_.-".includes(s[j - 1]!))) j--
  return nameWords(s.slice(j, i))
}

function isElementField(words: readonly string[]): boolean {
  return words.length === 2 && words[0] === "element" && words[1] === "token"
}

function elementToken(s: string, a: number, b: number): boolean {
  if (b - a < 9 || s[a] !== "s" || (a > 0 && isWordByte(s[a - 1]))) return false
  for (let i = a + 1; i < a + 9; i++) {
    const c = s.charCodeAt(i)
    if (!((c >= 48 && c <= 57) || (c >= 97 && c <= 102))) return false
  }
  let end = a + 9
  if (end < s.length && s[end] === ":") {
    let i = end + 1
    while (i < s.length && isAsciiDigit(s[i])) i++
    if (i === end + 1) return false
    end = i
  }
  if ((b !== a + 9 && b !== end) || (end < s.length && isWordByte(s[end]))) return false
  return end > a + 9 || isElementField(fieldWordsAt(s, a))
}

const NON_CREDENTIAL_FIELD_WORDS = new Set([
  "page",
  "next",
  "cursor",
  "continuation",
  "csrf",
  "xsrf",
  "trace",
  "request",
  "idempotency",
  "sync",
  "nonce",
  "hash",
  "digest",
  "checksum",
  "sha",
  "fingerprint",
  "etag",
  "cache",
  "commit",
  "object",
  "blob",
  "file",
  "content",
  "revision",
  "rev",
  "partition",
  "shard",
  "bucket",
  "dedup",
  "dedupe",
  "lookup",
  "row",
  "sort",
])

function keyPhrase(s: string, at: number): boolean {
  const before = s.slice(Math.max(0, at - 24), at).toLowerCase()
  const idx = before.lastIndexOf("key")
  if (idx < 0) return false
  const head = trimRightChars(before.slice(0, idx), " ")
  for (const w of ["api", "access", "secret", "private", "signing", "license", "licence"]) {
    if (head.endsWith(w) && (head.length === w.length || !isWordByte(head[head.length - w.length - 1]))) {
      return true
    }
  }
  return false
}

function credentialField(s: string, at: number): boolean {
  const words = fieldWordsAt(s, at)
  if (words.length === 1 && words[0] === "key" && keyPhrase(s, at)) return true
  if ((words.length < 2 && (words.length === 0 || words[0] === "key")) || isElementField(words)) return false
  const last = words[words.length - 1]!
  if (last === "id" || last === "ids" || last === "uuid" || last === "guid") return false
  return !words.some((w) => NON_CREDENTIAL_FIELD_WORDS.has(w))
}

function idAround(s: string, a: number, b: number): readonly [number, number, boolean] {
  if (elementToken(s, a, b)) return [a, b, true]
  let l = a
  let r = b
  while (l > 0 && isHexOrHyphen(s[l - 1])) l--
  while (r < s.length && isHexOrHyphen(s[r])) r++
  while (l < r && s[l] === "-") l++
  while (r > l && s[r - 1] === "-") r--
  if (a < l || b > r) return [0, 0, false]
  const seg = s.slice(l, r)
  for (let i = 0; i < seg.length; i++) {
    if (!isHexOrHyphen(seg[i])) return [0, 0, false]
  }
  if (!idShaped(seg)) return [0, 0, false]
  if (digestShaped(seg) && ((l > 0 && isWordByte(s[l - 1])) || (r < s.length && isWordByte(s[r])))) {
    return [0, 0, false]
  }
  return [l, r, true]
}

/** 排除 UUID、commit hash、短摘要与计算机操作 element_token 的误命中（用户词表与用户规则除外） */
export function filterNoIDs(s: string, found: Span[]): Span[] {
  return found.filter((f) => {
    if (f.by === "word" || f.by === "yours") return true
    const [l, r, ok] = idAround(s, f.start, f.end)
    if (!ok) return true
    if (f.start > l || f.end < r) return false
    if (f.by === "known") {
      return !elementToken(s, l, r)
    }
    if (f.by === "rule") {
      if (
        f.kind === "PASSWORD" ||
        f.kind === "API_KEY" ||
        f.kind === "TOKEN" ||
        f.kind === "PRIVATE_KEY" ||
        f.kind === "WALLET_KEY"
      ) {
        return true
      }
      if (f.kind === "SECRET") {
        if (digestShaped(s.slice(l, r)) && fieldWordsAt(s, l).length === 0) return true
        return credentialField(s, l)
      }
    }
    return false
  })
}

function inDecimal(s: string, a: number, b: number): boolean {
  const isD = (idx: number) => idx >= 0 && idx < s.length && isAsciiDigit(s[idx])
  return (
    (isD(a) && a >= 2 && s[a - 1] === "." && isD(a - 2)) ||
    (isD(b - 1) && b + 1 < s.length && s[b] === "." && isD(b + 1))
  )
}

function jsonNumber(s: string, a: number, b: number): boolean {
  if (a >= b || !hasOnlyChars(s.slice(a, b), DIGITS)) return false
  let k = b
  while (k < s.length && isSpaceChar(s[k])) k++
  if (k < s.length && !",}]".includes(s[k]!)) return false
  let i = a - 1
  while (i >= 0 && isSpaceChar(s[i])) i--
  if (i < 0) return false
  if (s[i] === ":") {
    i--
    while (i >= 0 && isSpaceChar(s[i])) i--
    return i >= 0 && s[i] === '"'
  }
  if (s[i] === "[" || s[i] === ",") {
    for (; i >= 0; i--) {
      if (s[i] === "[") return true
      if (!"0123456789,.-+eE".includes(s[i]!) && !isSpaceChar(s[i])) return false
    }
  }
  return false
}

/** 排除小数片段和 JSON 裸数字时间戳误命中个人信息规则 */
export function filterNoNumbers(s: string, found: Span[], personalKinds: ReadonlySet<string>): Span[] {
  return found.filter((f) => {
    if (!personalKinds.has(f.kind) || f.by === "word" || f.by === "yours") return true
    return !inDecimal(s, f.start, f.end) && !jsonNumber(s, f.start, f.end)
  })
}

/** 已知值回溯时的独立边界校验（known.go standsAlone） */
export function standsAlone(kind: string, s: string, a: number, b: number): boolean {
  const before = a > 0 ? s[a - 1] : undefined
  const after = b < s.length ? s[b] : undefined
  const inSet = (ch: string | undefined, set: string) => ch !== undefined && set.includes(ch)
  switch (kind) {
    case "PHONE":
    case "BANK_CARD":
    case "ID_CARD":
    case "IBAN":
    case "SSN":
    case "PASSPORT":
    case "SERIAL":
      return !inSet(before, ALNUM) && !inSet(after, ALNUM)
    case "IP":
    case "MAC":
      if (inSet(before, `${ALNUM}.:`) || inSet(after, `${ALNUM}:`)) return false
      return after !== "." || b + 1 >= s.length || !isAsciiDigit(s[b + 1])
    case "USERNAME":
      return nameAlone(s, a, b)
    case "EMAIL":
      if (inSet(before, `${ALNUM}._%+-`) || inSet(after, `${ALNUM}_%+`)) return false
      return !inSet(after, ".-") || b + 1 >= s.length || !inSet(s[b + 1], ALNUM)
    default:
      return !(inSet(before, ALNUM) && inSet(s[a], ALNUM)) && !(inSet(after, ALNUM) && inSet(s[b - 1], ALNUM))
  }
}

// ---- 工具参数字段名识别密钥（scrub.go SecretName / Hint）----

const SECRET_NAME_RE =
  /password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|priv[_-]?key|credential|authori[sz]ation|cookie|^key$|^pass$|_pass$/i

export function isSecretFieldName(name: string): boolean {
  const n = name.toLowerCase()
  return SECRET_NAME_RE.test(n) && !n.endsWith("tokens") && !n.endsWith("token_count")
}

/** 生成不泄露完整原文的脱敏提示（仅首字符或密钥前缀 + 字符长度） */
export function makeHint(kind: string, v: string, personalKinds: ReadonlySet<string>): { head: string; len: number } {
  const runes = Array.from(v)
  const len = runes.length
  if (len < 2) return { head: "", len }
  let k = 1
  if (!personalKinds.has(kind) && kind !== "TERM" && len >= 16) {
    k = 0
    for (const ch of runes) {
      if (k >= 4 || !/[a-zA-Z_-]/.test(ch)) break
      k++
      if (ch === "-" || ch === "_") break
    }
    k = Math.max(k, 1)
  }
  return { head: runes.slice(0, k).join(""), len }
}
