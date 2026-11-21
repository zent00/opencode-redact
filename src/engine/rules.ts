// 全量内置脱敏规则集（Secrets + Personal + 细分分类 + Crypto）与自定义规则编译。
import { escapeRegExp, normalizeRuleKind } from "../config.js"
import { CRYPTO_RULES } from "./crypto.js"
import {
  ALNUM,
  CAT_PERSONAL,
  type CompiledRule,
  type CustomRule,
  DIGITS,
  MAX_REGEX,
  MIN_CUSTOM_LEN,
  PREFIX_TAIL,
  TOKEN_CH,
} from "./types.js"
import {
  birthdayDateOK,
  bucketOK,
  chineseID,
  emailAt,
  fieldAt,
  headerValue,
  hiddenInURL,
  homeAt,
  hostOK,
  ibanAt,
  ipv4At,
  ipv6OK,
  keyAt,
  lineHostOK,
  lineUserOK,
  luhn,
  macOK,
  namedSecretAt,
  notASlug,
  notAVariable,
  notLineIdent,
  notPackagePin,
  passportOK,
  phoneAt,
  realEmail,
  secretValue,
  serialOK,
  ssnOK,
  unixUserOK,
} from "./validators.js"

const SECRET_FIELDS: ReadonlyArray<readonly [string, string]> = [
  ["password", "pass"],
  ["passwd", "pass"],
  ["passphrase", "pass"],
  ["secret", "secret"],
  ["token", "token"],
  ["api[_-]?key", "key"],
  ["access[_-]?key", "key"],
  ["private[_-]?key", "key"],
  ["priv[_-]?key", "key"],
  ["credential", "credential"],
]

const SECRET_NAMES_PATTERN = SECRET_FIELDS.map(([re]) => re).join("|")

function caseVariants(markers: readonly string[]): string[] {
  const out: string[] = []
  for (const m of markers) {
    for (const v of [m, m.toUpperCase(), m[0]!.toUpperCase() + m.slice(1)]) {
      if (!out.includes(v)) out.push(v)
    }
  }
  return out
}

const SECRET_NAME_MARKERS = caseVariants(SECRET_FIELDS.map(([, marker]) => marker))
const KEY_PASS_MARKERS = caseVariants(["key", "pass"])
const AUTH_COOKIE_MARKERS = caseVariants(["authorization", "cookie"])
const KEY_MARKERS = caseVariants(["key"])

const QUOTE = `(?:\\\\?["'])?`
const SECRET_CH = `[A-Za-z0-9_\\-./+=~!@#%^&*]`

const CJK_PASSWORD_NAMES = [
  "密码",
  "密碼",
  "口令",
  "PIN码",
  "PIN碼",
  "PIN 码",
  "安全码",
  "安全碼",
  "パスワード",
  "暗証番号",
  "비밀번호",
  "암호",
  "비번",
]

const CJK_KEY_NAMES = [
  "密钥",
  "密鑰",
  "秘钥",
  "秘鑰",
  "私钥",
  "私鑰",
  "金钥",
  "金鑰",
  "令牌",
  "权杖",
  "權杖",
  "授权码",
  "授權碼",
  "秘密鍵",
  "トークン",
  "シークレット",
  "APIキー",
  "アクセスキー",
  "토큰",
  "비밀키",
  "API 키",
  "API키",
]

const CJK_COPULAS = ["为", "為", "是", "："]

function cjkNamedRegex(names: readonly string[]): RegExp {
  return new RegExp(
    `(?:${names.join("|")})[ \\t]*(?:[:：=][ \\t]*|[为為是][ \\t]*[:：]?[ \\t]*|は[ \\t]*|는[ \\t]*)?(?:\\\\?["'“「])?(${SECRET_CH}{3,63}[A-Za-z0-9_\\-/+=~!@#%^&*])`,
    "gid",
  )
}

const SEP = `["']?[ \\t]*(?:[:#=：][ \\t]*)?`
const MONTHS = `(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\\.?`
const PATH_NAME = "[^\\s/\\\\:*?\"'<>|,;()\\[\\]{}`$%]{1,64}"
const HOST_RE = `[A-Za-z0-9][A-Za-z0-9-]{0,62}(?:\\.[A-Za-z0-9-]{1,63})*`
const UNIX_USER = `[a-z_][a-z0-9_.-]{0,31}`
const LINE_USER = `[A-Za-z0-9_][A-Za-z0-9._-]{0,31}`
const BUCKET_RE = `[A-Za-z0-9](?:[A-Za-z0-9._-]{0,61}[A-Za-z0-9])?`

const BUCKET_HOSTS = [
  "amazonaws.com",
  "googleapis.com",
  "cloud.google.com",
  "aliyuncs.com",
  "myqcloud.com",
  "windows.net",
  "cloudflarestorage.com",
  "digitaloceanspaces.com",
  "myhuaweicloud.com",
  "volces.com",
]

/** 构建核心内置规则表（接受 now 供 birthday 判定，支持测试固定时间） */
export function buildBuiltinRules(now: () => Date = () => new Date()): readonly CompiledRule[] {
  const coreSecretsAndPersonal: CompiledRule[] = [
    // ---- Secrets ----
    {
      kind: "PRIVATE_KEY",
      re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]+?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/dg,
      markers: ["PRIVATE KEY"],
    },
    {
      kind: "API_KEY",
      re: /sk-(?:ant-|proj-|or-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/dg,
      markers: ["sk-"],
      bound: TOKEN_CH,
      ok: notASlug,
    },
    {
      kind: "API_KEY",
      re: /[a-z]{2,4}_sk_[A-Za-z0-9_-]{20,}/dg,
      markers: ["_sk_"],
      bound: TOKEN_CH,
      ok: secretValue,
    },
    {
      kind: "API_KEY",
      re: /ark-[A-Za-z0-9][A-Za-z0-9_-]{15,}/dg,
      markers: ["ark-"],
      bound: TOKEN_CH,
      ok: secretValue,
    },
    {
      kind: "API_KEY",
      re: /(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20,})/dg,
      markers: ["gh", "github_pat_", "glpat-"],
      bound: TOKEN_CH,
    },
    {
      kind: "API_KEY",
      re: /AIza[0-9A-Za-z_-]{35}/dg,
      markers: ["AIza"],
      bound: TOKEN_CH,
    },
    {
      kind: "API_KEY",
      re: /xox[abposr]-[0-9A-Za-z-]{10,}/dg,
      markers: ["xox"],
      bound: TOKEN_CH,
    },
    {
      kind: "API_KEY",
      re: /(?:sk|rk)_live_[0-9A-Za-z]{20,}/dg,
      markers: ["_live_"],
      bound: TOKEN_CH,
    },
    {
      kind: "API_KEY",
      re: /(?:AKIA|ASIA)[0-9A-Z]{16}/dg,
      markers: ["AKIA", "ASIA"],
      bound: ALNUM,
    },
    {
      kind: "API_KEY",
      re: /(?:hf_[A-Za-z0-9]{30,}|gsk_[A-Za-z0-9]{40,}|xai-[A-Za-z0-9]{40,}|npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,}|dop_v1_[a-f0-9]{64}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})/dg,
      markers: ["hf_", "gsk_", "xai-", "npm_", "pypi-", "dop_v1_", "SG."],
      bound: TOKEN_CH,
    },
    {
      kind: "API_KEY",
      re: /cf(?:ut|at|k|oat)_[A-Za-z0-9_-]{40,}/dg,
      markers: ["cfut_", "cfat_", "cfk_", "cfoat_"],
      bound: TOKEN_CH,
    },
    {
      kind: "API_KEY",
      re: /v1\.0-[A-Za-z0-9]{16,}-[A-Za-z0-9]{40,}/dg,
      markers: ["v1.0-"],
      bound: TOKEN_CH,
    },
    {
      kind: "TOKEN",
      re: /eyJhIjoi[A-Za-z0-9+/_-]{40,}={0,2}/dg,
      markers: ["eyJhIjoi"],
      bound: TOKEN_CH,
    },
    {
      kind: "SECRET",
      re: /x-auth-(?:user-service-)?key["']?[ \t]*[:=][ \t]*["']?([A-Za-z0-9._-]{16,})/dgi,
      fold: ["x-auth-"],
      ahead: 120,
      ok: notAVariable,
    },
    {
      kind: "TOKEN",
      re: /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/dg,
      markers: ["eyJ"],
      bound: TOKEN_CH,
    },
    {
      kind: "PASSWORD",
      re: /[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s:@/?#"'<>]*:([^\s@/?#"'<>]{3,})@/dg,
      markers: ["://"],
      ok: notAVariable,
      at: hiddenInURL,
    },
    {
      kind: "SECRET",
      re: new RegExp(
        `[A-Za-z0-9_.-]*(?:${SECRET_NAMES_PATTERN})[A-Za-z0-9_.-]*${QUOTE}[ \\t]*[:=][ \\t]*${QUOTE}(${SECRET_CH}{8,})`,
        "gid",
      ),
      markers: SECRET_NAME_MARKERS,
      ok: secretValue,
      at: fieldAt,
      field: true,
    },
    {
      kind: "SECRET",
      re: new RegExp(
        `(?:^|[^A-Za-z0-9_.-])[A-Za-z0-9_.-]*_(?:KEY|PASS)${QUOTE}[ \\t]*[:=][ \\t]*${QUOTE}(${SECRET_CH}{8,})`,
        "gd",
      ),
      markers: KEY_PASS_MARKERS,
      ok: secretValue,
      at: namedSecretAt,
      field: true,
    },
    {
      kind: "SECRET",
      re: /^[ \t]*(?:authorization|cookie)[ \t]*:[ \t]*(\S[^\r\n]{7,})/dgim,
      markers: AUTH_COOKIE_MARKERS,
      ok: headerValue,
    },
    {
      kind: "SECRET",
      re: new RegExp(`(?:^|[^A-Za-z0-9_.-])${QUOTE}key${QUOTE}[ \\t]*[:=][ \\t]*${QUOTE}(${SECRET_CH}{16,})`, "gid"),
      markers: KEY_MARKERS,
      ok: secretValue,
      at: fieldAt,
      field: true,
    },
    {
      kind: "PASSWORD",
      re: cjkNamedRegex(CJK_PASSWORD_NAMES),
      fold: CJK_PASSWORD_NAMES.map((x) => x.toLowerCase()),
      back: 64,
      ahead: 100,
      ok: notAVariable,
      field: true,
    },
    {
      kind: "SECRET",
      re: cjkNamedRegex(CJK_KEY_NAMES),
      fold: CJK_KEY_NAMES.map((x) => x.toLowerCase()),
      back: 64,
      ahead: 100,
      at: keyAt,
      field: true,
    },
    {
      kind: "SECRET",
      re: new RegExp(
        `(?:${SECRET_NAMES_PATTERN}|pwd|api[ ]key|access[ ]key|secret[ ]key|key|\\bpin(?:[ ]?code)?)${QUOTE}[ \\t]*(?:[为為是][ \\t]*[:：]?|：)[ \\t]*(?:\\\\?["'“「])?(${SECRET_CH}{3,}[A-Za-z0-9_\\-/+=~!@#%^&*])`,
        "gid",
      ),
      fold: CJK_COPULAS,
      back: 24,
      ahead: 260,
      at: keyAt,
      field: true,
    },

    // ---- Personal 核心 ----
    {
      kind: "EMAIL",
      re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/dg,
      markers: ["@"],
      bound: `${ALNUM}_%+-`,
      ok: realEmail,
      at: emailAt,
      cat: CAT_PERSONAL,
    },
    {
      kind: "ID_CARD",
      re: /[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]/dg,
      bound: ALNUM,
      ok: chineseID,
      cat: CAT_PERSONAL,
    },
    {
      kind: "PHONE",
      re: /(?:\+?86[- ]?)?1[3-9]\d{9}/dg,
      bound: ALNUM,
      at: phoneAt,
      cat: CAT_PERSONAL,
    },
    {
      kind: "BANK_CARD",
      re: /[3-6]\d{3}(?:[ -]?\d{4}){2,3}(?:[ -]?\d{1,3})?/dg,
      bound: ALNUM,
      ok: luhn,
      cat: CAT_PERSONAL,
    },

    // ---- Personal 可选分类 ----
    {
      kind: "SSN",
      cat: "ssn",
      re: /\d{3}-\d{2}-\d{4}/dg,
      markers: ["-"],
      bound: `${ALNUM}-`,
      ok: ssnOK,
    },
    {
      kind: "SSN",
      cat: "ssn",
      re: new RegExp(
        `(?:\\bssn|\\bsocial[ \\t]+security(?:[ \\t]+(?:number|no\\.?|#))?)${SEP}(?:is[ \\t]+)?["']?(\\d{9}|\\d{3} \\d{2} \\d{4})`,
        "gid",
      ),
      fold: ["ssn", "social"],
      back: 8,
      ahead: 80,
      bound: DIGITS,
      ok: ssnOK,
    },
    {
      kind: "PASSPORT",
      cat: "passport",
      anyGroup: true,
      bound: ALNUM,
      ok: passportOK,
      re: new RegExp(
        `(?:\\bpassport(?:[ \\t]*(?:no\\.?|number|num|#))?|\\breisepass(?:nummer)?)${SEP}(?:(?:is|was)[ \\t]+)?["']?([A-Za-z0-9]{6,9})` +
          `|(?:护照(?:号码|号)?|護照(?:號碼|号码|番号)?|パスポート(?:番号)?)[ \\t]*(?:[:：=][ \\t]*)?(?:是[ \\t]*|は[ \\t]*)?["']?([A-Za-z0-9]{6,9})`,
        "gid",
      ),
      fold: ["passport", "reisepass", "护照", "護照", "パスポート"],
      back: 8,
      ahead: 80,
    },
    {
      kind: "IBAN",
      cat: "iban",
      re: /[A-Z]{2}\d{2}(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,3})?)/dg,
      bound: ALNUM,
      fix: ibanAt,
    },
    {
      kind: "BIRTHDAY",
      cat: "birthday",
      bound: DIGITS,
      ok: (v) => birthdayDateOK(v, now),
      re: new RegExp(
        `(?:\\bdate[ \\t]+of[ \\t]+birth|\\bbirth[ \\t_-]?date|\\bbirthday|\\bdob\\b|\\bd\\.o\\.b\\.?|\\bborn(?:[ \\t]+on)?|\\bgeburtsdatum|\\bgeboren(?:[ \\t]+am)?|生日|出生日期|出生年月日|出生于|出生於|出生|誕生日|生年月日)` +
          `${SEP}(?:(?:is|was)[ \\t]+|是[ \\t]*|为[ \\t]*|為[ \\t]*|は[ \\t]*)?["']?` +
          `(\\d{4}[-/.]\\d{1,2}[-/.]\\d{1,2}|\\d{4}[ \\t]*年[ \\t]*\\d{1,2}[ \\t]*月[ \\t]*\\d{1,2}[ \\t]*日?|\\d{1,2}[-/.]\\d{1,2}[-/.]\\d{4}` +
          `|${MONTHS}[ \\t]+\\d{1,2}(?:st|nd|rd|th)?,?[ \\t]+\\d{4}|\\d{1,2}(?:st|nd|rd|th)?[ \\t]+${MONTHS},?[ \\t]+\\d{4})`,
        "gid",
      ),
      fold: ["birth", "dob", "d.o.b", "born", "geburt", "geboren", "生日", "出生", "誕生日", "生年月日"],
      back: 16,
      ahead: 80,
    },
    {
      kind: "MAC",
      cat: "mac",
      re: /[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}|[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}/dg,
      bound: `${ALNUM}:-`,
      ok: macOK,
    },
    {
      kind: "SERIAL",
      cat: "serial",
      anyGroup: true,
      bound: `${ALNUM}-`,
      ok: serialOK,
      re: /(?:(?:\bserial[ \t_-]?(?:number|num|no\.?|#)?|\bs\/n|\bsn)(?:[ \t]*\([^)\n]{1,20}\))?["']?[ \t]*[:#=：][ \t]*["']?([A-Za-z0-9][A-Za-z0-9-]{4,39})|(?:序列号|序列號|シリアル番号|seriennummer)[ \t]*[:：=]?[ \t]*["']?([A-Za-z0-9][A-Za-z0-9-]{4,39}))/dgi,
      fold: ["serial", "s/n", "sn", "序列", "シリアル", "seriennummer"],
      back: 8,
      ahead: 80,
    },
    {
      kind: "USERNAME",
      cat: "home",
      fix: homeAt,
      re: new RegExp(`(?:^|[^A-Za-z0-9_.~/\\\\-])(?:file://)?(?:/mnt/[a-z])?/(?:Users|home)/(${PATH_NAME})`, "gd"),
      fold: ["/users/", "/home/"],
      back: 16,
      ahead: 80,
    },
    {
      kind: "USERNAME",
      cat: "home",
      anyGroup: true,
      fix: homeAt,
      re: new RegExp(
        `(?:^|[^A-Za-z0-9])[A-Za-z]:(?:\\\\{1,4}|/)(?:users|documents and settings)(?:\\\\{1,4}|/)` +
          `(?:([A-Za-z0-9._-]+(?: [A-Za-z0-9._-]+)+)(?:\\\\|/)|(${PATH_NAME}))`,
        "gid",
      ),
      fold: ["users", "documents and settings"],
      back: 12,
      ahead: 100,
    },
    {
      kind: "",
      cat: "userhost",
      groups: ["USERNAME", "HOSTNAME"],
      groupOK: [unixUserOK, hostOK],
      markers: ["@"],
      at: notPackagePin,
      re: new RegExp(
        `(?:^|[^A-Za-z0-9._%+-])(${UNIX_USER})@(${HOST_RE})(?::[~/]|:[ \\t]*$|[ \\t]+[~/]|[ \\t]*[$%#>][ \\t]|[ \\t]*[$%#>]$)`,
        "gmd",
      ),
    },
    {
      kind: "",
      cat: "userhost",
      groups: ["USERNAME", "HOSTNAME"],
      groupOK: [unixUserOK, hostOK],
      markers: ["@"],
      at: notPackagePin,
      re: new RegExp(
        `\\b(?:ssh|scp|sftp|rsync|mosh|ssh-copy-id)\\b[^\\n@]{0,80}?[ \\t"'](${UNIX_USER})@(${HOST_RE})`,
        "gid",
      ),
    },
    {
      kind: "HOSTNAME",
      cat: "userhost",
      anyGroup: true,
      ok: lineHostOK,
      re: new RegExp(
        `^[ \\t]*["']?(?:host[ \\t_-]?name|computer[ \\t_-]?name|machine[ \\t_-]?name|device[ \\t_-]?name|主机名|主機名|計算機名|コンピュータ名|コンピューター名)["']?` +
          `[ \\t]*[:=：][ \\t]*(?:["'](${HOST_RE})["'][ \\t]*[,;]?|(${HOST_RE}))[ \\t]*$`,
        "gimd",
      ),
      fold: ["name", "主机", "主機", "計算機", "コンピュータ"],
    },
    {
      kind: "HOSTNAME",
      cat: "userhost",
      ok: lineHostOK,
      re: new RegExp(`^[ \\t]+HostName[ \\t]+(${HOST_RE})[ \\t]*$`, "gmd"),
      markers: ["HostName"],
    },
    {
      kind: "USERNAME",
      cat: "userhost",
      anyGroup: true,
      ok: lineUserOK,
      at: notLineIdent,
      re: new RegExp(
        `^[ \\t]*["']?(?:user[ \\t_-]?name|login[ \\t_-]?name|user|login|logname|用户名|用戶名|ユーザー名)["']?` +
          `[ \\t]*[:=：][ \\t]*(?:["'](${LINE_USER})["'][ \\t]*[,;]?|(${LINE_USER}))[ \\t]*$`,
        "gimd",
      ),
      fold: ["user", "login", "logname", "用户", "用戶", "ユーザー"],
    },
    {
      kind: "USERNAME",
      cat: "userhost",
      ok: lineUserOK,
      at: notLineIdent,
      re: new RegExp(`^[ \\t]+User[ \\t]+(${LINE_USER})[ \\t]*$`, "gmd"),
      markers: ["User"],
    },
    {
      kind: "IP",
      cat: "ip",
      markers: ["."],
      at: ipv4At,
      re: /(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}/dg,
    },
    {
      kind: "IP",
      cat: "ip",
      markers: [":"],
      bound: `${ALNUM}:_`,
      ok: ipv6OK,
      re: /[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7}/dg,
    },
    {
      kind: "",
      cat: "bucket",
      groups: ["BUCKET", "BUCKET"],
      groupOK: [bucketOK, bucketOK],
      markers: ["://"],
      re: new RegExp(
        `\\b(?:s3a?|s3n|gs|oss|cosn?|obs|r2|ks3|bos|tos|az|azure|wasbs?|abfss?)://(${BUCKET_RE})(?:@([a-z0-9]{3,24})\\.(?:blob|dfs)\\.core\\.windows\\.net)?`,
        "gid",
      ),
    },
    {
      kind: "BUCKET",
      cat: "bucket",
      ok: bucketOK,
      fold: BUCKET_HOSTS,
      back: 128,
      ahead: 32,
      re: /(?:^|[^A-Za-z0-9.-])([a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?)\.(?:s3(?:[.-](?:dualstack\.)?[a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?|s3-accelerate\.amazonaws\.com|storage\.googleapis\.com|oss-[a-z0-9-]+\.aliyuncs\.com|cos\.[a-z0-9-]+\.myqcloud\.com|obs\.[a-z0-9-]+\.myhuaweicloud\.com|r2\.cloudflarestorage\.com|(?:blob|dfs)\.core\.windows\.net|[a-z0-9-]+\.digitaloceanspaces\.com|tos-[a-z0-9-]+\.volces\.com)/dg,
    },
    {
      kind: "BUCKET",
      cat: "bucket",
      ok: bucketOK,
      fold: BUCKET_HOSTS,
      back: 48,
      ahead: 80,
      re: new RegExp(
        `(?:^|[^A-Za-z0-9.-])(?:s3(?:[.-](?:dualstack\\.)?[a-z0-9-]+)?\\.amazonaws\\.com(?:\\.cn)?|storage\\.googleapis\\.com|storage\\.cloud\\.google\\.com` +
          `|[a-z0-9]{3,24}\\.blob\\.core\\.windows\\.net|oss-[a-z0-9-]+\\.aliyuncs\\.com|[a-z0-9-]+\\.digitaloceanspaces\\.com)/(${BUCKET_RE})`,
        "gd",
      ),
    },
  ]

  return [...coreSecretsAndPersonal, ...CRYPTO_RULES]
}

/** Personal 占位符类型 -> 所属分类列表（用于判断 knownSpans 是否受当前配置覆盖） */
export const KIND_TO_CATS: ReadonlyMap<string, readonly string[]> = (() => {
  const m = new Map<string, string[]>()
  for (const r of buildBuiltinRules()) {
    if (!r.cat) continue
    const ks = r.groups && r.groups.length > 0 ? r.groups : [r.kind]
    for (const k of ks) {
      if (!k) continue
      const list = m.get(k) ?? []
      if (!list.includes(r.cat)) list.push(r.cat)
      m.set(k, list)
    }
  }
  return m
})()

export const PERSONAL_KINDS: ReadonlySet<string> = new Set(KIND_TO_CATS.keys())

/** 编译用户自定义规则（在实例内缓存已编译正则） */
export class CustomRuleCompiler {
  private readonly cache = new Map<string, CompiledRule | null>()

  compile(input: readonly CustomRule[]): CompiledRule[] {
    const out: CompiledRule[] = []
    for (const r of input) {
      const prefix = r.prefix?.trim() ?? ""
      const regex = r.regex?.trim() ?? ""
      if ((!prefix && !regex) || regex.length > MAX_REGEX) continue
      const key = `${r.kind}\0${prefix}\0${regex}`
      let compiled = this.cache.get(key)
      if (compiled === undefined) {
        compiled = this.buildOne(r.kind, prefix, regex)
        this.cache.set(key, compiled)
      }
      if (compiled) out.push(compiled)
    }
    return out
  }

  private buildOne(rawKind: string, prefix: string, regex: string): CompiledRule | null {
    try {
      const source = prefix ? `${escapeRegExp(prefix)}${PREFIX_TAIL}` : regex
      const testRe = new RegExp(source)
      if (testRe.test("")) return null
      const re = new RegExp(source, "gd")
      return {
        kind: normalizeRuleKind(rawKind),
        yours: true,
        re,
        markers: prefix ? [prefix] : undefined,
        ok: (v) => v.length >= MIN_CUSTOM_LEN,
      }
    } catch {
      return null
    }
  }
}
