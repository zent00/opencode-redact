// 脱敏引擎核心类型与分类常量，借鉴 Magpie internal/redact 设计。

export type CategoryId =
  | "ssn"
  | "passport"
  | "iban"
  | "birthday"
  | "mac"
  | "serial"
  | "home"
  | "userhost"
  | "ip"
  | "bucket"

export interface CategoryDef {
  readonly id: CategoryId
  readonly kinds: readonly string[]
  /** 未显式配置时默认是否开启 */
  readonly defaultOn: boolean
}

/** Personal 脱敏下的细分开关分类，默认值与 Magpie 保持一致 */
export const CATEGORIES: readonly CategoryDef[] = [
  { id: "ssn", kinds: ["SSN"], defaultOn: true },
  { id: "passport", kinds: ["PASSPORT"], defaultOn: true },
  { id: "iban", kinds: ["IBAN"], defaultOn: true },
  { id: "birthday", kinds: ["BIRTHDAY"], defaultOn: true },
  { id: "mac", kinds: ["MAC"], defaultOn: true },
  { id: "serial", kinds: ["SERIAL"], defaultOn: true },
  { id: "home", kinds: ["USERNAME"], defaultOn: false },
  { id: "userhost", kinds: ["USERNAME", "HOSTNAME"], defaultOn: false },
  { id: "ip", kinds: ["IP"], defaultOn: false },
  { id: "bucket", kinds: ["BUCKET"], defaultOn: false },
]

export const CATEGORY_DEFAULT_ON: Readonly<Record<string, boolean>> = Object.fromEntries(
  CATEGORIES.map((c) => [c.id, c.defaultOn]),
)

export const CAT_PERSONAL = "personal"

export type Action = "mask" | "warn" | "block"
export type NonDefaultAction = "warn" | "block"
export type Finder = "rule" | "yours" | "word" | "known"

export interface CustomRule {
  readonly kind: string
  readonly prefix?: string
  readonly regex?: string
}

export interface Span {
  start: number
  end: number
  kind: string
  by: Finder
  /** JSON 裸值（例如未加引号的数字密码）替换占位符时需要加双引号 */
  bare?: boolean
}

export interface Hit {
  readonly kind: string
  readonly by: Finder
  readonly placeholder: string
  /** "" 表示正常脱敏，"warn" 表示放行仅告警，"block" 表示拦截请求 */
  readonly action: "" | NonDefaultAction
  /** 仅保留首字符或密钥前缀，绝不包含完整原文 */
  readonly head: string
  readonly len: number
}

export interface MaskOptions {
  readonly secrets: boolean
  readonly personal: boolean
  readonly kinds: Readonly<Record<string, boolean>>
  readonly words: readonly string[]
  readonly wordsAnyCase: boolean
  readonly wordsWhole: boolean
  readonly rules: readonly CustomRule[]
  readonly actions: Readonly<Record<string, NonDefaultAction>>
  readonly allow: readonly string[]
  readonly shape: boolean
  /** 目标路由标识（如 providerID），用于按路由保持 Prompt Cache 前缀稳定 */
  readonly route?: string
  /** 每次命中敏感值时的回调（仅传递元信息与 Hint，绝不含原文） */
  readonly onHit?: (hit: Hit) => void
  /** 内部标记：是否发往真实上游（开启 sentSpans 与 allowKept 前缀记忆） */
  readonly sent?: boolean
  /** 内部标记：当前时间供给，便于单元测试控制 birthday 判定 */
  readonly now?: () => Date
}

export interface MaskResult {
  readonly text: string
  readonly count: number
  readonly hits: Hit[]
  readonly blocked: Hit | undefined
}

export interface CompiledRule {
  readonly kind: string
  readonly re: RegExp
  /** 区分大小写的快速子串预筛标记 */
  readonly markers?: readonly string[]
  /** 忽略大小写（转小写后）的快速子串预筛标记 */
  readonly fold?: readonly string[]
  /** 匹配两端禁止紧邻的 ASCII 字符集合 */
  readonly bound?: string
  readonly ok?: (value: string) => boolean
  readonly at?: (s: string, a: number, b: number) => boolean
  readonly fix?: (s: string, a: number, b: number) => readonly [number, number, boolean]
  /** 配合 fold 做局部窗口扫描，避免大文本全量正则开销 */
  readonly back?: number
  readonly ahead?: number
  /** "" 表示 secrets，"personal" 表示基础个人信息，其余为 CategoryId */
  readonly cat?: string
  /** 是否属于 key=value / key: value 字段赋值类规则（启用 nextField 防止误吃下一个字段） */
  readonly field?: boolean
  readonly yours?: boolean
  readonly anyGroup?: boolean
  readonly groups?: readonly string[]
  readonly groupOK?: ReadonlyArray<(value: string) => boolean>
  /** 无固定标记时的低成本快速预检函数（如 base58 / base32 连续长度扫描） */
  readonly may?: (s: string) => boolean
}

export const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
export const TOKEN_CH = `${ALNUM}_-`
export const DIGITS = "0123456789"

export const MAX_RULES = 32
export const MAX_KIND = 24
export const MAX_PREFIX = 64
export const MIN_PREFIX = 3
export const MAX_REGEX = 300
export const MIN_CUSTOM_LEN = 4
export const CUSTOM_KIND = "CUSTOM"
export const PREFIX_TAIL = "[A-Za-z0-9_\\-]{8,}"
export const MAX_PLACEHOLDER_LEN = 2 + MAX_KIND + 1 + 8 + 2
export const MAX_ALLOW = 200
export const MAX_ALLOW_LEN = 256
export const MIN_KNOWN = 8
