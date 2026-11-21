// 插件配置解析与规则校验（对齐 Magpie CheckRules / redactActions / redactAllow）。
import os from "node:os"
import path from "node:path"
import { z } from "zod"
import {
  CATEGORIES,
  CUSTOM_KIND,
  type CustomRule,
  MAX_ALLOW,
  MAX_ALLOW_LEN,
  MAX_KIND,
  MAX_PREFIX,
  MAX_REGEX,
  MAX_RULES,
  type MaskOptions,
  MIN_PREFIX,
  type NonDefaultAction,
  PREFIX_TAIL,
} from "./engine/types.js"

const VALID_CATEGORY_IDS = new Set<string>(CATEGORIES.map((c) => c.id))

/** 将用户指定的规则 Kind 规范化为合法占位符类型名（大写字母/数字/下划线，以字母开头，最长 24） */
export function normalizeRuleKind(kind: string): string {
  const upper = kind.trim().toUpperCase()
  let out = ""
  for (const ch of upper) {
    if ((ch >= "A" && ch <= "Z") || (ch >= "0" && ch <= "9") || ch === "_") {
      out += ch
    } else if (ch === " " || ch === "-" || ch === ".") {
      out += "_"
    }
  }
  let k = out.replace(/^_+|_+$/g, "")
  if (!k) return CUSTOM_KIND
  if (k[0]! < "A" || k[0]! > "Z") {
    k = `${CUSTOM_KIND}_${k}`
  }
  if (k.length > MAX_KIND) {
    k = k.slice(0, MAX_KIND).replace(/_+$/g, "")
  }
  return k || CUSTOM_KIND
}

/** 检查 k 是否为规范的占位符 Kind 名称 */
export function isValidKindName(k: string): boolean {
  return k !== "" && normalizeRuleKind(k) === k
}

export function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

/** 校验并整理用户自定义规则 */
export function checkRules(input: readonly CustomRule[]): CustomRule[] {
  const out: CustomRule[] = []
  const seen = new Set<string>()
  for (const raw of input) {
    const prefix = raw.prefix?.trim() ?? ""
    const regex = raw.regex?.trim() ?? ""
    if (!prefix && !regex) continue
    const kind = normalizeRuleKind(raw.kind)
    if (prefix && regex) {
      throw new Error(`自定义规则 ${kind} 不能同时指定 prefix 和 regex`)
    }
    if (prefix && (prefix.length < MIN_PREFIX || prefix.length > MAX_PREFIX)) {
      throw new Error(`自定义规则 ${kind} 的 prefix 长度必须在 ${MIN_PREFIX} 到 ${MAX_PREFIX} 之间`)
    }
    if (regex.length > MAX_REGEX) {
      throw new Error(`自定义规则 ${kind} 的 regex 长度不能超过 ${MAX_REGEX}`)
    }
    let re: RegExp
    try {
      re = prefix ? new RegExp(`${escapeRegExp(prefix)}${PREFIX_TAIL}`) : new RegExp(regex)
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error)
      throw new Error(`自定义规则 ${kind} 的正则表达式无效：${msg}`)
    }
    if (re.test("")) {
      throw new Error(`自定义规则 ${kind} 可以匹配空字符串，会导致过度脱敏：${regex}`)
    }
    const dedupeKey = `${kind}\0${prefix}\0${regex}`
    if (!seen.has(dedupeKey)) {
      seen.add(dedupeKey)
      out.push(prefix ? { kind, prefix } : { kind, regex })
    }
  }
  if (out.length > MAX_RULES) {
    throw new Error(`最多允许配置 ${MAX_RULES} 条自定义规则，当前为 ${out.length} 条`)
  }
  return out
}

/** 校验并整理按类型覆盖动作配置 */
export function checkActions(input: Readonly<Record<string, string>>): Record<string, NonDefaultAction> {
  const out: Record<string, NonDefaultAction> = {}
  for (const [rawKind, rawAction] of Object.entries(input)) {
    const kind = rawKind.trim()
    const action = rawAction.trim().toLowerCase()
    if (action === "" || action === "mask") continue
    if (action !== "warn" && action !== "block") {
      throw new Error(`动作配置仅支持 mask、warn 或 block，收到无效值：${rawAction}`)
    }
    if (!isValidKindName(kind)) {
      throw new Error(`actions 中的类型名不合法：${kind}`)
    }
    out[kind] = action
  }
  return out
}

/** 校验并去重白名单列表（忽略大小写去重） */
export function checkAllow(input: readonly string[]): string[] {
  const out: string[] = []
  const seen = new Set<string>()
  for (const raw of input) {
    const v = raw.trim()
    if (!v) continue
    const lower = v.toLowerCase()
    if (seen.has(lower)) continue
    if (v.length > MAX_ALLOW_LEN) {
      throw new Error(`白名单条目长度不能超过 ${MAX_ALLOW_LEN} 字符`)
    }
    seen.add(lower)
    out.push(v)
  }
  if (out.length > MAX_ALLOW) {
    throw new Error(`白名单最多允许 ${MAX_ALLOW} 条，当前为 ${out.length} 条`)
  }
  return out
}

const CustomRuleSchema = z.object({
  kind: z.string().default(CUSTOM_KIND),
  prefix: z.string().optional(),
  regex: z.string().optional(),
})

const AuditOptionsSchema = z
  .object({
    enabled: z.boolean().default(true),
    dir: z.string().optional(),
    keepDays: z.number().int().min(1).max(365).default(30),
    keepBytes: z
      .number()
      .int()
      .min(1024 * 1024)
      .default(100 * 1024 * 1024),
  })
  .strict()

export const RedactOptionsSchema = z
  .object({
    enabled: z.boolean().default(true),
    secrets: z.boolean().default(true),
    personal: z.boolean().default(true),
    kinds: z.record(z.string(), z.boolean()).default({}),
    words: z.array(z.string()).default([]),
    wordsAnyCase: z.boolean().default(false),
    wordsWhole: z.boolean().default(false),
    rules: z.array(CustomRuleSchema).default([]),
    actions: z.record(z.string(), z.string()).default({}),
    allow: z.array(z.string()).default([]),
    shape: z.boolean().default(false),
    skipProviders: z.array(z.string()).default([]),
    includeProviders: z.array(z.string()).default([]),
    failClosed: z.boolean().default(true),
    persistKey: z.boolean().default(false),
    keyPath: z.string().optional(),
    stateDir: z.string().optional(),
    audit: AuditOptionsSchema.optional(),
  })
  .strict()

export type RedactPluginInputOptions = z.input<typeof RedactOptionsSchema>

export interface RedactConfig {
  readonly enabled: boolean
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
  readonly skipProviders: ReadonlySet<string>
  readonly includeProviders: ReadonlySet<string>
  readonly failClosed: boolean
  readonly persistKey: boolean
  readonly keyPath: string | undefined
  readonly stateDir: string
  readonly audit: {
    readonly enabled: boolean
    readonly dir: string
    readonly keepDays: number
    readonly keepBytes: number
  }
}

export function resolveStateDir(
  explicitDir: string | undefined,
  env: NodeJS.ProcessEnv = process.env,
  homeDir: string = os.homedir(),
): string {
  if (explicitDir && explicitDir.trim() !== "") {
    return expandHome(explicitDir.trim(), homeDir)
  }
  const xdgConfig = env.XDG_CONFIG_HOME?.trim()
  const configBase = xdgConfig ? expandHome(xdgConfig, homeDir) : path.join(homeDir, ".config")
  return path.join(configBase, "opencode", "opencode-redact")
}

function expandHome(p: string, homeDir: string): string {
  if (p === "~") return homeDir
  if (p.startsWith("~/")) return path.join(homeDir, p.slice(2))
  return p
}

/** 解析并校验插件配置 */
export function parseConfig(
  rawOptions: unknown = {},
  env: NodeJS.ProcessEnv = process.env,
  homeDir: string = os.homedir(),
): RedactConfig {
  const parsed = RedactOptionsSchema.parse(rawOptions ?? {})
  const kinds: Record<string, boolean> = {}
  for (const [k, v] of Object.entries(parsed.kinds)) {
    const id = k.trim().toLowerCase()
    if (!VALID_CATEGORY_IDS.has(id)) {
      throw new Error(`未知的 personal 分类开关：${k}`)
    }
    kinds[id] = v
  }
  const rules = checkRules(parsed.rules)
  const actions = checkActions(parsed.actions)
  const allow = checkAllow(parsed.allow)
  const words = parsed.words.map((w) => w.trim()).filter((w) => w.length >= 2)
  const stateDir = resolveStateDir(parsed.stateDir, env, homeDir)
  const keyPath = parsed.keyPath
    ? expandHome(parsed.keyPath.trim(), homeDir)
    : parsed.persistKey
      ? path.join(stateDir, "redact.key")
      : undefined
  const auditRaw = parsed.audit ?? AuditOptionsSchema.parse({})
  const auditDir = auditRaw.dir ? expandHome(auditRaw.dir.trim(), homeDir) : path.join(stateDir, "audit")

  return {
    enabled: parsed.enabled,
    secrets: parsed.secrets,
    personal: parsed.personal,
    kinds,
    words,
    wordsAnyCase: parsed.wordsAnyCase,
    wordsWhole: parsed.wordsWhole,
    rules,
    actions,
    allow,
    shape: parsed.shape,
    skipProviders: new Set(parsed.skipProviders.map((p) => p.trim().toLowerCase()).filter(Boolean)),
    includeProviders: new Set(parsed.includeProviders.map((p) => p.trim().toLowerCase()).filter(Boolean)),
    failClosed: parsed.failClosed,
    persistKey: parsed.persistKey,
    keyPath,
    stateDir,
    audit: {
      enabled: auditRaw.enabled,
      dir: auditDir,
      keepDays: auditRaw.keepDays,
      keepBytes: auditRaw.keepBytes,
    },
  }
}

/** 将插件配置转为脱敏引擎选项 */
export function toMaskOptions(
  config: RedactConfig,
  overrides: Partial<Pick<MaskOptions, "route" | "onHit" | "sent" | "now">> = {},
): MaskOptions {
  return {
    secrets: config.secrets,
    personal: config.personal,
    kinds: config.kinds,
    words: config.words,
    wordsAnyCase: config.wordsAnyCase,
    wordsWhole: config.wordsWhole,
    rules: config.rules,
    actions: config.actions,
    allow: config.allow,
    shape: config.shape,
    ...overrides,
  }
}

/** 判断指定 providerID 是否需要脱敏 */
export function shouldMaskProvider(config: RedactConfig, providerID: string): boolean {
  const id = providerID.trim().toLowerCase()
  if (config.includeProviders.size > 0) {
    return config.includeProviders.has(id)
  }
  return !config.skipProviders.has(id)
}
