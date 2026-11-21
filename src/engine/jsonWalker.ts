// 协议感知的精确 JSON 遍历器与区域识别（借鉴 Magpie internal/redact/json.go）。
// 未修改的字符串保持原样，仅改写命中的字符串字面量，并精准区分：
// - kept / isID：协议控制字段与 ID，禁止脱敏；
// - defs：工具/输出 schema 定义区，仅脱敏 description；
// - signed：供应商签名块（thinking.signature / thoughtSignature / encrypted_content），仅回填已知映射；
// - args：工具调用参数与结构化工具结果，放开协议键名并启用按字段名识密。
import { isSecretFieldName, notAVariable, timestampValue } from "./validators.js"

export const KEPT_KEYS: ReadonlySet<string> = new Set([
  "signature",
  "encrypted_content",
  "data",
  "thoughtSignature",
  "thought_signature",
  "model",
  "id",
  "tool_use_id",
  "call_id",
  "item_id",
  "type",
  "role",
  "name",
  "namespace",
  "server_label",
  "server_name",
  "previous_response_id",
  "prompt_cache_key",
  "media_type",
  "mime_type",
  "mimeType",
  "url",
  "image_url",
  "file_id",
  "reasoning_effort",
  "effort",
  "stop_reason",
  "finish_reason",
  "status",
  "object",
  "event",
])

export const SIGNATURE_KEYS: readonly string[] = [
  "signature",
  "thoughtSignature",
  "thought_signature",
  "encrypted_content",
]

const DEF_KEYS: readonly string[] = [
  "tools",
  "tool_choice",
  "functions",
  "function_call",
  "toolConfig",
  "tool_config",
  "response_format",
  "text",
  "reasoning",
  "include",
  "output_format",
  "output_config",
  "generationConfig",
  "generation_config",
  "stream_options",
  "client_metadata",
]

const DEF_ITEMS = new Set(["additional_tools", "tool_search_output"])

export function isProtocolID(key: string): boolean {
  return (
    key === "id" ||
    key === "ids" ||
    key.endsWith("_id") ||
    key.endsWith("_ids") ||
    key.endsWith("Id") ||
    key.endsWith("Ids")
  )
}

export function underAny(path: string, roots: readonly string[]): boolean {
  for (const r of roots) {
    if (r === "" || path === r || path.startsWith(`${r}.`)) return true
  }
  return false
}

export function keepIn(
  path: string,
  key: string,
  s: string,
  args: readonly string[],
  defs: readonly string[],
): boolean {
  if (s.startsWith("data:")) return true
  if (underAny(path, args)) return false
  if (underAny(path, defs)) return key !== "description"
  return KEPT_KEYS.has(key) || isProtocolID(key)
}

/** 响应中不应被还原修改的密封文本（签名、data: URI、长 base64 data 字段） */
export function isSealedResponseText(key: string, s: string): boolean {
  return (
    SIGNATURE_KEYS.includes(key) ||
    s.startsWith("data:") ||
    (key === "data" && s.length >= 64 && !s.includes(" ") && !s.includes("\n"))
  )
}

/** 该 JSON 字段本身承载嵌套 JSON 字符串（如 tool_call 的 arguments / partial_json / delta） */
export function isNestedJSONField(key: string, eventType: string): boolean {
  return key === "arguments" || key === "partial_json" || (key === "delta" && eventType.includes("arguments"))
}

/** 工具参数区域按字段名直接识别密钥（例如 {"api_key": "..."}） */
export function isNamedSecret(key: string, s: string): boolean {
  return key !== "" && s.length >= 8 && notAVariable(s) && !timestampValue(s) && isSecretFieldName(key)
}

/** 将字符串转义为 JSON 字符串内部内容（不含外层双引号） */
export function jsonEscape(s: string): string {
  return JSON.stringify(s).slice(1, -1)
}

function joinPath(prefix: string, seg: string): string {
  return prefix ? `${prefix}.${seg}` : seg
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v)
}

function isSealedObject(x: Record<string, unknown>): boolean {
  const t = typeof x.type === "string" ? x.type : ""
  for (const k of SIGNATURE_KEYS) {
    const v = x[k]
    if (typeof v !== "string" || v === "") continue
    if (
      k === "thoughtSignature" ||
      k === "thought_signature" ||
      t === "thinking" ||
      t === "reasoning" ||
      t.startsWith("reasoning.")
    ) {
      return true
    }
  }
  return false
}

function isToolArgsField(t: string, parentKey: string, key: string): boolean {
  if (t.endsWith("tool_use")) return key === "input"
  if (t.endsWith("_call")) {
    return key === "arguments" || key === "input" || key === "action" || key === "operation"
  }
  if (parentKey === "function" || parentKey === "functionCall" || parentKey === "function_call") {
    return key === "arguments" || key === "args"
  }
  return false
}

function findDefinitions(v: unknown): string[] {
  if (!isPlainObject(v)) return []
  const defs: string[] = []
  for (const k of DEF_KEYS) {
    if (!(k in v)) continue
    if (k === "text" && !isPlainObject(v[k])) continue
    defs.push(k)
  }
  const items = v.input
  if (Array.isArray(items)) {
    for (let i = 0; i < items.length; i++) {
      const it = items[i]
      if (isPlainObject(it) && typeof it.type === "string" && DEF_ITEMS.has(it.type)) {
        defs.push(joinPath(joinPath("input", String(i)), "tools"))
      }
    }
  }
  return defs
}

export interface ScannedRegions {
  readonly signed: string[]
  readonly args: string[]
  readonly defs: string[]
}

/** 扫描请求体 JSON，定位签名块、工具参数区、定义区路径 */
export function scanJSONRegions(body: string): ScannedRegions {
  let maybeHasSpecial = false
  for (const k of [
    ...SIGNATURE_KEYS,
    "functionCall",
    "function_call",
    "functionResponse",
    "function_response",
    "arguments",
  ]) {
    if (body.includes(`"${k}"`)) {
      maybeHasSpecial = true
      break
    }
  }
  if (!maybeHasSpecial && (body.includes('tool_use"') || body.includes('_call"'))) {
    maybeHasSpecial = true
  }
  if (!maybeHasSpecial) {
    for (const k of DEF_KEYS) {
      if (body.includes(`"${k}"`)) {
        maybeHasSpecial = true
        break
      }
    }
  }
  if (!maybeHasSpecial) {
    return { signed: [], args: [], defs: [] }
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(body)
  } catch {
    return { signed: [], args: [], defs: [] }
  }
  const defs = findDefinitions(parsed)
  const signed: string[] = []
  const args: string[] = []

  const visit = (curPath: string, parentKey: string, node: unknown): void => {
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        visit(joinPath(curPath, String(i)), parentKey, node[i])
      }
      return
    }
    if (!isPlainObject(node)) return
    if (isSealedObject(node)) {
      signed.push(curPath)
      return
    }
    const t = typeof node.type === "string" ? node.type : ""
    for (const [k, child] of Object.entries(node)) {
      if (
        isToolArgsField(t, parentKey, k) ||
        (k === "response" && (parentKey === "functionResponse" || parentKey === "function_response"))
      ) {
        args.push(joinPath(curPath, k))
        continue
      }
      visit(joinPath(curPath, k), k, child)
    }
  }
  visit("", "", parsed)
  return { signed, args, defs }
}

/** 遍历 JSON 文档中的每个字符串值并按需原地替换，保留其他所有文本字节不变 */
export function walkJSONStrings(
  input: string,
  fn: (path: string, key: string, value: string) => string,
): { readonly text: string; readonly ok: boolean } {
  const len = input.length
  let out = ""
  let last = 0

  const ws = (i: number): number => {
    while (i < len) {
      const c = input.charCodeAt(i)
      if (c === 32 || c === 9 || c === 10 || c === 13) i++
      else break
    }
    return i
  }

  const scanString = (i: number): { end: number; escaped: boolean; ok: boolean } => {
    let escaped = false
    for (let j = i + 1; j < len; j++) {
      const c = input.charCodeAt(j)
      if (c === 92) {
        escaped = true
        j++
      } else if (c === 34) {
        return { end: j + 1, escaped, ok: true }
      }
    }
    return { end: 0, escaped: false, ok: false }
  }

  const parseValue = (start: number, curPath: string, key: string): { next: number; ok: boolean } => {
    let i = start
    if (i >= len) return { next: i, ok: false }
    const ch = input[i]!
    if (ch === "{") {
      i = ws(i + 1)
      if (i < len && input[i] === "}") return { next: i + 1, ok: true }
      while (true) {
        if (i >= len || input[i] !== '"') return { next: i, ok: false }
        const st = scanString(i)
        if (!st.ok) return { next: i, ok: false }
        let k = input.slice(i + 1, st.end - 1)
        if (st.escaped) {
          try {
            k = JSON.parse(input.slice(i, st.end)) as string
          } catch {
            return { next: i, ok: false }
          }
        }
        i = ws(st.end)
        if (i >= len || input[i] !== ":") return { next: i, ok: false }
        const valRes = parseValue(ws(i + 1), joinPath(curPath, k), k)
        if (!valRes.ok) return valRes
        i = ws(valRes.next)
        if (i < len && input[i] === ",") {
          i = ws(i + 1)
          continue
        }
        if (i < len && input[i] === "}") return { next: i + 1, ok: true }
        return { next: i, ok: false }
      }
    }
    if (ch === "[") {
      i = ws(i + 1)
      if (i < len && input[i] === "]") return { next: i + 1, ok: true }
      for (let n = 0; ; n++) {
        const valRes = parseValue(i, joinPath(curPath, String(n)), key)
        if (!valRes.ok) return valRes
        i = ws(valRes.next)
        if (i < len && input[i] === ",") {
          i = ws(i + 1)
          continue
        }
        if (i < len && input[i] === "]") return { next: i + 1, ok: true }
        return { next: i, ok: false }
      }
    }
    if (ch === '"') {
      const st = scanString(i)
      if (!st.ok) return { next: i, ok: false }
      let s = input.slice(i + 1, st.end - 1)
      if (st.escaped) {
        try {
          s = JSON.parse(input.slice(i, st.end)) as string
        } catch {
          return { next: i, ok: false }
        }
      }
      const replaced = fn(curPath, key, s)
      if (replaced !== s) {
        out += input.slice(last, i)
        out += `"${jsonEscape(replaced)}"`
        last = st.end
      }
      return { next: st.end, ok: true }
    }
    let j = i
    while (j < len && !",]} \t\r\n".includes(input[j]!)) j++
    if (j === i) return { next: i, ok: false }
    return { next: j, ok: true }
  }

  const root = parseValue(ws(0), "", "")
  if (!root.ok || ws(root.next) !== len) {
    return { text: input, ok: false }
  }
  if (last === 0) {
    return { text: input, ok: true }
  }
  return { text: out + input.slice(last), ok: true }
}

/** 读取 JSON 顶层 "type" 字段（不依赖键顺序） */
export function typeOfJSON(data: string): string {
  let typ = ""
  walkJSONStrings(data, (p, _k, s) => {
    if (p === "type") typ = s
    return s
  })
  return typ
}

/** 提取流式事件的续接上下文标识（type/item_id/index/output_index/content_index） */
export function eventCtxOfJSON(data: string): string {
  let ctx = ""
  walkJSONStrings(data, (p, _k, s) => {
    if (p === "type" || p === "item_id") {
      ctx += `${p}=${s};`
    }
    return s
  })
  for (const k of ['"index":', '"output_index":', '"content_index":']) {
    const idx = data.indexOf(k)
    if (idx >= 0) {
      const j = idx + k.length
      let e = j
      while (e < data.length && ((data[e]! >= "0" && data[e]! <= "9") || data[e] === " ")) e++
      ctx += `${k}${data.slice(j, e)};`
    }
  }
  return ctx
}

/** 检查 JSON 文档中是否包含所有指定路径的字符串字段 */
export function hasPathsInJSON(data: string, paths: ReadonlyMap<string, string>): boolean {
  let found = 0
  walkJSONStrings(data, (p, _k, s) => {
    if (paths.has(p)) found++
    return s
  })
  return found === paths.size
}
