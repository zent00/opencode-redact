// SSE 流式、整包 JSON 与 WebSocket 帧级双向还原器（借鉴 Magpie internal/redact/writer.go）。
import type { RedactEngine } from "./engine.js"
import {
  eventCtxOfJSON,
  hasPathsInJSON,
  isNestedJSONField,
  isSealedResponseText,
  KEPT_KEYS,
  typeOfJSON,
  walkJSONStrings,
} from "./jsonWalker.js"

const WAIT_EVENTS = new Set(["ping", "keepalive", "response.in_progress", "response.queued"])

const BINARY_CONTENT_TYPES = [
  "audio/",
  "image/",
  "video/",
  "application/octet-stream",
  "application/pdf",
  "application/zip",
]

export function isBinaryContentType(ct: string | null | undefined): boolean {
  if (!ct) return false
  const lower = ct.toLowerCase()
  return BINARY_CONTENT_TYPES.some((prefix) => lower.startsWith(prefix))
}

interface PendingEvent {
  readonly ctx: string
  readonly tails: Map<string, string>
  readonly full: string
  readonly cut: string
}

interface SplitEvent {
  readonly name: string
  readonly data: string
  readonly pre: string
  readonly post: string
}

function splitSSEEvent(ev: string): SplitEvent | undefined {
  const lines = ev.match(/[^\n]*\n|[^\n]+$/g)
  if (!lines) return undefined
  let name = ""
  let dataLineIdx = -1
  let offset = 0
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!
    const trimmed = line.replace(/\r?\n$/, "")
    if (trimmed.startsWith("event:")) {
      name = trimmed.slice(6).trim()
    } else if (trimmed.startsWith("data:")) {
      if (dataLineIdx >= 0) return undefined // 多行 data: 按纯文本降级还原
      dataLineIdx = i
    }
    if (dataLineIdx < 0) offset += line.length
  }
  if (dataLineIdx < 0) return undefined
  const line = lines[dataLineIdx]!
  const trimmed = line.replace(/\r?\n$/, "")
  const start = trimmed.length > 5 && trimmed[5] === " " ? 6 : 5
  const data = trimmed.slice(start)
  if (!data || (data[0] !== "{" && data[0] !== "[")) return undefined
  return {
    name,
    data,
    pre: ev.slice(0, offset + start),
    post: ev.slice(offset + trimmed.length),
  }
}

function isWaitEvent(name: string, data: string): boolean {
  const typ = typeOfJSON(data) || name
  return WAIT_EVENTS.has(typ)
}

function leadingCommentLength(buf: string): number {
  let n = 0
  while (n < buf.length && (buf[n] === ":" || buf[n] === "\n" || buf[n] === "\r")) {
    const nl = buf.indexOf("\n", n)
    if (nl < 0 || (buf[n] === "\r" && nl !== n + 1)) break
    n = nl + 1
  }
  return n
}

function findEventBoundary(buf: string): readonly [number, number] {
  const i = buf.indexOf("\n\n")
  const j = buf.indexOf("\r\n\r\n")
  if (i < 0 && j < 0) return [-1, 0]
  if (j >= 0 && (i < 0 || j < i)) return [j, 4]
  return [i, 2]
}

/** 逐事件 SSE 还原状态机，处理跨事件切分占位符、心跳直通与嵌套 JSON 参数转义 */
export class SSERestorer {
  private buf = ""
  private pending: PendingEvent | undefined
  readonly restoredCounts = new Map<string, number>()

  constructor(private readonly engine: RedactEngine) {}

  push(chunk: string): string {
    this.buf += chunk
    let out = ""
    while (this.buf.length > 0) {
      const commentLen = leadingCommentLength(this.buf)
      if (commentLen > 0) {
        out += this.buf.slice(0, commentLen)
        this.buf = this.buf.slice(commentLen)
        continue
      }
      const [idx, sepLen] = findEventBoundary(this.buf)
      if (idx < 0) break
      const ev = this.buf.slice(0, idx + sepLen)
      this.buf = this.buf.slice(idx + sepLen)
      out += this.processEvent(ev)
    }
    return out
  }

  finish(): string {
    let out = ""
    if (this.pending) {
      out += this.pending.full
      this.pending = undefined
    }
    if (this.buf.length > 0) {
      out += this.engine.restore(this.buf, false, this.restoredCounts)
      this.buf = ""
    }
    return out
  }

  private processEvent(ev: string): string {
    if (!this.pending && !this.engine.store.hasValues()) {
      return ev
    }
    const split = splitSSEEvent(ev)
    if (!split) {
      let out = ""
      if (this.pending) {
        out += this.pending.full
        this.pending = undefined
      }
      return out + this.engine.restore(ev, false, this.restoredCounts)
    }

    const { name, data, pre, post } = split
    if (this.pending && isWaitEvent(name, data)) {
      return pre + this.engine.restoreJSON(data, this.restoredCounts) + post
    }

    let prefixOut = ""
    let carry: Map<string, string> | undefined
    const ctx = `${name}|${eventCtxOfJSON(data)}`
    if (this.pending) {
      if (this.pending.ctx === ctx && hasPathsInJSON(data, this.pending.tails)) {
        prefixOut = this.pending.cut
        carry = this.pending.tails
      } else {
        prefixOut = this.pending.full
      }
      this.pending = undefined
    }

    const typ = typeOfJSON(data) || name
    let tails: Map<string, string> | undefined
    let cuts: Map<string, string> | undefined

    const walked = walkJSONStrings(data, (p, key, rawStr) => {
      const s = carry?.has(p) ? `${carry.get(p)!}${rawStr}` : rawStr
      if (isSealedResponseText(key, s)) return s
      const escaped = isNestedJSONField(key, typ)
      if (!KEPT_KEYS.has(key) && key !== "obfuscation") {
        const n = this.engine.partialTail(s)
        if (n > 0) {
          if (!tails || !cuts) {
            tails = new Map()
            cuts = new Map()
          }
          tails.set(p, s.slice(s.length - n))
          cuts.set(p, this.engine.restore(s.slice(0, s.length - n), escaped))
        }
      }
      return this.engine.restore(s, escaped, this.restoredCounts)
    })

    const full = pre + walked.text + post
    if (!tails || !cuts) {
      return prefixOut + full
    }

    const cutWalked = walkJSONStrings(walked.text, (p, _k, s) => cuts!.get(p) ?? s)
    this.pending = {
      ctx,
      tails,
      full,
      cut: pre + cutWalked.text + post,
    }
    return prefixOut
  }
}

/** 包装 Web Fetch Response，对 SSE 流实时还原、对 JSON/文本整包还原、对二进制流直通 */
export function wrapHttpResponse(
  engine: RedactEngine,
  response: Response,
  onFinished?: (restored: Map<string, number>) => void,
): Response {
  if (!response.body || response.status === 204 || !engine.store.hasValues()) {
    return response
  }
  const ct = response.headers.get("content-type") ?? ""
  if (isBinaryContentType(ct)) {
    return response
  }

  const encoder = new TextEncoder()
  const decoder = new TextDecoder()
  let mode: "unknown" | "stream" | "whole" = ct.toLowerCase().includes("event-stream") ? "stream" : "unknown"
  const sse = new SSERestorer(engine)
  let wholeBuf = ""
  const wholeCounts = new Map<string, number>()

  const transform = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      const text = decoder.decode(chunk, { stream: true })
      if (!text) return
      if (mode === "unknown") {
        mode =
          !ct && (text.startsWith("event:") || text.startsWith("data:") || text.startsWith(":")) ? "stream" : "whole"
      }
      if (mode === "stream") {
        const out = sse.push(text)
        if (out) controller.enqueue(encoder.encode(out))
      } else {
        wholeBuf += text
      }
    },
    flush(controller) {
      const trailing = decoder.decode()
      if (mode === "stream") {
        if (trailing) {
          const out = sse.push(trailing)
          if (out) controller.enqueue(encoder.encode(out))
        }
        const finalOut = sse.finish()
        if (finalOut) controller.enqueue(encoder.encode(finalOut))
        onFinished?.(sse.restoredCounts)
      } else {
        wholeBuf += trailing
        if (wholeBuf) {
          const restored = engine.restoreJSON(wholeBuf, wholeCounts)
          controller.enqueue(encoder.encode(restored))
        }
        onFinished?.(wholeCounts)
      }
    },
  })

  const headers = new Headers(response.headers)
  // 还原后字节长度发生变化，且 fetch 读取 body 时已自动解压，移除旧长度和编码头
  headers.delete("content-length")
  headers.delete("content-encoding")

  return new Response(response.body.pipeThrough(transform), {
    status: response.status,
    statusText: response.statusText,
    headers,
  })
}

/**
 * WebSocket 入站帧级还原器（面向 OpenCode v2 `experimental.ws.receive`）。
 * 与 SSE 不同，WS hook 每次调用必须 1:1 返回当前帧，因此遇到末尾截断占位符时立即吐出安全前缀（cut），
 * 并把尾部暂存到下一帧同上下文的 delta 前拼接还原。
 */
export class WebSocketFrameRestorer {
  private pendingCtx = ""
  private pendingTails = new Map<string, string>()

  constructor(private readonly engine: RedactEngine) {}

  restoreFrame(frame: string, restoredCounts?: Map<string, number>): string {
    if (!this.engine.store.hasValues() && this.pendingTails.size === 0) return frame
    const trimmed = frame.trimStart()
    if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
      this.pendingTails.clear()
      this.pendingCtx = ""
      return this.engine.restore(frame, false, restoredCounts)
    }

    const typ = typeOfJSON(frame)
    if (WAIT_EVENTS.has(typ)) {
      return this.engine.restoreJSON(frame, restoredCounts)
    }

    const ctx = eventCtxOfJSON(frame)
    let carry: Map<string, string> | undefined
    if (this.pendingTails.size > 0) {
      if (this.pendingCtx === ctx && hasPathsInJSON(frame, this.pendingTails)) {
        carry = new Map(this.pendingTails)
      }
      this.pendingTails.clear()
      this.pendingCtx = ""
    }

    const nextTails = new Map<string, string>()
    const walked = walkJSONStrings(frame, (p, key, rawStr) => {
      const s = carry?.has(p) ? `${carry.get(p)!}${rawStr}` : rawStr
      if (isSealedResponseText(key, s)) return s
      const escaped = isNestedJSONField(key, typ)
      // 仅对 delta 流式分片做跨帧尾缀暂存，终态（done/completed）帧完整还原
      if (!KEPT_KEYS.has(key) && key !== "obfuscation" && typ.includes("delta")) {
        const n = this.engine.partialTail(s)
        if (n > 0) {
          nextTails.set(p, s.slice(s.length - n))
          return this.engine.restore(s.slice(0, s.length - n), escaped, restoredCounts)
        }
      }
      return this.engine.restore(s, escaped, restoredCounts)
    })

    if (nextTails.size > 0) {
      this.pendingCtx = ctx
      this.pendingTails = nextTails
    }
    return walked.ok ? walked.text : this.engine.restore(frame, false, restoredCounts)
  }

  reset(): void {
    this.pendingCtx = ""
    this.pendingTails.clear()
  }
}
