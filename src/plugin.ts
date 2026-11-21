// OpenCode v2 双向脱敏插件入口逻辑。
// 仅使用 `import type` 引入 `@opencode/plugin`，避免运行时强依赖宿主 SDK 路径。
import type { Plugin } from "@opencode/plugin"
import { AuditLogger } from "./audit.js"
import { parseConfig, type RedactConfig, shouldMaskProvider, toMaskOptions } from "./config.js"
import { RedactEngine } from "./engine/engine.js"
import { isBinaryContentType, WebSocketFrameRestorer, wrapHttpResponse } from "./engine/stream.js"
import { CATEGORIES, CATEGORY_DEFAULT_ON, type Hit } from "./engine/types.js"

export type V2Context = Plugin.Context
export type V2Cleanup = Plugin.Cleanup

type Registration = { dispose: () => Promise<void> }

export class RedactBlockedError extends Error {
  readonly hit: Hit

  constructor(hit: Hit) {
    const desc = hit.head ? `${hit.head}…，${hit.len} 字符` : `${hit.len} 字符`
    super(
      `opencode-redact 已拦截本次请求：规则对 ${hit.kind} 配置了 block 动作（命中 ${desc}），未向模型发送任何内容。`,
    )
    this.name = "RedactBlockedError"
    this.hit = hit
  }
}

export class RedactFailClosedError extends Error {
  constructor(cause: unknown) {
    const msg = cause instanceof Error ? cause.message : String(cause)
    super(`opencode-redact 脱敏处理异常（已开启 failClosed 保护，拒绝发送明文）：${msg}`)
    this.name = "RedactFailClosedError"
  }
}

function isSkippableRequestContentType(ct: string | null): boolean {
  if (!ct) return false
  const lower = ct.toLowerCase()
  return lower.startsWith("multipart/") || isBinaryContentType(lower)
}

function isCategoryEnabled(config: RedactConfig, id: string): boolean {
  if (!config.personal) return false
  const explicit = config.kinds[id]
  return explicit !== undefined ? explicit : (CATEGORY_DEFAULT_ON[id] ?? false)
}

function formatStatus(config: RedactConfig, runtimeEnabled: boolean, engine: RedactEngine, audit: AuditLogger): string {
  const activeCats = CATEGORIES.filter((c) => isCategoryEnabled(config, c.id)).map((c) => c.id)
  const storeStats = engine.store.stats()
  const lines = [
    `# opencode-redact 状态`,
    ``,
    `- 运行状态：${runtimeEnabled ? "已开启" : "已暂停"}`,
    `- 脱敏范围：secrets=${config.secrets ? "开" : "关"}，personal=${config.personal ? "开" : "关"}，shape=${config.shape ? "开" : "关"}，failClosed=${config.failClosed ? "开" : "关"}`,
    `- 启用的 personal 分类：${activeCats.length > 0 ? activeCats.join(", ") : "无"}`,
    `- 自定义配置：words=${config.words.length}，rules=${config.rules.length}，allow=${config.allow.length}，actions=${Object.keys(config.actions).length}`,
    `- Provider 过滤：include=[${[...config.includeProviders].join(", ")}]，skip=[${[...config.skipProviders].join(", ")}]`,
    `- 内存映射表：${storeStats.values} 条（仿形/伪装 ${storeStats.shapes} 条，类型 ${storeStats.kinds} 种）`,
    `- 会话统计：检查 ${audit.totalChecked} 次请求，脱敏 ${audit.totalMaskedRequests} 次（${audit.totalMaskedHits} 处命中，${audit.totalWarnedHits} 处告警，${audit.totalBlockedRequests} 次拦截，${audit.totalRestoredHits} 处还原）`,
    `- 审计日志：${config.audit.enabled ? config.audit.dir : "已关闭"}`,
  ]
  return lines.join("\n")
}

function formatPreview(sample: string, config: RedactConfig, engine: RedactEngine): string {
  const opts = toMaskOptions(config, { sent: false })
  const effectiveOpts =
    !opts.secrets && !opts.personal && opts.words.length === 0 ? { ...opts, secrets: true, personal: true } : opts
  const res = engine.preview(sample, effectiveOpts)
  const lines = [
    `# opencode-redact 预览（不会写入映射表，也不会发往模型）`,
    ``,
    `## 脱敏结果`,
    "```text",
    res.text,
    "```",
  ]
  if (res.hits.length === 0) {
    lines.push(``, `未命中任何敏感信息。`)
  } else {
    lines.push(``, `## 命中明细（共 ${res.hits.length} 处）`)
    for (const h of res.hits) {
      const hint = h.head ? `${h.head}…(${h.len})` : `${h.len} 字符`
      const act = h.action || "mask"
      lines.push(`- \`${h.kind}\` [${h.by}/${act}] ${hint} -> \`${h.placeholder}\``)
    }
  }
  return lines.join("\n")
}

function formatRecent(audit: AuditLogger, limit: number): string {
  const items = audit.recentRecords(limit)
  if (items.length === 0) {
    return "暂无脱敏记录。"
  }
  const lines = [`# 最近 ${items.length} 条脱敏审计记录`, ``]
  for (const r of items) {
    const kinds = r.values.map((v) => `${v.k}×${v.n}${v.a ? `(${v.a})` : ""}`).join(", ")
    const restoredSum = r.back ? Object.values(r.back).reduce((a, b) => a + b, 0) : 0
    const target = [r.provider, r.model].filter(Boolean).join("/") || "-"
    const status = r.blocked ? "BLOCKED" : r.what.toUpperCase()
    const took = r.tookUs !== undefined ? ` ${(r.tookUs / 1000).toFixed(2)}ms` : ""
    lines.push(
      `- [${r.t}] **${status}** ${target}${took} | 脱敏 ${r.n} 处${restoredSum > 0 ? ` / 还原 ${restoredSum} 处` : ""} | ${kinds}`,
    )
  }
  return lines.join("\n")
}

function formatHelp(): string {
  return [
    `# /redact 命令用法`,
    ``,
    `- \`/redact status\`：查看当前脱敏开关、规则统计与审计路径`,
    `- \`/redact preview <文本>\`：在本地预览脱敏结果（不写入内存表、不发送给模型）`,
    `- \`/redact toggle\` / \`/redact on\` / \`/redact off\`：动态开关当前运行期脱敏`,
    `- \`/redact recent [数量]\`：查看最近脱敏审计记录（仅含占位符与统计，不含原文）`,
    `- \`/redact clear\`：清空审计日志与统计计数（保留内存映射以确保在途会话正常还原）`,
  ].join("\n")
}

function parseCommandArgs(rawPrompt: string): { sub: string; rest: string } {
  const trimmed = rawPrompt.trim()
  const withoutSlash = trimmed.startsWith("/redact") ? trimmed.slice("/redact".length).trim() : trimmed
  if (!withoutSlash) return { sub: "status", rest: "" }
  const sp = withoutSlash.search(/\s/)
  if (sp < 0) return { sub: withoutSlash.toLowerCase(), rest: "" }
  return {
    sub: withoutSlash.slice(0, sp).toLowerCase(),
    rest: withoutSlash.slice(sp).trim(),
  }
}

export interface CreateRedactSetupDeps {
  readonly env?: NodeJS.ProcessEnv
  readonly homeDir?: string
  readonly now?: () => Date
  readonly key?: Uint8Array
}

/** 创建 OpenCode v2 插件 setup 函数（每次 setup 独立维护状态，支持隔离测试） */
export function createRedactSetup(deps: CreateRedactSetupDeps = {}): (ctx: V2Context) => Promise<V2Cleanup> {
  return async (ctx: V2Context): Promise<V2Cleanup> => {
    const config = parseConfig(ctx.options, deps.env, deps.homeDir)
    const engine = new RedactEngine({
      key: deps.key,
      keyPath: deps.key ? undefined : config.keyPath,
    })
    const audit = new AuditLogger({
      enabled: config.audit.enabled,
      dir: config.audit.dir,
      keepDays: config.audit.keepDays,
      keepBytes: config.audit.keepBytes,
      now: deps.now,
    })

    let runtimeEnabled = config.enabled
    const requestAuditKeys = new WeakMap<Request, number | undefined>()
    const wsRestorers = new Map<string, WebSocketFrameRestorer>()
    const wsLastAuditKeys = new Map<string, number | undefined>()
    const registrations: Registration[] = []

    const register = async (call: () => Promise<Registration>): Promise<void> => {
      registrations.push(await call())
    }

    const disposeAll = async (): Promise<void> => {
      for (const reg of registrations.splice(0).reverse()) {
        try {
          await reg.dispose()
        } catch {
          // 宿主卸载阶段忽略清理错误
        }
      }
      wsRestorers.clear()
      wsLastAuditKeys.clear()
    }

    const getWsRestorer = (sessionID: string): WebSocketFrameRestorer => {
      let restorer = wsRestorers.get(sessionID)
      if (!restorer) {
        if (wsRestorers.size >= 256) {
          const firstKey = wsRestorers.keys().next().value
          if (firstKey !== undefined) wsRestorers.delete(firstKey)
        }
        restorer = new WebSocketFrameRestorer(engine)
        wsRestorers.set(sessionID, restorer)
      }
      return restorer
    }

    const sendLocalNotice = async (sessionID: string, text: string): Promise<void> => {
      await ctx.session.synthetic({
        sessionID,
        text,
        description: "opencode-redact",
        resume: false,
      })
    }

    try {
      // 1. 出站 HTTP 请求脱敏
      await register(() =>
        ctx.session.hook("http.request", async (event) => {
          if (!runtimeEnabled || !shouldMaskProvider(config, event.model.providerID)) return
          const req = event.request
          if (!req.body || req.method === "GET" || req.method === "HEAD") return
          if (isSkippableRequestContentType(req.headers.get("content-type"))) return

          const started = performance.now()
          let rawBody: string
          try {
            rawBody = await req.clone().text()
          } catch (error) {
            if (config.failClosed) throw new RedactFailClosedError(error)
            return
          }
          if (!rawBody) return

          audit.noteChecked()
          let result: ReturnType<RedactEngine["maskJSON"]>
          try {
            const opts = toMaskOptions(config, {
              route: event.model.providerID,
              sent: true,
              now: deps.now,
            })
            result = engine.maskJSON(rawBody, opts)
          } catch (error) {
            if (config.failClosed) throw new RedactFailClosedError(error)
            return
          }
          const tookUs = Math.round((performance.now() - started) * 1000)

          if (result.blocked) {
            audit.record({
              what: "blocked",
              sessionID: event.sessionID,
              agent: event.agent,
              provider: event.model.providerID,
              model: event.model.id,
              hits: result.hits,
              blocked: true,
              tookUs,
            })
            throw new RedactBlockedError(result.blocked)
          }

          const rec =
            result.hits.length > 0
              ? audit.record({
                  what: "http",
                  sessionID: event.sessionID,
                  agent: event.agent,
                  provider: event.model.providerID,
                  model: event.model.id,
                  hits: result.hits,
                  tookUs,
                })
              : undefined

          if (result.count > 0 && result.text !== rawBody) {
            const headers = new Headers(req.headers)
            headers.delete("content-length")
            const maskedRequest = new Request(req, {
              body: result.text,
              headers,
            })
            event.request = maskedRequest
            requestAuditKeys.set(maskedRequest, rec?.key)
          } else if (rec) {
            requestAuditKeys.set(req, rec.key)
          }
        }),
      )

      // 2. 入站 HTTP 响应还原（流式 SSE + 非流式 JSON）
      // 即使当前请求未新增脱敏或开关刚被关闭，只要内存表中仍有映射就继续还原历史占位符
      await register(() =>
        ctx.session.hook("http.response", (event) => {
          if (!engine.store.hasValues()) return
          const recordKey = requestAuditKeys.get(event.request)
          event.response = wrapHttpResponse(engine, event.response, (restoredCounts) => {
            audit.noteRestored(recordKey, restoredCounts)
          })
        }),
      )

      // 3. WebSocket 双向帧脱敏/还原（适配 OpenAI Responses WS 等长连接驱动）
      try {
        await register(() =>
          ctx.session.hook("experimental.ws.send", (event) => {
            if (!runtimeEnabled || !shouldMaskProvider(config, event.model.providerID)) return
            if (!event.frame) return
            const started = performance.now()
            audit.noteChecked()
            let result: ReturnType<RedactEngine["maskJSON"]>
            try {
              const opts = toMaskOptions(config, {
                route: event.model.providerID,
                sent: true,
                now: deps.now,
              })
              result = engine.maskJSON(event.frame, opts)
            } catch (error) {
              if (config.failClosed) throw new RedactFailClosedError(error)
              return
            }
            const tookUs = Math.round((performance.now() - started) * 1000)
            if (result.blocked) {
              audit.record({
                what: "blocked",
                sessionID: event.sessionID,
                agent: event.agent,
                provider: event.model.providerID,
                model: event.model.id,
                hits: result.hits,
                blocked: true,
                tookUs,
              })
              throw new RedactBlockedError(result.blocked)
            }
            if (result.hits.length > 0) {
              const rec = audit.record({
                what: "ws",
                sessionID: event.sessionID,
                agent: event.agent,
                provider: event.model.providerID,
                model: event.model.id,
                hits: result.hits,
                tookUs,
              })
              wsLastAuditKeys.set(event.sessionID, rec?.key)
            }
            if (result.count > 0 && result.text !== event.frame) {
              event.frame = result.text
            }
          }),
        )

        await register(() =>
          ctx.session.hook("experimental.ws.receive", (event) => {
            if (!event.frame || !engine.store.hasValues()) return
            const restorer = getWsRestorer(event.sessionID)
            const restoredCounts = new Map<string, number>()
            const out = restorer.restoreFrame(event.frame, restoredCounts)
            if (out !== event.frame) {
              event.frame = out
            }
            if (restoredCounts.size > 0) {
              audit.noteRestored(wsLastAuditKeys.get(event.sessionID), restoredCounts)
            }
          }),
        )
      } catch {
        // 兼容未提供 experimental.ws.* hook 的旧版 OpenCode 2.x
      }

      // 4. 注册 /redact Slash Command
      if (ctx.command?.transform) {
        await register(() =>
          ctx.command.transform((editor) => {
            editor.add({
              name: "redact",
              description: "查看或控制本地敏感信息脱敏（status / preview / toggle / recent / clear）",
              execute: async (invocation) => {
                const { sub, rest } = parseCommandArgs(invocation.prompt.text ?? "")
                switch (sub) {
                  case "status":
                    await sendLocalNotice(invocation.sessionID, formatStatus(config, runtimeEnabled, engine, audit))
                    return
                  case "preview":
                    if (!rest) {
                      await sendLocalNotice(invocation.sessionID, "用法：`/redact preview <待检测文本>`")
                      return
                    }
                    await sendLocalNotice(invocation.sessionID, formatPreview(rest, config, engine))
                    return
                  case "toggle":
                    runtimeEnabled = !runtimeEnabled
                    await sendLocalNotice(
                      invocation.sessionID,
                      `opencode-redact 已${runtimeEnabled ? "开启" : "暂停"}。`,
                    )
                    return
                  case "on":
                  case "enable":
                    runtimeEnabled = true
                    await sendLocalNotice(invocation.sessionID, "opencode-redact 已开启。")
                    return
                  case "off":
                  case "disable":
                    runtimeEnabled = false
                    await sendLocalNotice(invocation.sessionID, "opencode-redact 已暂停。")
                    return
                  case "recent": {
                    const n = rest ? Number.parseInt(rest, 10) : 10
                    const limit = Number.isFinite(n) && n > 0 ? n : 10
                    await sendLocalNotice(invocation.sessionID, formatRecent(audit, limit))
                    return
                  }
                  case "clear": {
                    const removed = audit.clear()
                    await sendLocalNotice(
                      invocation.sessionID,
                      `已清空脱敏审计记录（删除 ${removed} 个日志文件；内存映射表已保留以确保会话继续还原）。`,
                    )
                    return
                  }
                  default:
                    await sendLocalNotice(invocation.sessionID, formatHelp())
                    return
                }
              },
            })
          }),
        )
      }
    } catch (error) {
      await disposeAll()
      throw error
    }

    return async () => {
      await disposeAll()
    }
  }
}
