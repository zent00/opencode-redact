import { afterEach, describe, expect, test } from "bun:test"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { createRedactSetup, RedactBlockedError, type V2Context } from "../src/index.js"

const tmpDirs: string[] = []
function makeTempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "opencode-redact-plugin-"))
  tmpDirs.push(dir)
  return dir
}

afterEach(() => {
  for (const dir of tmpDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

type HookFn = (event: Record<string, unknown>) => Promise<void> | void
type CommandDef = {
  name: string
  description?: string
  execute: (inv: { sessionID: string; prompt: { text: string }; delivery: string }) => Promise<void>
}

function makeMockCtx(options: Record<string, unknown> = {}) {
  const hooks: Record<string, HookFn> = {}
  const commands: Record<string, CommandDef> = {}
  const synthetics: Array<{ sessionID: string; text: string; resume?: boolean | null }> = []
  const disposed: string[] = []

  const ctx = {
    app: { name: "cli", version: "2.3.2", channel: "latest" },
    location: { directory: "/tmp/test-project" },
    options,
    session: {
      hook: async (name: string, cb: HookFn) => {
        hooks[name] = cb
        return {
          dispose: async () => {
            disposed.push(`session:${name}`)
          },
        }
      },
      synthetic: async (input: { sessionID: string; text: string; resume?: boolean | null }) => {
        synthetics.push(input)
        return { id: "syn_1" }
      },
    },
    command: {
      transform: async (cb: (editor: { add: (def: CommandDef) => void }) => void) => {
        cb({
          add: (def) => {
            commands[def.name] = def
          },
        })
        return {
          dispose: async () => {
            disposed.push("command.transform")
          },
        }
      },
    },
  }

  return {
    ctx: ctx as unknown as V2Context,
    hooks,
    commands,
    synthetics,
    disposed,
  }
}

describe("OpenCode v2 插件集成测试", () => {
  test("http.request 脱敏 + http.response SSE 流式还原 + skipProviders 过滤", async () => {
    const stateDir = makeTempDir()
    const mock = makeMockCtx({
      stateDir,
      skipProviders: ["ollama"],
    })
    const setup = createRedactSetup({ key: new Uint8Array(32).fill(5) })
    const cleanup = await setup(mock.ctx)

    const realKey = "sk-proj-AbCdEf1234567890GhIjKlMnOpQrStUv"
    const reqEvent: Record<string, unknown> = {
      sessionID: "ses_1",
      agent: "build",
      model: { providerID: "openai", id: "gpt-5" },
      kind: "primary",
      request: new Request("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          model: "gpt-5",
          messages: [{ role: "user", content: `Use key ${realKey}` }],
        }),
      }),
    }

    await mock.hooks["http.request"]!(reqEvent)
    const sentReq = reqEvent.request as Request
    const sentBody = await sentReq.clone().text()
    expect(sentBody).not.toContain(realKey)
    const phMatch = /\{\{API_KEY_[a-z2-7]{8}\}\}/.exec(sentBody)
    expect(phMatch).not.toBeNull()
    const ph = phMatch![0]

    // 模拟上游 SSE 响应把占位符拆成两片返回
    const encoder = new TextEncoder()
    const sseStream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(`data: {"choices":[{"delta":{"content":"Key: ${ph.slice(0, 6)}"}}]}\n\n`))
        controller.enqueue(encoder.encode(`data: {"choices":[{"delta":{"content":"${ph.slice(6)}"}}]}\n\n`))
        controller.enqueue(encoder.encode("data: [DONE]\n\n"))
        controller.close()
      },
    })
    const respEvent: Record<string, unknown> = {
      sessionID: "ses_1",
      agent: "build",
      model: { providerID: "openai", id: "gpt-5" },
      kind: "primary",
      request: sentReq,
      response: new Response(sseStream, {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      }),
    }
    await mock.hooks["http.response"]!(respEvent)
    const finalText = await (respEvent.response as Response).text()
    expect(finalText).toContain(realKey)
    expect(finalText).not.toContain(ph)

    // skipProviders 中的 ollama 应跳过脱敏
    const ollamaReq = new Request("http://127.0.0.1:11434/v1/chat/completions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ messages: [{ role: "user", content: `Use ${realKey}` }] }),
    })
    const ollamaEvent: Record<string, unknown> = {
      sessionID: "ses_1",
      agent: "build",
      model: { providerID: "ollama", id: "qwen3" },
      kind: "primary",
      request: ollamaReq,
    }
    await mock.hooks["http.request"]!(ollamaEvent)
    expect(ollamaEvent.request).toBe(ollamaReq)

    await cleanup()
    expect(mock.disposed.length).toBeGreaterThanOrEqual(4)
  })

  test("actions block 拦截请求，experimental.ws 双向帧脱敏还原，以及 /redact 命令", async () => {
    const stateDir = makeTempDir()
    const mock = makeMockCtx({
      stateDir,
      actions: { PRIVATE_KEY: "block" },
    })
    const setup = createRedactSetup({ key: new Uint8Array(32).fill(6) })
    const cleanup = await setup(mock.ctx)

    // 1. Block 动作
    const blockEvent: Record<string, unknown> = {
      sessionID: "ses_2",
      agent: "build",
      model: { providerID: "anthropic", id: "claude-sonnet" },
      kind: "primary",
      request: new Request("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          messages: [{ role: "user", content: "-----BEGIN PRIVATE KEY-----\nABC123456\n-----END PRIVATE KEY-----" }],
        }),
      }),
    }
    await expect(mock.hooks["http.request"]!(blockEvent)).rejects.toBeInstanceOf(RedactBlockedError)

    // 2. WebSocket 帧双向脱敏还原
    const secret = "ghp_1234567890abcdefghijklmnopqrstuvwx"
    const wsSend: Record<string, unknown> = {
      sessionID: "ses_ws",
      agent: "build",
      model: { providerID: "openai", id: "gpt-5" },
      kind: "primary",
      frame: JSON.stringify({ type: "response.create", input: `token ${secret}` }),
    }
    await mock.hooks["experimental.ws.send"]!(wsSend)
    expect(wsSend.frame as string).not.toContain(secret)
    const wsPh = /\{\{API_KEY_[a-z2-7]{8}\}\}/.exec(wsSend.frame as string)![0]

    const wsRecv1: Record<string, unknown> = {
      sessionID: "ses_ws",
      agent: "build",
      model: { providerID: "openai", id: "gpt-5" },
      kind: "primary",
      frame: JSON.stringify({ type: "response.output_text.delta", item_id: "i1", delta: wsPh.slice(0, 8) }),
    }
    const wsRecv2: Record<string, unknown> = {
      sessionID: "ses_ws",
      agent: "build",
      model: { providerID: "openai", id: "gpt-5" },
      kind: "primary",
      frame: JSON.stringify({ type: "response.output_text.delta", item_id: "i1", delta: wsPh.slice(8) }),
    }
    await mock.hooks["experimental.ws.receive"]!(wsRecv1)
    await mock.hooks["experimental.ws.receive"]!(wsRecv2)
    expect(JSON.parse(wsRecv1.frame as string).delta + JSON.parse(wsRecv2.frame as string).delta).toBe(secret)

    // 3. /redact Slash Command（resume 必须为 false，且 preview 不污染内存映射表）
    const cmd = mock.commands.redact!
    expect(cmd).toBeDefined()
    await cmd.execute({ sessionID: "ses_cmd", prompt: { text: "/redact status" }, delivery: "steer" })
    expect(mock.synthetics.at(-1)?.resume).toBe(false)
    expect(mock.synthetics.at(-1)?.text).toContain("opencode-redact 状态")

    await cmd.execute({
      sessionID: "ses_cmd",
      prompt: { text: "/redact preview 测试邮箱 preview_only@acme.cn" },
      delivery: "steer",
    })
    expect(mock.synthetics.at(-1)?.resume).toBe(false)
    expect(mock.synthetics.at(-1)?.text).toContain("{{EMAIL_")
    expect(mock.synthetics.at(-1)?.text).not.toContain("preview_only@acme.cn")

    await cmd.execute({ sessionID: "ses_cmd", prompt: { text: "/redact toggle" }, delivery: "steer" })
    expect(mock.synthetics.at(-1)?.text).toContain("已暂停")

    await cmd.execute({ sessionID: "ses_cmd", prompt: { text: "/redact recent" }, delivery: "steer" })
    expect(mock.synthetics.at(-1)?.text).toContain("BLOCKED")

    await cmd.execute({ sessionID: "ses_cmd", prompt: { text: "/redact clear" }, delivery: "steer" })
    expect(mock.synthetics.at(-1)?.text).toContain("已清空脱敏审计记录")

    await cleanup()
  })
})
