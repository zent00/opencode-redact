import { describe, expect, test } from "bun:test"
import { parseConfig, toMaskOptions } from "../src/config.js"
import { RedactEngine } from "../src/engine/engine.js"
import { SSERestorer, WebSocketFrameRestorer, wrapHttpResponse } from "../src/engine/stream.js"

const FIXED_KEY = new Uint8Array(32).fill(33)

describe("SSE 与 WebSocket 流式还原", () => {
  test("跨多个 SSE 事件切分占位符 + 中途穿插 ping/注释心跳仍完整还原", () => {
    const engine = new RedactEngine({ key: FIXED_KEY })
    const o = toMaskOptions(parseConfig(), { sent: false })
    const realKey = "sk-proj-AbCdEf1234567890GhIjKlMnOpQrStUv"
    const masked = engine.mask(`key=${realKey}`, o)
    const placeholder = masked.hits[0]!.placeholder // {{API_KEY_xxxxxxxx}}

    const p1 = placeholder.slice(0, 6) // {{API_
    const p2 = placeholder.slice(6, 14) // KEY_xxxx
    const p3 = placeholder.slice(14) // xxxx}}

    const sse = new SSERestorer(engine)
    let combined = ""
    combined += sse.push(
      `event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Result: ${p1}"}}\n\n`,
    )
    // 中途心跳注释与 ping 事件必须直通且不能打断 pending
    const keepalive = sse.push(`: keepalive\n\nevent: ping\ndata: {"type":"ping"}\n\n`)
    expect(keepalive).toContain(": keepalive")
    expect(keepalive).toContain('"type":"ping"')
    combined += keepalive
    combined += sse.push(
      `event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"${p2}"}}\n\n`,
    )
    combined += sse.push(
      `event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"${p3}!"}}\n\n`,
    )
    combined += sse.finish()

    // 拼接所有 text_delta 的 text，必须精确还原为原始密钥
    const texts: string[] = []
    for (const line of combined.split("\n")) {
      if (!line.startsWith("data: ")) continue
      const obj = JSON.parse(line.slice(6))
      if (obj.delta?.text) texts.push(obj.delta.text)
    }
    expect(texts.join("")).toBe(`Result: ${realKey}!`)
    expect(sse.restoredCounts.get(placeholder)).toBe(1)
  })

  test("容错还原（丢失花括号/插入空格/改大小写）与工具参数 JSON 二次转义", () => {
    const engine = new RedactEngine({ key: FIXED_KEY })
    const o = toMaskOptions(parseConfig({ words: ['pass"with\nquote'] }), { sent: false })
    const masked = engine.mask('my secret pass"with\nquote', o)
    const ph = masked.hits[0]!.placeholder
    const body = ph.slice(2, -2) // TERM_xxxxxxxx

    // 模型改了格式：空格 + 大写 + 去括号
    expect(engine.restore(`a={{ ${body.toUpperCase()} }} b=${body.toLowerCase()} c={${body}}`)).toBe(
      'a=pass"with\nquote b=pass"with\nquote c=pass"with\nquote',
    )

    // 工具参数流式分片：还原带引号和换行符的值时必须做 JSON 转义
    const sse = new SSERestorer(engine)
    const ev =
      `event: content_block_delta\n` +
      `data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"pw\\":\\"${ph}\\"}"}}\n\n`
    const out = sse.push(ev) + sse.finish()
    const dataLine = out.split("\n").find((l) => l.startsWith("data: "))!
    const parsedEvent = JSON.parse(dataLine.slice(6))
    const parsedArgs = JSON.parse(parsedEvent.delta.partial_json)
    expect(parsedArgs.pw).toBe('pass"with\nquote')
  })

  test("wrapHttpResponse 支持 SSE 流、整包 JSON 与二进制直通", async () => {
    const engine = new RedactEngine({ key: FIXED_KEY })
    const o = toMaskOptions(parseConfig(), { sent: false })
    const email = "bob@acme.cn"
    const ph = engine.mask(email, o).hits[0]!.placeholder

    // 1. 整包 JSON
    let restoredTotal = 0
    const jsonResp = new Response(JSON.stringify({ choices: [{ message: { content: `Hi ${ph}` } }] }), {
      headers: { "content-type": "application/json", "content-length": "999" },
    })
    const wrappedJson = wrapHttpResponse(engine, jsonResp, (counts) => {
      for (const n of counts.values()) restoredTotal += n
    })
    expect(wrappedJson.headers.has("content-length")).toBe(false)
    const parsed = await wrappedJson.json()
    expect(parsed.choices[0].message.content).toBe(`Hi ${email}`)
    expect(restoredTotal).toBe(1)

    // 2. 二进制流直接透传不被包装
    const binResp = new Response(new Uint8Array([1, 2, 3, 4]), {
      headers: { "content-type": "image/png" },
    })
    expect(wrapHttpResponse(engine, binResp)).toBe(binResp)
  })

  test("WebSocketFrameRestorer 支持跨帧拼接截断占位符", () => {
    const engine = new RedactEngine({ key: FIXED_KEY })
    const o = toMaskOptions(parseConfig(), { sent: false })
    const secret = "ghp_1234567890abcdefghijklmnopqrstuvwx"
    const ph = engine.mask(secret, o).hits[0]!.placeholder

    const ws = new WebSocketFrameRestorer(engine)
    const counts = new Map<string, number>()
    const f1 = ws.restoreFrame(
      JSON.stringify({ type: "response.output_text.delta", item_id: "item_1", delta: `Token: ${ph.slice(0, 7)}` }),
      counts,
    )
    const f2 = ws.restoreFrame(
      JSON.stringify({ type: "response.output_text.delta", item_id: "item_1", delta: `${ph.slice(7)}!` }),
      counts,
    )
    const d1 = JSON.parse(f1).delta
    const d2 = JSON.parse(f2).delta
    expect(d1 + d2).toBe(`Token: ${secret}!`)
    expect(counts.get(ph)).toBe(1)
  })
})
