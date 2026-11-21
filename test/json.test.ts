import { describe, expect, test } from "bun:test"
import { parseConfig, toMaskOptions } from "../src/config.js"
import { RedactEngine } from "../src/engine/engine.js"

const FIXED_KEY = new Uint8Array(32).fill(21)

describe("协议感知 JSON 脱敏（kept / defs / signed / args）", () => {
  test("保留协议字段与 ID，定义区仅脱敏 description", () => {
    const engine = new RedactEngine({ key: FIXED_KEY })
    const o = toMaskOptions(parseConfig({ words: ["secretword"] }), { sent: false })

    const body = JSON.stringify({
      model: "secretword-model",
      tool_call_id: "call_4532015112830366",
      tools: [
        {
          type: "function",
          function: {
            name: "secretword_tool",
            description: "Call secretword endpoint with alice@acme.cn",
            parameters: {
              type: "object",
              properties: {
                secretword_param: { type: "string", description: "owner alice@acme.cn" },
              },
            },
          },
        },
      ],
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: "hi secretword" },
            { type: "image_url", image_url: { url: "data:image/png;base64,secretword123456" } },
          ],
        },
      ],
    })

    const res = engine.maskJSON(body, o)
    const parsed = JSON.parse(res.text)
    expect(parsed.model).toBe("secretword-model")
    expect(parsed.tool_call_id).toBe("call_4532015112830366")
    expect(parsed.tools[0].function.name).toBe("secretword_tool")
    expect(parsed.tools[0].function.parameters.properties).toHaveProperty("secretword_param")
    expect(parsed.tools[0].function.description).toContain("{{TERM_")
    expect(parsed.tools[0].function.description).toContain("{{EMAIL_")
    expect(parsed.messages[0].content[1].image_url.url).toBe("data:image/png;base64,secretword123456")
  })

  test("签名思考块（Anthropic thinking.signature）不运行常规规则，仅回填已知映射", () => {
    const engine = new RedactEngine({ key: FIXED_KEY })
    const o = toMaskOptions(parseConfig(), { sent: false })
    const realKey = "sk-proj-AbCdEf1234567890GhIjKlMnOpQrStUv"

    const body = JSON.stringify({
      messages: [
        { role: "user", content: `My key is ${realKey}` },
        {
          role: "assistant",
          content: [
            {
              type: "thinking",
              // 模型思考中带回了 realKey（应回填占位符），也自造了一个邮箱（不应被规则改写破坏签名）
              thinking: `The key ${realKey} was provided, maybe notify demo@corp.cn`,
              signature: "Ev0BCkYICxgCKkBsignatureBase64Value",
            },
            { type: "text", text: "Done." },
          ],
        },
      ],
    })

    const res = engine.maskJSON(body, o)
    const parsed = JSON.parse(res.text)
    const thinking = parsed.messages[1].content[0]
    expect(thinking.signature).toBe("Ev0BCkYICxgCKkBsignatureBase64Value")
    expect(thinking.thinking).not.toContain(realKey)
    expect(thinking.thinking).toContain("{{API_KEY_")
    // 签名块内未在正文脱敏过的邮箱保持原样，不破坏上游签名
    expect(thinking.thinking).toContain("demo@corp.cn")
  })

  test("工具调用参数：namedSecret 按字段名识密，且嵌套 JSON 转义与引号边界保持合法 JSON", () => {
    const engine = new RedactEngine({ key: FIXED_KEY })
    const o = toMaskOptions(parseConfig({ rules: [{ kind: "TOK", regex: "tok-\\S+" }] }), { sent: false })

    const body = JSON.stringify({
      messages: [
        {
          role: "assistant",
          content: [
            {
              type: "tool_use",
              id: "toolu_01",
              name: "call_api",
              input: {
                api_key: "opaque-custom-credential-xyz",
                url: "https://internal.example",
              },
            },
          ],
          tool_calls: [
            {
              id: "call_1",
              type: "function",
              function: {
                name: "run_shell",
                // 包含 \n 后紧跟邮箱与匹配到引号结尾的自定义正则
                arguments: JSON.stringify({
                  cmd: "echo hello\nzoe@acme.cn && curl -H tok-abcdef1234",
                }),
              },
            },
          ],
        },
      ],
    })

    const res = engine.maskJSON(body, o)
    const parsed = JSON.parse(res.text)

    // tool_use.input 下的 api_key 被按字段名脱敏
    expect(parsed.messages[0].content[0].input.api_key).toMatch(/^\{\{SECRET_[a-z2-7]{8}\}\}$/)

    // function.arguments 仍是合法 JSON，且 \n 与结尾引号均未被破坏
    const rawArgs = parsed.messages[0].tool_calls[0].function.arguments
    const argsObj = JSON.parse(rawArgs)
    expect(argsObj.cmd).toContain("echo hello\n{{EMAIL_")
    expect(argsObj.cmd).toContain("{{TOK_")
    expect(argsObj.cmd).not.toContain("zoe@acme.cn")

    // RestoreJSON 完整还原且保持嵌套 JSON 合法
    const restored = JSON.parse(engine.restoreJSON(res.text))
    expect(restored.messages[0].content[0].input.api_key).toBe("opaque-custom-credential-xyz")
    expect(JSON.parse(restored.messages[0].tool_calls[0].function.arguments).cmd).toBe(
      "echo hello\nzoe@acme.cn && curl -H tok-abcdef1234",
    )
  })
})
