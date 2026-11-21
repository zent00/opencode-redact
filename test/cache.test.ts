import { describe, expect, test } from "bun:test"
import { parseConfig, toMaskOptions } from "../src/config.js"
import { RedactEngine } from "../src/engine/engine.js"

const FIXED_KEY = new Uint8Array(32).fill(45)

describe("已知值回溯、Prompt Cache 前缀稳定、ruleMemo 与 LRU 淘汰", () => {
  test("knownSpans：曾经通过赋值规则脱敏的值，在无上下文自由文本中也一致脱敏", () => {
    const engine = new RedactEngine({ key: FIXED_KEY })
    const o = toMaskOptions(parseConfig(), { sent: false })

    const r1 = engine.mask("DB_PASSWORD=UltraSecretPass99", o)
    const ph = r1.hits[0]!.placeholder
    const r2 = engine.mask("请把 UltraSecretPass99 写入配置", o)
    expect(r2.text).toBe(`请把 ${ph} 写入配置`)
  })

  test("sentKnownMemo：历史消息在同一路由保持前缀稳定，在新路由按新知识重新脱敏", () => {
    const engine = new RedactEngine({ key: FIXED_KEY })
    const historyText = "Earlier turn mentioned BareSecretVal99 without assignment."

    // Turn 1 在 routeA 发送：此时 BareSecretVal99 尚未成为 known，原样发送
    const t1 = engine.mask(historyText, toMaskOptions(parseConfig(), { route: "route-a", sent: true }))
    expect(t1.text).toBe(historyText)

    // Turn 2 新工具输出引入赋值，使 BareSecretVal99 成为 known
    const learn = engine.mask(
      "API_SECRET=BareSecretVal99",
      toMaskOptions(parseConfig(), { route: "route-a", sent: true }),
    )
    expect(learn.count).toBe(1)

    // Turn 2 重发同一历史消息到 routeA：必须保持原样以命中 Prompt Cache
    const t2SameRoute = engine.mask(historyText, toMaskOptions(parseConfig(), { route: "route-a", sent: true }))
    expect(t2SameRoute.text).toBe(historyText)

    // 发送到不同路由 routeB：应按最新 known 脱敏
    const t2OtherRoute = engine.mask(historyText, toMaskOptions(parseConfig(), { route: "route-b", sent: true }))
    expect(t2OtherRoute.text).toContain("{{SECRET_")
  })

  test("allowKeptMemo：新增白名单不影响同一路由已发送过的历史文本，仅对新文本生效", () => {
    const engine = new RedactEngine({ key: FIXED_KEY })
    const oldText = "Contact alice@acme.cn for invoice"
    const newText = "New turn: contact alice@acme.cn today"

    const first = engine.mask(oldText, toMaskOptions(parseConfig(), { route: "anthropic", sent: true }))
    expect(first.text).toContain("{{EMAIL_")

    // 中途把 alice@acme.cn 加入 allow
    const allowOpts = toMaskOptions(parseConfig({ allow: ["alice@acme.cn"] }), { route: "anthropic", sent: true })
    const replayOld = engine.mask(oldText, allowOpts)
    expect(replayOld.text).toBe(first.text) // 历史前缀不变

    const sendNew = engine.mask(newText, allowOpts)
    expect(sendNew.text).toBe(newText) // 新文本放行
  })

  test("ruleMemo：长文本重复扫描直接命中缓存，避免多轮历史 CPU 开销", () => {
    const engine = new RedactEngine({ key: FIXED_KEY })
    const o = toMaskOptions(parseConfig(), { sent: false })
    const longText = `${"这是一段普通的上下文日志内容，用于测试长文本规则缓存命中。".repeat(20)} sk-proj-AbCdEf1234567890GhIjKlMnOpQrStUv`
    expect(longText.length).toBeGreaterThanOrEqual(256)

    const r1 = engine.mask(longText, o)
    const r2 = engine.mask(longText, o)
    expect(r1.text).toBe(r2.text)
    expect(engine.store.ruleRuns).toBe(1)
  })

  test("LRU 淘汰：超过 maxValues 时淘汰最久未使用的一半，保留最近使用的映射", () => {
    const engine = new RedactEngine({ key: FIXED_KEY, maxValues: 4 })
    const o = toMaskOptions(parseConfig(), { sent: false })
    const keys = [
      "sk-proj-AAAAAAAAAAAAAAAAAAAA0001",
      "sk-proj-AAAAAAAAAAAAAAAAAAAA0002",
      "sk-proj-AAAAAAAAAAAAAAAAAAAA0003",
      "sk-proj-AAAAAAAAAAAAAAAAAAAA0004",
      "sk-proj-AAAAAAAAAAAAAAAAAAAA0005",
    ]
    const phs = keys.slice(0, 4).map((k) => engine.mask(k, o).hits[0]!.placeholder)
    // 再次触碰第 1 个，使其成为最新
    engine.mask(keys[0]!, o)
    // 插入第 5 个触发淘汰（应淘汰最老的 keys[1] 和 keys[2]，保留 keys[0]、keys[3]、keys[4]）
    const ph5 = engine.mask(keys[4]!, o).hits[0]!.placeholder

    expect(engine.store.getValue(phs[0]!)).toBe(keys[0])
    expect(engine.store.getValue(phs[3]!)).toBe(keys[3])
    expect(engine.store.getValue(ph5)).toBe(keys[4])
    expect(engine.store.getValue(phs[1]!)).toBeUndefined()
  })
})
