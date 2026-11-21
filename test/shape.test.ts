import { describe, expect, test } from "bun:test"
import { parseConfig, toMaskOptions } from "../src/config.js"
import { RedactEngine } from "../src/engine/engine.js"

const FIXED_KEY = new Uint8Array(32).fill(11)

describe("Format-Preserving 仿形与伪装", () => {
  test("shape=true 保留密钥前缀、长度、分隔符与字符类别，且确定性可逆", () => {
    const engine = makeEngine()
    const o = toMaskOptions(parseConfig({ shape: true }), { sent: false })
    const rawKey = "sk-ant-api03-AbCdEf123456-GhIjKl789012"
    const res1 = engine.mask(`ANTHROPIC_API_KEY=${rawKey}`, o)
    const res2 = engine.mask(`ANTHROPIC_API_KEY=${rawKey}`, o)

    expect(res1.text).toBe(res2.text)
    const fakeKey = res1.text.slice("ANTHROPIC_API_KEY=".length)
    expect(fakeKey).not.toBe(rawKey)
    expect(fakeKey.startsWith("sk-ant-api03-")).toBe(true)
    expect(fakeKey.length).toBe(rawKey.length)
    expect(fakeKey[rawKey.lastIndexOf("-")]).toBe("-")

    // 不对已经仿形的假 Key 二次脱敏
    const resAgain = engine.mask(`ANTHROPIC_API_KEY=${fakeKey}`, o)
    expect(resAgain.text).toBe(`ANTHROPIC_API_KEY=${fakeKey}`)

    // 响应还原
    expect(engine.restore(`使用密钥 ${fakeKey} 调用`)).toBe(`使用密钥 ${rawKey} 调用`)
  })

  test("USERNAME 伪登录名在大小写变化后仍可还原", () => {
    const engine = makeEngine()
    const o = toMaskOptions(parseConfig({ kinds: { home: true } }), { sent: false })
    const res = engine.mask("目录是 /Users/zhangsan/work", o)
    const m = /^目录是 \/Users\/([a-z]{8})\/work$/.exec(res.text)
    expect(m).not.toBeNull()
    const pseudo = m![1]!
    const capitalized = pseudo[0]!.toUpperCase() + pseudo.slice(1)
    expect(engine.restore(`Hi ${capitalized}, check /Users/${pseudo}`)).toBe("Hi zhangsan, check /Users/zhangsan")
  })

  test("公网 IP 伪主机名支持整词边界还原", () => {
    const engine = makeEngine()
    const o = toMaskOptions(parseConfig({ kinds: { ip: true } }), { sent: false })
    const res = engine.mask("ssh root@198.51.101.25", o)
    const m = /public-ip-[a-z]{8}/.exec(res.text)
    expect(m).not.toBeNull()
    const standIn = m![0]

    // 作为完整主机名（含端口、路径、大写）可还原；作为其他域名一部分不误还原
    expect(engine.restore(`ssh root@${standIn.toUpperCase()}:22`)).toBe("ssh root@198.51.101.25:22")
    expect(engine.restore(`host ${standIn}.lan and my-${standIn}`)).toBe(`host ${standIn}.lan and my-${standIn}`)
  })
})

function makeEngine() {
  return new RedactEngine({ key: FIXED_KEY })
}
