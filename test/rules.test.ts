import { describe, expect, test } from "bun:test"
import crypto from "node:crypto"
import { parseConfig, toMaskOptions } from "../src/config.js"
import { RedactEngine } from "../src/engine/engine.js"

const FIXED_KEY = new Uint8Array(32).fill(7)
const FIXED_NOW = () => new Date("2026-11-21T12:00:00Z")

function makeEngine() {
  return new RedactEngine({ key: FIXED_KEY })
}

function opts(overrides: Parameters<typeof parseConfig>[0] = {}) {
  return toMaskOptions(parseConfig(overrides), { now: FIXED_NOW, sent: false })
}

// 辅助生成合法 Base58Check（供 Bitcoin WIF / BIP32 测试用）
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
function encodeBase58Check(payload: Buffer): string {
  const h1 = crypto.createHash("sha256").update(payload).digest()
  const h2 = crypto.createHash("sha256").update(h1).digest()
  const full = Buffer.concat([payload, h2.subarray(0, 4)])
  let n = BigInt(`0x${full.toString("hex")}`)
  let out = ""
  while (n > 0n) {
    out = B58[Number(n % 58n)]! + out
    n /= 58n
  }
  for (const byte of full) {
    if (byte === 0) out = `1${out}`
    else break
  }
  return out
}

function encodeBase58Raw(buf: Buffer): string {
  let n = BigInt(`0x${buf.toString("hex")}`)
  let out = ""
  while (n > 0n) {
    out = B58[Number(n % 58n)]! + out
    n /= 58n
  }
  for (const byte of buf) {
    if (byte === 0) out = `1${out}`
    else break
  }
  return out
}

function crc16XModem(buf: Uint8Array): number {
  let c = 0
  for (const x of buf) {
    c ^= x << 8
    for (let i = 0; i < 8; i++) {
      c = (c & 0x8000) !== 0 ? ((c << 1) ^ 0x1021) & 0xffff : (c << 1) & 0xffff
    }
  }
  return c
}

function encodeBase32(buf: Uint8Array): string {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  let bits = 0
  let val = 0
  let out = ""
  for (const b of buf) {
    val = (val << 8) | b
    bits += 8
    while (bits >= 5) {
      out += A[(val >>> (bits - 5)) & 31]!
      bits -= 5
    }
  }
  if (bits > 0) out += A[(val << (5 - bits)) & 31]!
  return out
}

describe("内置 Secrets 规则与防误报", () => {
  test("常见 API Key、私钥、JWT、URL 密码、Header 与 CJK 语境", () => {
    const engine = makeEngine()
    const samples = [
      ["OpenAI", "key=sk-proj-AbCdEf1234567890GhIjKlMnOpQrStUv", "API_KEY"],
      ["GitHub", "token ghp_1234567890abcdefghijklmnopqrstuvwx", "API_KEY"],
      ["AWS", "AKIAIOSFODNN7EXAMPLE", "API_KEY"],
      ["Ark", "ark-Ab12Cd34Ef56Gh78Ij90", "API_KEY"],
      ["Cloudflare", `cfut_${"aB12".repeat(11)}`, "API_KEY"],
      ["JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV", "TOKEN"],
      ["PEM", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA123456\n-----END RSA PRIVATE KEY-----", "PRIVATE_KEY"],
      ["URL密码", "postgres://app:Sup3rS3cret!@db.acme.internal:5432/prod", "PASSWORD"],
      ["环境变量", "DB_PASSWORD=MyRealPass2026", "SECRET"],
      ["大写后缀", "SERVICE_X_KEY=Ab12Cd34Ef56", "SECRET"],
      ["Auth头", "Authorization: Bearer tok_9876543210abcdef", "SECRET"],
      ["中文密码", "登录密码：Hunter2026!", "PASSWORD"],
      ["中文密钥", "我们的密钥为 12231241，请妥善保管", "SECRET"],
      ["中英混排", "apikey 是 Ab12Cd34Ef56Gh", "SECRET"],
    ] as const

    for (const [label, input, expectedKind] of samples) {
      const res = engine.mask(input, opts())
      expect(res.count, `${label} 应命中脱敏`).toBeGreaterThanOrEqual(1)
      expect(
        res.hits.some((h) => h.kind === expectedKind),
        `${label} 类型应为 ${expectedKind}`,
      ).toBe(true)
      expect(engine.restore(res.text)).toBe(input)
    }
  })

  test("防误报：slug、代码标识符、行号引用、路径、版本号、时间戳、空赋值连写、同值 URL 密码", () => {
    const engine = makeEngine()
    const cleanInputs = [
      "https://cnbc.com/2026/sk-hynix-third-quarter-profit-record.html",
      "internal/auth/token.go:L643-669.",
      "PRIVATE_KEY_PATH=~/.ssh/id_ed25519",
      "const access_token = get_access_token_v2",
      "secretKey: Uint8Array;",
      "privateKey: toBase64Url(raw)",
      '"jsonwebtoken": "9.2.0-beta1"',
      '"access_token_expires_at": "2026-08-30T11:44:31.312645+08:00"',
      "SORT_KEY=abc123456",
      "密钥为 2048 位，令牌 300000 毫秒",
      "postgresql://geodatafusion:geodatafusion@127.0.0.1:55432/geodatafusion",
      "env -i UI_PASSWORD= UI_ADDR=127.0.0.1:39117 ./syncer serve",
      "design-tokens:generate-v2",
      "element_token: s0000002a:14",
      '{"id": "550e8400-e29b-41d4-a716-446655440000", "timestamp": 17929036837}',
    ]
    for (const text of cleanInputs) {
      const res = engine.mask(text, opts())
      expect(res.text, `不应误脱敏: ${text}`).toBe(text)
    }

    // 空赋值后紧跟真实密钥应只脱敏后面的密钥
    const chained = engine.mask("UI_PASSWORD= UI_TOKEN=t0k3nValue2", opts())
    expect(chained.text).toContain("UI_PASSWORD= UI_TOKEN={{SECRET_")
    expect(chained.text).not.toContain("t0k3nValue2")
    expect(engine.restore(chained.text)).toBe("UI_PASSWORD= UI_TOKEN=t0k3nValue2")
  })
})

describe("Personal 规则与细分分类开关", () => {
  test("Email、中国身份证、手机号与订单号区分、银行卡 Luhn", () => {
    const engine = makeEngine()
    const email = engine.mask("请联系 alice.wang@acme.cn.", opts())
    expect(email.text).toMatch(/请联系 \{\{EMAIL_[a-z2-7]{8}\}\}\.$/)
    expect(engine.restore(email.text)).toBe("请联系 alice.wang@acme.cn.")

    // 非邮箱防误报
    for (const nonEmail of [
      "git@github.com:org/repo.git",
      "261020_14-16-11@2x.jpg",
      "ref xxx@AGENTS.md",
      "call system@plt",
      "test@example.com",
      "x@pytest.fixture",
    ]) {
      expect(engine.mask(nonEmail, opts()).text, `非邮箱不应脱敏: ${nonEmail}`).toBe(nonEmail)
    }

    // 中国合法 18 位身份证号（校验码 11010519491231002X）
    const idRes = engine.mask("身份证号 11010519491231002X", opts())
    expect(idRes.text).toContain("{{ID_CARD_")
    expect(engine.mask("无效身份证 110105194912310029", opts()).text).toBe("无效身份证 110105194912310029")

    // 手机号 vs 订单号 / 小数 / JSON 裸数字（用不同号码测试规则本身，避免被前面已记住的 knownSpans 命中）
    const phoneRes = engine.mask("我的手机号是 13800138000", opts())
    expect(phoneRes.text).toContain("{{PHONE_")
    expect(engine.mask("订单号 13912345678 已发货", opts()).text).toBe("订单号 13912345678 已发货")
    expect(engine.mask('{"order_id": "13800138001"}', opts()).text).toBe('{"order_id": "13800138001"}')
    expect(engine.mask('{"phone": "13800138002"}', opts()).text).toContain("{{PHONE_")
    expect(engine.mask("score is 5.13800138003", opts()).text).toBe("score is 5.13800138003")

    // 合法 Luhn 银行卡（4532015112830366）
    const cardRes = engine.mask("卡号 4532 0151 1283 0366", opts())
    expect(cardRes.text).toContain("{{BANK_CARD_")
  })

  test("可选分类：SSN、护照、IBAN、生日、MAC、序列号、Home、User@Host、公网 IP、Bucket", () => {
    const engine = makeEngine()
    // 默认开启的分类（123-45-6789 是文档示例假号应放行，真实范围号码应脱敏）
    expect(engine.mask("SSN: 123-45-6789", opts()).text).toBe("SSN: 123-45-6789")
    expect(engine.mask("SSN: 123-45-6788", opts()).text).toContain("{{SSN_")
    expect(engine.mask("护照号：E12345678", opts()).text).toContain("{{PASSPORT_")
    const iban = engine.mask("Pay DE89 3704 0044 0532 0130 00 THEN confirm", opts())
    expect(iban.text).toMatch(/Pay \{\{IBAN_[a-z2-7]{8}\}\} THEN confirm/)
    expect(engine.mask("生日：1992-08-15", opts()).text).toContain("{{BIRTHDAY_")
    // 一年内的日期不是生日
    expect(engine.mask("生日：2026-10-01", opts()).text).toBe("生日：2026-10-01")
    expect(engine.mask("mac a4:5e:60:c1:2b:3f", opts()).text).toContain("{{MAC_")
    expect(engine.mask("mac 00:00:00:00:00:00", opts()).text).toBe("mac 00:00:00:00:00:00")
    expect(engine.mask("S/N: C02Z91ABC123", opts()).text).toContain("{{SERIAL_")

    // 默认关闭的分类（home/userhost/ip/bucket）关闭时不脱敏，开启后脱敏
    expect(engine.mask("/home/alice/project", opts()).text).toBe("/home/alice/project")
    const homeOn = engine.mask("/home/alice/project", opts({ kinds: { home: true } }))
    expect(homeOn.text).not.toContain("alice")
    expect(homeOn.text).toMatch(/^\/home\/[a-z]{8}\/project$/)
    expect(engine.restore(homeOn.text)).toBe("/home/alice/project")

    const userHostOn = engine.mask("ssh alice@prod-box.corp.internal", opts({ kinds: { userhost: true } }))
    expect(userHostOn.text).not.toContain("alice")
    expect(userHostOn.text).not.toContain("prod-box.corp.internal")
    expect(engine.restore(userHostOn.text)).toBe("ssh alice@prod-box.corp.internal")
    // pnpm-lock.yaml 包版本不误报
    expect(engine.mask("js-tokens@4.0.0:", opts({ kinds: { userhost: true } })).text).toBe("js-tokens@4.0.0:")

    const ipOn = engine.mask(
      "connect 203.0.114.42 and 192.168.1.1 and 8.8.8.8 and version 1.2.3.4",
      opts({ kinds: { ip: true } }),
    )
    expect(ipOn.text).toMatch(/connect public-ip-[a-z]{8} and 192\.168\.1\.1 and 8\.8\.8\.8 and version 1\.2\.3\.4/)
    expect(engine.restore(ipOn.text)).toBe("connect 203.0.114.42 and 192.168.1.1 and 8.8.8.8 and version 1.2.3.4")

    const bucketOn = engine.mask(
      "upload to s3://acme-prod-archive/data and s3://my-bucket/demo",
      opts({ kinds: { bucket: true } }),
    )
    expect(bucketOn.text).toContain("s3://{{BUCKET_")
    expect(bucketOn.text).toContain("s3://my-bucket/demo")
  })
})

describe("Crypto 钱包私钥与助记词规则", () => {
  test("EVM、Bitcoin WIF、Solana Key/Keypair、Stellar、Sui、Aptos、Nostr、Age 与 BIP-0039 助记词", () => {
    const engine = makeEngine()

    // 1. EVM 私钥（命令行 flag / new Wallet 触发 WALLET_KEY，tx hash 不命中）
    const evmHex = `0x${"ab12cd34".repeat(8)}`
    expect(engine.mask(`cast send --private-key ${evmHex}`, opts()).text).toContain("{{WALLET_KEY_")
    expect(engine.mask(`wallet tx hash 0x${"cd34ef56".repeat(8)}`, opts()).text).toBe(
      `wallet tx hash 0x${"cd34ef56".repeat(8)}`,
    )

    // 2. Bitcoin WIF（真实 Base58Check 校验通过）
    const wif = encodeBase58Check(Buffer.concat([Buffer.from([0x80]), Buffer.alloc(32, 0x11), Buffer.from([0x01])]))
    const wifRes = engine.mask(`wif=${wif}`, opts())
    expect(wifRes.text).toContain("{{WIF_KEY_")
    expect(engine.restore(wifRes.text)).toBe(`wif=${wif}`)

    // 3. Solana Ed25519 私钥 + 64 字节 JSON Keypair（真实 Ed25519 派生）
    const seed = Buffer.alloc(32, 0x22)
    const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex")
    const priv = crypto.createPrivateKey({ key: Buffer.concat([pkcs8Prefix, seed]), format: "der", type: "pkcs8" })
    const pubDer = crypto.createPublicKey(priv).export({ format: "der", type: "spki" }) as Buffer
    const solBytes = Buffer.concat([seed, pubDer.subarray(pubDer.length - 32)])
    const solB58 = encodeBase58Raw(solBytes)
    expect(engine.mask(`sol ${solB58}`, opts()).text).toContain("{{SOLANA_KEY_")
    const solJson = `[${[...solBytes].join(",")}]`
    expect(engine.mask(`keyfile: ${solJson}`, opts()).text).toContain("{{SOLANA_KEYPAIR_")

    // 4. Stellar Seed（CRC16-XModem）
    const stellarPayload = Buffer.concat([Buffer.from([18 << 3]), Buffer.alloc(32, 0x33)])
    const crc = crc16XModem(stellarPayload)
    const stellarSeed = encodeBase32(Buffer.concat([stellarPayload, Buffer.from([crc & 0xff, (crc >>> 8) & 0xff])]))
    expect(engine.mask(`stellar ${stellarSeed}`, opts()).text).toContain("{{STELLAR_KEY_")

    // 5. 固定前缀链私钥
    expect(engine.mask(`suiprivkey1${"a".repeat(58)}`, opts()).text).toContain("{{SUI_KEY_")
    expect(engine.mask(`ed25519-priv-0x${"a1".repeat(32)}`, opts()).text).toContain("{{APTOS_KEY_")
    expect(engine.mask(`nsec1${"q".repeat(58)}`, opts()).text).toContain("{{NOSTR_KEY_")
    expect(engine.mask(`AGE-SECRET-KEY-1${"A".repeat(58)}`, opts()).text).toContain("{{AGE_KEY_")

    // 6. BIP-0039 助记词（合法 12 词命中，普通句子不命中）
    const mnemonic = "abandon ability able about above absent absorb abstract absurd abuse access accident"
    const seedRes = engine.mask(`我的助记词：${mnemonic} 请保管`, opts())
    expect(seedRes.text).toMatch(/我的助记词：\{\{SEED_PHRASE_[a-z2-7]{8}\}\} 请保管/)
    expect(engine.restore(seedRes.text)).toBe(`我的助记词：${mnemonic} 请保管`)
    expect(engine.mask("recovery plan for the server is ready to execute soon in prod", opts()).text).toBe(
      "recovery plan for the server is ready to execute soon in prod",
    )
  })
})

describe("自定义词表、日期等价、自定义规则、Allow 与 Actions", () => {
  test("日期型自定义词匹配多种日期格式", () => {
    const engine = makeEngine()
    const o = opts({ words: ["1990-05-12"], personal: false, secrets: false })
    for (const form of ["1990-05-12", "1990/5/12", "1990年5月12日", "19900512", "May 12, 1990", "12 May 1990"]) {
      const res = engine.mask(`日期是 ${form}。`, o)
      expect(res.text, `应匹配日期形式: ${form}`).toMatch(/日期是 \{\{TERM_[a-z2-7]{8}\}\}。/)
      expect(engine.restore(res.text)).toBe(`日期是 ${form}。`)
    }
    // 版本号不误命中日期词
    expect(engine.mask("version 1990.5.12.1", o).text).toBe("version 1990.5.12.1")
  })

  test("整词/大小写、自定义规则、Allow 优先级与 Warn/Block 动作", () => {
    const engine = makeEngine()
    const whole = engine.mask(
      "XABC ABC 用ABC做",
      opts({ words: ["ABC"], wordsWhole: true, secrets: false, personal: false }),
    )
    expect(whole.text).toMatch(/^XABC \{\{TERM_[a-z2-7]{8}\}\} 用\{\{TERM_[a-z2-7]{8}\}\}做$/)

    // 自定义前缀规则与正则规则（含 group 1）
    const custom = engine.mask(
      "tok=corp_tok_AbCdEf123456 and badge=EMP-998877",
      opts({
        rules: [
          { kind: "CORP_TOKEN", prefix: "corp_tok_" },
          { kind: "BADGE", regex: "badge=(EMP-\\d{6})" },
        ],
      }),
    )
    expect(custom.text).toContain("{{CORP_TOKEN_")
    expect(custom.text).toContain("badge={{BADGE_")
    expect(engine.restore(custom.text)).toBe("tok=corp_tok_AbCdEf123456 and badge=EMP-998877")

    // Allow 放行规则命中，但用户显式 words 优先级高于 Allow
    const allowRes = engine.mask("public@acme.io and alice@acme.io", opts({ allow: ["public@acme.io"] }))
    expect(allowRes.text).toStartWith("public@acme.io and {{EMAIL_")

    const wordWins = engine.mask("public@acme.io", opts({ allow: ["public@acme.io"], words: ["public@acme.io"] }))
    expect(wordWins.text).toContain("{{TERM_")

    // warn 放行明文并记录告警；block 标记 blocked
    const warnRes = engine.mask("mail alice@acme.io", opts({ actions: { EMAIL: "warn" } }))
    expect(warnRes.text).toBe("mail alice@acme.io")
    expect(warnRes.count).toBe(0)
    expect(warnRes.hits).toHaveLength(1)
    expect(warnRes.hits[0]?.action).toBe("warn")

    const blockRes = engine.mask(
      "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADAN\n-----END PRIVATE KEY-----",
      opts({ actions: { PRIVATE_KEY: "block" } }),
    )
    expect(blockRes.blocked?.kind).toBe("PRIVATE_KEY")
    expect(blockRes.blocked?.action).toBe("block")
  })
})
