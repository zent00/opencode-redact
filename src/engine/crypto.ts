// 加密货币钱包私钥与助记词脱敏规则（借鉴 Magpie internal/redact/crypto.go）。
// 支持 EVM、Bitcoin WIF(Base58Check)、BIP-0032 xprv、Solana(Ed25519 派生校验)、NEAR、Sui、Aptos、
// Stellar(CRC16-XModem)、Nostr、age、Zcash 以及 BIP-0039 助记词校验。
import crypto from "node:crypto"
import { BIP39_ENGLISH } from "./bip39english.js"
import { ALNUM, type CompiledRule } from "./types.js"
import { isAsciiLetter, lowerASCII } from "./validators.js"

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
const B58_INDEX = new Int8Array(256).fill(-1)
for (let i = 0; i < B58_ALPHABET.length; i++) {
  B58_INDEX[B58_ALPHABET.charCodeAt(i)] = i
}

function decodeBase58(s: string): Buffer | undefined {
  let n = 0n
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    const d = code < 256 ? B58_INDEX[code]! : -1
    if (d < 0) return undefined
    n = n * 58n + BigInt(d)
  }
  let zeros = 0
  while (zeros < s.length && s[zeros] === "1") zeros++
  const hex = n === 0n ? "" : n.toString(16)
  const paddedHex = hex.length % 2 === 1 ? `0${hex}` : hex
  const body = paddedHex ? Buffer.from(paddedHex, "hex") : Buffer.alloc(0)
  if (zeros === 0) return body
  return Buffer.concat([Buffer.alloc(zeros), body])
}

function decodeBase58Check(s: string): Buffer | undefined {
  const b = decodeBase58(s)
  if (!b || b.length < 5) return undefined
  const payload = b.subarray(0, b.length - 4)
  const checksum = b.subarray(b.length - 4)
  const h1 = crypto.createHash("sha256").update(payload).digest()
  const h2 = crypto.createHash("sha256").update(h1).digest()
  if (!h2.subarray(0, 4).equals(checksum)) return undefined
  return payload
}

export function isWifKey(v: string): boolean {
  if (v.length !== 51 && v.length !== 52) return false
  const p = decodeBase58Check(v)
  return p !== undefined && (p.length === 33 || (p.length === 34 && p[33] === 1))
}

export function isBip32Key(v: string): boolean {
  const p = decodeBase58Check(v)
  return p !== undefined && p.length === 78
}

// Ed25519 PKCS#8 DER 固定前缀（后接 32 字节 seed）
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex")

function isSeedAndPublic(b: Buffer | undefined): boolean {
  if (b?.length !== 64) return false
  try {
    const seed = b.subarray(0, 32)
    const expectedPub = b.subarray(32, 64)
    const priv = crypto.createPrivateKey({
      key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
      format: "der",
      type: "pkcs8",
    })
    const pubDer = crypto.createPublicKey(priv).export({ format: "der", type: "spki" }) as Buffer
    const derivedPub = pubDer.subarray(pubDer.length - 32)
    return derivedPub.equals(expectedPub)
  } catch {
    return false
  }
}

export function isSolanaKey(v: string): boolean {
  if (v.length < 85 || v.length > 88) return false
  return isSeedAndPublic(decodeBase58(v))
}

export function isSolanaKeypair(v: string): boolean {
  const inner = v.replace(/^\[|\]$/g, "").trim()
  const parts = inner.split(",")
  if (parts.length !== 64) return false
  const buf = Buffer.alloc(64)
  for (let i = 0; i < 64; i++) {
    const t = parts[i]!.trim()
    if (!/^\d{1,3}$/.test(t)) return false
    const n = Number(t)
    if (n > 255) return false
    buf[i] = n
  }
  return isSeedAndPublic(buf)
}

function decodeBase32NoPad(s: string): Buffer | undefined {
  let bits = 0
  let value = 0
  const out: number[] = []
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    let idx: number
    if (c >= 65 && c <= 90) idx = c - 65
    else if (c >= 50 && c <= 55) idx = c - 50 + 26
    else return undefined
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return Buffer.from(out)
}

function crc16XModem(buf: Uint8Array): number {
  let c = 0
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i]! << 8
    for (let bit = 0; bit < 8; bit++) {
      if ((c & 0x8000) !== 0) {
        c = ((c << 1) ^ 0x1021) & 0xffff
      } else {
        c = (c << 1) & 0xffff
      }
    }
  }
  return c
}

export function isStellarSeed(v: string): boolean {
  const b = decodeBase32NoPad(v)
  if (b?.length !== 35 || b[0] !== 18 << 3) return false
  const crc = crc16XModem(b.subarray(0, 33))
  return b[33] === (crc & 0xff) && b[34] === ((crc >>> 8) & 0xff)
}

const WALLET_KEY_CUES = [
  "priv",
  "secret",
  "signer",
  "signing",
  "deployer",
  "wallet",
  "pk",
  "私钥",
  "私鑰",
  "秘密鍵",
  "개인키",
  "비밀키",
]

const NOT_KEY_WORDS = ["hash", "sha", "digest", "sum", "pub", "addr", "tx", "fingerprint", "id"]

function walletKeyAt(s: string, a: number): boolean {
  let start = Math.max(0, a - 48)
  const nl = s.slice(start, a).lastIndexOf("\n")
  if (nl >= 0) start += nl + 1
  const before = lowerASCII(s.slice(start, a))
  let cue = -1
  let end = 0
  for (const c of WALLET_KEY_CUES) {
    for (let i = 0; ; ) {
      const j = before.indexOf(c, i)
      if (j < 0) break
      const next = j + c.length
      i = next
      if (
        c === "pk" &&
        ((j > 0 && isAsciiLetter(before[j - 1])) || (next < before.length && isAsciiLetter(before[next])))
      ) {
        continue
      }
      if (j > cue) {
        cue = j
        end = next
      }
    }
  }
  if (cue < 0) return false
  const between = before.slice(end)
  for (const w of NOT_KEY_WORDS) {
    if (w === "id") {
      const trimmed = between.replace(/^[_ -]+/, "")
      if (trimmed.startsWith("id") && (trimmed.length === 2 || !isAsciiLetter(trimmed[2]))) return false
      continue
    }
    if (between.includes(w)) return false
  }
  return true
}

const SEED_CUES = [
  "seed",
  "mnemonic",
  "phrase",
  "recovery",
  "助记词",
  "助記詞",
  "シード",
  "ニーモニック",
  "시드",
  "니모닉",
]
const PHRASE_LENGTHS = [25, 24, 21, 18, 15, 12]

function seedPhraseAt(s: string, a: number, b: number): readonly [number, number, boolean] {
  let bestA = 0
  let bestN = 0
  let bestEnd = 0
  let runA = -1
  let runN = 0
  const ends: number[] = []
  let i = a
  while (i < b) {
    while (i < b && (s[i] === " " || s[i] === "\t")) i++
    let j = i
    while (j < b && s[j] !== " " && s[j] !== "\t") j++
    if (i === j) break
    if (BIP39_ENGLISH.has(s.slice(i, j).toLowerCase())) {
      if (runA < 0) {
        runA = i
        runN = 0
        ends.length = 0
      }
      runN++
      ends.push(j)
      if (runN > bestN) {
        bestA = runA
        bestN = runN
        bestEnd = j
        for (const l of PHRASE_LENGTHS) {
          if (runN >= l) {
            bestEnd = ends[l - 1]!
            break
          }
        }
      }
    } else {
      runA = -1
    }
    i = j
  }
  if (bestN < 12) return [0, 0, false]
  return [bestA, bestEnd, true]
}

function hasBase58Run(n: number): (s: string) => boolean {
  return (s: string) => {
    let run = 0
    for (let i = 0; i < s.length; i++) {
      const code = s.charCodeAt(i)
      if (code < 256 && B58_INDEX[code]! >= 0) {
        if (++run >= n) return true
      } else {
        run = 0
      }
    }
    return false
  }
}

function hasBase32Run(n: number): (s: string) => boolean {
  return (s: string) => {
    let run = 0
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i)
      if ((c >= 65 && c <= 90) || (c >= 50 && c <= 55)) {
        if (++run >= n) return true
      } else {
        run = 0
      }
    }
    return false
  }
}

export const CRYPTO_RULES: readonly CompiledRule[] = [
  {
    kind: "WALLET_KEY",
    fold: WALLET_KEY_CUES,
    back: 64,
    ahead: 160,
    bound: ALNUM,
    at: walletKeyAt,
    re: /0x[0-9a-fA-F]{56,64}|[0-9a-fA-F]{64}/dg,
  },
  {
    kind: "WIF_KEY",
    bound: ALNUM,
    ok: isWifKey,
    may: hasBase58Run(51),
    re: /[1-9A-HJ-NP-Za-km-z]{51,}/dg,
  },
  {
    kind: "BIP32_KEY",
    markers: ["prv"],
    bound: ALNUM,
    ok: isBip32Key,
    re: /[xyztuvYZUV]prv[1-9A-HJ-NP-Za-km-z]{107}/dg,
  },
  {
    kind: "SOLANA_KEY",
    bound: ALNUM,
    ok: isSolanaKey,
    may: hasBase58Run(85),
    re: /[1-9A-HJ-NP-Za-km-z]{85,}/dg,
  },
  {
    kind: "SOLANA_KEYPAIR",
    markers: ["["],
    ok: isSolanaKeypair,
    re: /\[\s*\d{1,3}(?:\s*,\s*\d{1,3}){63}\s*\]/dg,
  },
  {
    kind: "NEAR_KEY",
    markers: ["ed25519:"],
    bound: ALNUM,
    re: /ed25519:[1-9A-HJ-NP-Za-km-z]{86,88}/dg,
  },
  {
    kind: "SUI_KEY",
    markers: ["suiprivkey1"],
    bound: ALNUM,
    re: /suiprivkey1[0-9a-z]{58}/dg,
  },
  {
    kind: "APTOS_KEY",
    markers: ["-priv-0x"],
    bound: ALNUM,
    re: /(?:ed25519|secp256k1)-priv-0x[0-9a-fA-F]{64}/dg,
  },
  {
    kind: "STELLAR_KEY",
    bound: ALNUM,
    ok: isStellarSeed,
    may: hasBase32Run(56),
    re: /S[A-Z2-7]{55}/dg,
  },
  {
    kind: "NOSTR_KEY",
    markers: ["nsec1"],
    bound: ALNUM,
    re: /nsec1[02-9ac-hj-np-z]{58}/dg,
  },
  {
    kind: "AGE_KEY",
    markers: ["AGE-SECRET-KEY-"],
    bound: ALNUM,
    re: /AGE-SECRET-KEY-1[0-9A-Z]{58}/dg,
  },
  {
    kind: "ZCASH_KEY",
    markers: ["secret-extended-key-"],
    bound: ALNUM,
    re: /secret-extended-key-(?:main|test)1[0-9a-z]{150,320}/dg,
  },
  {
    kind: "SEED_PHRASE",
    fold: SEED_CUES,
    back: 32,
    ahead: 400,
    fix: seedPhraseAt,
    re: /(?:seed|mnemonic|phrase|recovery|助记词|助記詞|シード|ニーモニック|시드|니모닉)[^.\n]{0,24}?(?:\n[ \t]*)?\b([a-z]{3,8}(?:[ \t]+[a-z]{3,8}){11,40})\b/dgi,
  },
]
