// OpenCode v2 脱敏插件主入口（仅导出 V2 规范的 `{ id, setup }`，无运行时 SDK 强耦合）。
import { createRedactSetup, type V2Cleanup, type V2Context } from "./plugin.js"

export const PLUGIN_ID = "opencode-redact"

export const setup: (context: V2Context) => Promise<V2Cleanup> = createRedactSetup()

const plugin = {
  id: PLUGIN_ID,
  setup,
}

export default plugin

export { AuditLogger, type AuditLoggerOptions, type AuditRecord, type AuditValue } from "./audit.js"
export {
  checkActions,
  checkAllow,
  checkRules,
  isValidKindName,
  normalizeRuleKind,
  parseConfig,
  type RedactConfig,
  RedactOptionsSchema,
  type RedactPluginInputOptions,
  resolveStateDir,
  shouldMaskProvider,
  toMaskOptions,
} from "./config.js"
export { DateWordMatcher, parseDateWord } from "./engine/dateword.js"
export { RedactEngine } from "./engine/engine.js"
export {
  eventCtxOfJSON,
  hasPathsInJSON,
  isNestedJSONField,
  isProtocolID,
  isSealedResponseText,
  jsonEscape,
  scanJSONRegions,
  typeOfJSON,
  walkJSONStrings,
} from "./engine/jsonWalker.js"
export { buildBuiltinRules, CustomRuleCompiler, KIND_TO_CATS, PERSONAL_KINDS } from "./engine/rules.js"
export { shapeOf, standInOfUsername } from "./engine/shape.js"
export { RedactStore, type RedactStoreOptions } from "./engine/state.js"
export {
  isBinaryContentType,
  SSERestorer,
  WebSocketFrameRestorer,
  wrapHttpResponse,
} from "./engine/stream.js"
export {
  type Action,
  CATEGORIES,
  type CategoryDef,
  type CategoryId,
  type CustomRule,
  type Finder,
  type Hit,
  type MaskOptions,
  type MaskResult,
  type NonDefaultAction,
  type Span,
} from "./engine/types.js"
export {
  createRedactSetup,
  RedactBlockedError,
  RedactFailClosedError,
  type V2Cleanup,
  type V2Context,
} from "./plugin.js"
