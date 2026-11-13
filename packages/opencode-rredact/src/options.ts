/**
 * Plugin options as passed through `opencode.json(c)`:
 *
 * ```json
 * {
 *   "plugins": [
 *     { "package": "opencode-rredact", "options": { "failClosed": true } }
 *   ]
 * }
 * ```
 */
export interface RRedactPluginOptions {
  /** Path to the `rredact` binary. Default: `RREDACT_BIN` or `rredact`. */
  binary?: string
  /** Use an already running server instead of spawning one. Default: `RREDACT_URL`. */
  url?: string
  /** Bearer token for an external server. Default: `RREDACT_API_TOKEN`. */
  token?: string
  /** Extra arguments for the spawned `rredact serve` process. */
  args?: string[]
  /** Extra environment variables for the spawned process. */
  env?: Record<string, string>
  /**
   * Refuse to send unredacted content when rredact is unavailable or a request
   * fails. Default: `true`.
   */
  failClosed?: boolean
  /** Redact user prompts at admission. Default: `true`. */
  redactPrompts?: boolean
  /** Redact tool results before they enter the transcript. Default: `true`. */
  redactToolResults?: boolean
  /** Redact the assembled model context, including compaction and title requests. Default: `true`. */
  redactContext?: boolean
  /** Restore placeholders in write/edit tool inputs before they run. Default: `true`. */
  restoreToolInputs?: boolean
  /** Tools whose inputs may be restored. Default: `write`, `edit`, `multiedit`, `apply_patch`. */
  restoreTools?: string[]
  /** Milliseconds to wait for `rredact serve` to report its address. Default: `10_000`. */
  startupTimeoutMs?: number
  /** Milliseconds before an API request is aborted. Default: `15_000`. */
  requestTimeoutMs?: number
}

export interface ResolvedOptions {
  binary: string
  url: string | undefined
  token: string | undefined
  args: string[]
  env: Record<string, string>
  failClosed: boolean
  redactPrompts: boolean
  redactToolResults: boolean
  redactContext: boolean
  restoreToolInputs: boolean
  restoreTools: string[]
  startupTimeoutMs: number
  requestTimeoutMs: number
}

export const DEFAULT_RESTORE_TOOLS = ["write", "edit", "multiedit", "apply_patch"]

export interface ResolveResult {
  options: ResolvedOptions
  warnings: string[]
}

function readString(
  raw: Readonly<Record<string, unknown>>,
  key: string,
  fallback: string | undefined,
  warnings: string[],
): string | undefined {
  const value = raw[key]
  if (value === undefined) return fallback
  if (typeof value !== "string" || value.length === 0) {
    warnings.push(`ignoring option "${key}": expected a non-empty string`)
    return fallback
  }
  return value
}

function readBoolean(
  raw: Readonly<Record<string, unknown>>,
  key: string,
  fallback: boolean,
  warnings: string[],
): boolean {
  const value = raw[key]
  if (value === undefined) return fallback
  if (typeof value !== "boolean") {
    warnings.push(`ignoring option "${key}": expected a boolean`)
    return fallback
  }
  return value
}

function readNumber(
  raw: Readonly<Record<string, unknown>>,
  key: string,
  fallback: number,
  warnings: string[],
): number {
  const value = raw[key]
  if (value === undefined) return fallback
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    warnings.push(`ignoring option "${key}": expected a positive number`)
    return fallback
  }
  return value
}

function readStringArray(
  raw: Readonly<Record<string, unknown>>,
  key: string,
  fallback: string[],
  warnings: string[],
): string[] {
  const value = raw[key]
  if (value === undefined) return fallback
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || item.length === 0)) {
    warnings.push(`ignoring option "${key}": expected an array of non-empty strings`)
    return fallback
  }
  return [...value]
}

function readRecord(
  raw: Readonly<Record<string, unknown>>,
  key: string,
  warnings: string[],
): Record<string, string> {
  const value = raw[key]
  if (value === undefined) return {}
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    warnings.push(`ignoring option "${key}": expected an object`)
    return {}
  }
  const result: Record<string, string> = {}
  for (const [name, entry] of Object.entries(value)) {
    if (typeof entry === "string") result[name] = entry
    else warnings.push(`ignoring "${key}.${name}": expected a string`)
  }
  return result
}

export function resolveOptions(raw: Readonly<Record<string, unknown>>): ResolveResult {
  const warnings: string[] = []
  const environment = process.env

  const options: ResolvedOptions = {
    binary: readString(raw, "binary", environment.RREDACT_BIN || "rredact", warnings) as string,
    url: readString(raw, "url", environment.RREDACT_URL || undefined, warnings),
    token: readString(raw, "token", environment.RREDACT_API_TOKEN || undefined, warnings),
    args: readStringArray(raw, "args", [], warnings),
    env: readRecord(raw, "env", warnings),
    failClosed: readBoolean(raw, "failClosed", true, warnings),
    redactPrompts: readBoolean(raw, "redactPrompts", true, warnings),
    redactToolResults: readBoolean(raw, "redactToolResults", true, warnings),
    redactContext: readBoolean(raw, "redactContext", true, warnings),
    restoreToolInputs: readBoolean(raw, "restoreToolInputs", true, warnings),
    restoreTools: readStringArray(raw, "restoreTools", DEFAULT_RESTORE_TOOLS, warnings),
    startupTimeoutMs: readNumber(raw, "startupTimeoutMs", 10_000, warnings),
    requestTimeoutMs: readNumber(raw, "requestTimeoutMs", 15_000, warnings),
  }

  return { options, warnings }
}
