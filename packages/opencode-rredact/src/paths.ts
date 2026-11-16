/**
 * Best-effort guard against tools reading files that contain original values.
 *
 * This is defense in depth, not a sandbox. A shell command can obfuscate a path
 * (`cat $(printf .rredact)/sessions/...`), so the plugin also keeps session
 * mappings in memory by default. See `storeSessionMappings`.
 */

const PATH_KEYS = new Set([
  "filePath",
  "file_path",
  "filename",
  "path",
  "paths",
  "cwd",
  "directory",
  "dir",
  "uri",
  "url",
  "glob",
  "pattern",
])

const COMMAND_KEYS = new Set(["command", "cmd", "script", "patch", "patchText"])

const COMMAND_TOOLS = new Set([
  "bash",
  "shell",
  "exec",
  "run",
  "terminal",
  "apply_patch",
  "patch",
])

export function normalizePath(value: string): string {
  const absolute = value.startsWith("/")
  const parts: string[] = []
  for (const part of value.replaceAll("\\", "/").split("/")) {
    if (!part || part === ".") continue
    if (part === "..") {
      parts.pop()
      continue
    }
    parts.push(part)
  }
  return `${absolute ? "/" : ""}${parts.join("/")}`
}

/**
 * Match a path-like value against the sensitive entries. Absolute paths and
 * paths inside the project both match `.rredact/sessions/...`.
 */
export function findSensitivePath(value: string, sensitivePaths: readonly string[]): string | undefined {
  const normalized = normalizePath(value)
  if (!normalized) return undefined

  for (const entry of sensitivePaths) {
    const needle = normalizePath(entry)
    if (!needle) continue
    if (normalized === needle) return entry
    if (normalized.startsWith(`${needle}/`)) return entry
    if (normalized.includes(`/${needle}/`)) return entry
    if (normalized.endsWith(`/${needle}`)) return entry
  }
  return undefined
}

/**
 * Check a shell command for a sensitive path. Commands are not paths, so this
 * is a plain substring check after normalizing backslashes.
 */
export function findSensitiveCommand(
  command: string,
  sensitivePaths: readonly string[],
): string | undefined {
  const normalized = command
    .replaceAll("\\", "/")
    .replace(/\/\.\//g, "/")
    .replace(/\/{2,}/g, "/")
  for (const entry of sensitivePaths) {
    const needle = entry.replaceAll("\\", "/").replace(/\/+$/, "")
    if (needle && normalized.includes(needle)) return entry
  }
  return undefined
}

/**
 * Walk a tool input and look for path-like or command-like fields that point at
 * a sensitive file. Content fields are deliberately ignored: a document may
 * mention `.rredact/mapping.json` without reading it.
 */
export function findSensitiveAccess(
  input: unknown,
  sensitivePaths: readonly string[],
  tool: string,
): string | undefined {
  const seen = new WeakSet<object>()
  const commandTool = COMMAND_TOOLS.has(tool)

  const walk = (value: unknown, key: string | undefined, depth: number): string | undefined => {
    if (depth > 64) return undefined

    if (typeof value === "string") {
      if (key && COMMAND_KEYS.has(key)) return findSensitiveCommand(value, sensitivePaths)
      if (key && PATH_KEYS.has(key)) return findSensitivePath(value, sensitivePaths)
      if (!key && commandTool) return findSensitiveCommand(value, sensitivePaths)
      return undefined
    }

    if (Array.isArray(value)) {
      for (const item of value) {
        const match = walk(item, key, depth + 1)
        if (match) return match
      }
      return undefined
    }

    if (!isPlainRecord(value) || seen.has(value)) return undefined
    seen.add(value)

    for (const [childKey, child] of Object.entries(value)) {
      const match = walk(child, childKey, depth + 1)
      if (match) return match
    }
    return undefined
  }

  return walk(input, undefined, 0)
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}
