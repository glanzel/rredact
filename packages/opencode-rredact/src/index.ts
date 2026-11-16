import { existsSync } from "node:fs"
import { join } from "node:path"

import { Plugin } from "@opencode/plugin"

import { resolveOptions } from "./options.ts"
import { findSensitiveAccess, findSensitivePath } from "./paths.ts"
import {
  redactContext,
  redactJsonValue,
  redactPrompt,
  redactToolResult,
  restoreToolInput,
  type ContextLike,
} from "./redact.ts"
import { RRedactRuntime } from "./server.ts"

function describe(error: unknown): string {
  if (error instanceof Error) return error.message
  return String(error)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function toolPath(input: unknown): string | undefined {
  if (!isRecord(input)) return undefined
  for (const key of ["filePath", "file_path", "path"]) {
    const value = input[key]
    if (typeof value === "string" && value.length > 0) return value
  }
  return undefined
}

function attachmentUris(file: unknown): string[] {
  if (!isRecord(file)) return []
  const uris: string[] = []
  if (typeof file.uri === "string") uris.push(file.uri)
  const source = file.source
  if (isRecord(source) && typeof source.uri === "string") uris.push(source.uri)
  return uris
}

export const rredact = Plugin.define({
  id: "rredact",
  async setup(ctx) {
    const { options, warnings } = resolveOptions(ctx.options)
    for (const warning of warnings) console.error(`[rredact] ${warning}`)

    const mappingFile = join(ctx.location.directory, ".rredact/mapping.json")
    if (existsSync(mappingFile)) {
      console.error(
        `[rredact] warning: ${mappingFile} contains original secrets; tools are blocked from reading it, but a sandbox or --no-store is stronger`,
      )
    }
    if (!options.storeSessionMappings && existsSync(join(ctx.location.directory, ".rredact/sessions"))) {
      console.error(
        "[rredact] warning: .rredact/sessions exists from an earlier run and contains original secrets",
      )
    }

    const runtime = new RRedactRuntime(options, ctx.location.directory)
    void runtime.start().catch((error) => {
      console.error(`[rredact] failed to start: ${describe(error)}`)
    })

    const disposers: Array<() => Promise<void>> = []
    const controller = new AbortController()

    const cleanup = async (): Promise<void> => {
      controller.abort()
      for (const dispose of disposers.reverse()) {
        try {
          await dispose()
        } catch (error) {
          console.error(`[rredact] could not dispose a hook: ${describe(error)}`)
        }
      }
      await runtime.stop()
    }

    /**
     * Redact one string. With `failClosed` (the default) a failure throws, which
     * aborts the prompt, tool call or model request instead of leaking plaintext.
     */
    const redact = async (
      label: string,
      text: string,
      sessionID: string,
      path?: string,
    ): Promise<string> => {
      if (text.length === 0) return text
      try {
        return await runtime.redact(text, sessionID, path)
      } catch (error) {
        if (options.failClosed) {
          throw new Error(
            `rredact ${label} failed; refusing to send unredacted content: ${describe(error)}`,
          )
        }
        console.error(`[rredact] ${label} failed; continuing unredacted: ${describe(error)}`)
        return text
      }
    }

    try {
      if (options.redactPrompts) {
        const registration = await ctx.session.hook("prompt", async (event) => {
          if (options.blockSensitivePaths && options.sensitivePaths.length > 0) {
            for (const file of event.prompt.files ?? []) {
              for (const uri of attachmentUris(file)) {
                const match = findSensitivePath(uri, options.sensitivePaths)
                if (match) {
                  throw new Error(
                    `rredact blocked prompt attachment: ${match} contains original secrets and must not be read by the model`,
                  )
                }
              }
            }
          }

          await redactPrompt(event.prompt, (text) =>
            redact("prompt redaction", text, event.sessionID),
          )
        })
        disposers.push(() => registration.dispose())
      }

      if (options.redactToolResults) {
        const registration = await ctx.tool.hook("execute.after", async (event) => {
          if (event.status === "error") {
            const message = event.error?.message
            if (typeof message === "string" && message.length > 0) {
              const redacted = await redact("tool error redaction", message, event.sessionID)
              ;(event.error as { message: string }).message = redacted
            }
            if (event.error?.metadata !== undefined) {
              ;(event.error as { metadata?: unknown }).metadata = await redactJsonValue(
                event.error.metadata,
                (text) => redact("tool error metadata redaction", text, event.sessionID),
              )
            }
            return
          }

          const path = toolPath(event.input)
          event.result = (await redactToolResult(event.result, (text) =>
            redact("tool result redaction", text, event.sessionID, path),
          )) as typeof event.result
        })
        disposers.push(() => registration.dispose())
      }

      if (
        (options.blockSensitivePaths && options.sensitivePaths.length > 0) ||
        (options.restoreToolInputs && options.restoreTools.length > 0)
      ) {
        const restorable = new Set(options.restoreTools)
        const registration = await ctx.tool.hook("execute.before", async (event) => {
          if (options.blockSensitivePaths && options.sensitivePaths.length > 0) {
            const match = findSensitiveAccess(event.input, options.sensitivePaths, event.tool)
            if (match) {
              throw new Error(
                `rredact blocked ${event.tool}: ${match} contains original secrets and must not be read by the model`,
              )
            }
          }

          if (!options.restoreToolInputs || !restorable.has(event.tool)) return

          event.input = await restoreToolInput(event.input, async (text) => {
            try {
              return await runtime.restoreText(text, event.sessionID)
            } catch (error) {
              if (options.failClosed) {
                throw new Error(
                  `rredact restore failed; refusing to run ${event.tool} with unresolved placeholders: ${describe(error)}`,
                )
              }
              console.error(
                `[rredact] restore failed; leaving placeholders in ${event.tool}: ${describe(error)}`,
              )
              return text
            }
          })
        })
        disposers.push(() => registration.dispose())
      }

      if (options.redactContext) {
        const handler = async (event: ContextLike & { sessionID: string }): Promise<void> => {
          await redactContext(event, (text) =>
            redact("context redaction", text, event.sessionID),
          )
        }

        const registrations = await Promise.all([
          ctx.session.hook("context", handler),
          ctx.session.hook("compaction", handler),
          ctx.session.hook("title", handler),
          ctx.session.hook("generate", handler),
        ])
        for (const registration of registrations) {
          disposers.push(() => registration.dispose())
        }
      }

      void (async () => {
        try {
          for await (const event of ctx.event.subscribe({
            types: ["session.deleted"],
            signal: controller.signal,
          })) {
            const location = event.location as { directory?: string } | undefined
            if (location?.directory && location.directory !== ctx.location.directory) continue
            const data = event.data as { sessionID?: unknown }
            if (typeof data.sessionID === "string") {
              await runtime.deleteSession(data.sessionID)
            }
          }
        } catch (error) {
          if (!controller.signal.aborted) {
            console.error(`[rredact] event subscription failed: ${describe(error)}`)
          }
        }
      })()
    } catch (error) {
      await cleanup()
      throw error
    }

    return cleanup
  },
})

export default rredact
