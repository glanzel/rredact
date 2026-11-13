import assert from "node:assert/strict"
import { existsSync, mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import test from "node:test"

import { rredact } from "../src/index.ts"

const candidates = [
  process.env.RREDACT_BIN,
  resolve(import.meta.dirname, "../../../target/debug/rredact"),
  resolve(import.meta.dirname, "../../../target/release/rredact"),
].filter((value): value is string => typeof value === "string" && value.length > 0)

const binary = candidates.find((path) => existsSync(path))

type Handler = (event: any) => Promise<void> | void

function fakeContext(directory: string, options: Record<string, unknown>) {
  const handlers = new Map<string, Handler>()
  const disposers: string[] = []

  const register = (prefix: string) => async (name: string, handler: Handler) => {
    const key = `${prefix}:${name}`
    handlers.set(key, handler)
    return {
      dispose: async () => {
        disposers.push(key)
        handlers.delete(key)
      },
    }
  }

  const ctx = {
    options,
    app: { version: "test" },
    location: { directory },
    session: { hook: register("session") },
    tool: { hook: register("tool") },
    event: {
      subscribe: () => ({
        async *[Symbol.asyncIterator]() {
          // No events in this test.
        },
      }),
    },
  }

  return { ctx, handlers, disposers }
}

test(
  "plugin hooks redact prompts and tool results, then restore writes",
  { skip: binary === undefined ? "build rredact first (cargo build)" : false },
  async () => {
    const directory = mkdtempSync(join(tmpdir(), "rredact-plugin-hooks-"))
    const { ctx, handlers, disposers } = fakeContext(directory, { binary, requestTimeoutMs: 5_000 })
    const cleanup = await rredact.setup(ctx as any)
    assert.equal(typeof cleanup, "function")

    try {
      const promptHandler = handlers.get("session:prompt")
      const afterHandler = handlers.get("tool:execute.after")
      const beforeHandler = handlers.get("tool:execute.before")
      assert.ok(promptHandler)
      assert.ok(afterHandler)
      assert.ok(beforeHandler)

      const prompt = { sessionID: "session-a", prompt: { text: "PASSWORD=real-pass-42" } }
      await promptHandler(prompt)
      assert.equal(prompt.prompt.text.includes("real-pass-42"), false)
      assert.match(prompt.prompt.text, /\[REDACTED:ENV_SECRET:1\]/)

      const result = {
        tool: "bash",
        sessionID: "session-a",
        status: "completed" as const,
        input: {},
        result: { output: "PASSWORD=real-pass-42", content: "PASSWORD=real-pass-42" },
      }
      await afterHandler(result)
      assert.equal(String(result.result.output).includes("real-pass-42"), false)
      assert.equal(String(result.result.content).includes("real-pass-42"), false)

      const write = {
        tool: "write",
        sessionID: "session-a",
        input: { filePath: "/tmp/app.env", content: "PASSWORD=[REDACTED:ENV_SECRET:1]" },
      }
      await beforeHandler(write)
      assert.equal(write.input.content, "PASSWORD=real-pass-42")
    } finally {
      await cleanup!()
      assert.deepEqual(
        disposers.sort(),
        [
          "session:compaction",
          "session:context",
          "session:generate",
          "session:prompt",
          "session:title",
          "tool:execute.after",
          "tool:execute.before",
        ].sort(),
      )
      rmSync(directory, { recursive: true, force: true })
    }
  },
)

test("plugin fails closed when the server cannot start", async () => {
  const directory = mkdtempSync(join(tmpdir(), "rredact-plugin-fail-"))
  const { ctx, handlers } = fakeContext(directory, {
    binary: "/nonexistent/rredact-for-tests",
    startupTimeoutMs: 2_000,
  })
  const cleanup = await rredact.setup(ctx as any)
  assert.equal(typeof cleanup, "function")

  try {
    const promptHandler = handlers.get("session:prompt")
    assert.ok(promptHandler)
    await assert.rejects(
      async () => {
        await promptHandler({ sessionID: "session-a", prompt: { text: "PASSWORD=real-pass-42" } })
      },
      /refusing to send unredacted content/,
    )
  } finally {
    await cleanup!()
    rmSync(directory, { recursive: true, force: true })
  }
})
