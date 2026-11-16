import assert from "node:assert/strict"
import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import test from "node:test"

import { resolveOptions } from "../src/options.ts"
import { RRedactRuntime } from "../src/server.ts"

const candidates = [
  process.env.RREDACT_BIN,
  resolve(import.meta.dirname, "../../../target/debug/rredact"),
  resolve(import.meta.dirname, "../../../target/release/rredact"),
].filter((value): value is string => typeof value === "string" && value.length > 0)

const binary = candidates.find((path) => existsSync(path))

test(
  "runtime redacts, restores and deletes per-session mappings",
  { skip: binary === undefined ? "build rredact first (cargo build)" : false },
  async () => {
    const directory = mkdtempSync(join(tmpdir(), "rredact-plugin-"))
    const { options } = resolveOptions({
      binary,
      startupTimeoutMs: 15_000,
      requestTimeoutMs: 5_000,
    })
    const runtime = new RRedactRuntime(options, directory)

    try {
      await runtime.start()

      const secret = "PASSWORD=real-pass-42"
      const redacted = await runtime.redact(secret, "session-test", "app.env")
      assert.match(redacted, /\[REDACTED:/)
      assert.equal(redacted.includes("real-pass-42"), false)
      assert.equal(existsSync(join(directory, ".rredact/sessions")), false)

      assert.equal(await runtime.restoreText(redacted, "session-test"), secret)

      await runtime.deleteSession("session-test")
      assert.equal(await runtime.restoreText(redacted, "session-test"), redacted)
    } finally {
      await runtime.stop()
      rmSync(directory, { recursive: true, force: true })
    }
  },
)

test(
  "session mappings persist only when explicitly enabled",
  { skip: binary === undefined ? "build rredact first (cargo build)" : false },
  async () => {
    const directory = mkdtempSync(join(tmpdir(), "rredact-plugin-store-"))
    const { options } = resolveOptions({
      binary,
      storeSessionMappings: true,
      startupTimeoutMs: 15_000,
      requestTimeoutMs: 5_000,
    })
    const runtime = new RRedactRuntime(options, directory)
    const sessionDir = join(directory, ".rredact/sessions")

    try {
      await runtime.start()
      await runtime.redact("PASSWORD=real-pass-42", "persisted", "app.env")
      assert.equal(readdirSync(sessionDir).length, 1)

      await runtime.deleteSession("persisted")
      assert.equal(readdirSync(sessionDir).length, 0)
    } finally {
      await runtime.stop()
      rmSync(directory, { recursive: true, force: true })
    }
  },
)

test("a missing binary fails closed instead of passing plaintext through", async () => {
  const { options } = resolveOptions({
    binary: "/nonexistent/rredact-for-tests",
    startupTimeoutMs: 2_000,
  })
  const runtime = new RRedactRuntime(options, tmpdir())

  try {
    await assert.rejects(() => runtime.start(), /could not start|ENOENT/)
    await assert.rejects(() => runtime.redact("PASSWORD=real-pass-42", "session"), /could not start|ENOENT/)
  } finally {
    await runtime.stop()
  }
})
