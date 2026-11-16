import assert from "node:assert/strict"
import test from "node:test"

import { resolveOptions } from "../src/options.ts"

function withEnvironment(values: Record<string, string | undefined>, run: () => void): void {
  const saved = new Map<string, string | undefined>()
  for (const [key, value] of Object.entries(values)) {
    saved.set(key, process.env[key])
    if (value === undefined) delete process.env[key]
    else process.env[key] = value
  }
  try {
    run()
  } finally {
    for (const [key, value] of saved) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }
}

test("defaults are fail-closed and redact every egress point", () => {
  withEnvironment({ RREDACT_BIN: undefined, RREDACT_URL: undefined, RREDACT_API_TOKEN: undefined }, () => {
    const { options, warnings } = resolveOptions({})
    assert.deepEqual(warnings, [])
    assert.equal(options.binary, "rredact")
    assert.equal(options.url, undefined)
    assert.equal(options.failClosed, true)
    assert.equal(options.redactPrompts, true)
    assert.equal(options.redactToolResults, true)
    assert.equal(options.redactContext, true)
    assert.equal(options.restoreToolInputs, true)
    assert.deepEqual(options.restoreTools, ["write", "edit", "multiedit", "apply_patch"])
    assert.equal(options.storeSessionMappings, false)
    assert.equal(options.blockSensitivePaths, true)
    assert.ok(options.sensitivePaths.includes(".rredact/mapping.json"))
    assert.ok(options.sensitivePaths.includes(".rredact/sessions"))
  })
})

test("environment variables provide binary, URL and token", () => {
  withEnvironment(
    {
      RREDACT_BIN: "/opt/rredact",
      RREDACT_URL: "http://127.0.0.1:9000",
      RREDACT_API_TOKEN: "env-token",
    },
    () => {
      const { options } = resolveOptions({})
      assert.equal(options.binary, "/opt/rredact")
      assert.equal(options.url, "http://127.0.0.1:9000")
      assert.equal(options.token, "env-token")
    },
  )
})

test("explicit options win over the environment", () => {
  withEnvironment({ RREDACT_BIN: "/env/rredact", RREDACT_URL: "http://env" }, () => {
    const { options } = resolveOptions({ binary: "/explicit", url: "http://explicit" })
    assert.equal(options.binary, "/explicit")
    assert.equal(options.url, "http://explicit")
  })
})

test("invalid option types fall back and warn", () => {
  const { options, warnings } = resolveOptions({
    binary: "",
    failClosed: "yes",
    restoreTools: ["write", 3],
    startupTimeoutMs: -1,
    env: { GOOD: "value", BAD: 1 },
  })

  assert.equal(options.binary, "rredact")
  assert.equal(options.failClosed, true)
  assert.deepEqual(options.restoreTools, ["write", "edit", "multiedit", "apply_patch"])
  assert.equal(options.startupTimeoutMs, 10_000)
  assert.deepEqual(options.env, { GOOD: "value" })
  assert.equal(warnings.length, 5)
})

test("fail-open is opt-in", () => {
  const { options } = resolveOptions({ failClosed: false, redactPrompts: false })
  assert.equal(options.failClosed, false)
  assert.equal(options.redactPrompts, false)
})
