import assert from "node:assert/strict"
import test from "node:test"

import { DEFAULT_SENSITIVE_PATHS } from "../src/options.ts"
import {
  findSensitiveAccess,
  findSensitiveCommand,
  findSensitivePath,
  normalizePath,
} from "../src/paths.ts"

test("normalizePath resolves dot segments and separators", () => {
  assert.equal(normalizePath(".rredact/./sessions/../sessions/x.json"), ".rredact/sessions/x.json")
  assert.equal(normalizePath(".rredact\\sessions\\x.json"), ".rredact/sessions/x.json")
  assert.equal(normalizePath("/workspace/project/.rredact/sessions/x.json"), "/workspace/project/.rredact/sessions/x.json")
})

test("findSensitivePath matches relative, absolute and nested paths", () => {
  assert.equal(findSensitivePath(".rredact/mapping.json", DEFAULT_SENSITIVE_PATHS), ".rredact/mapping.json")
  assert.equal(
    findSensitivePath("/workspace/project/.rredact/sessions/abc.json", DEFAULT_SENSITIVE_PATHS),
    ".rredact/sessions",
  )
  assert.equal(findSensitivePath("file:///workspace/.rredact/calibration/a.env", DEFAULT_SENSITIVE_PATHS), ".rredact/calibration")
  assert.equal(findSensitivePath("src/index.ts", DEFAULT_SENSITIVE_PATHS), undefined)
  assert.equal(findSensitivePath(".rredact/rules.d/llm.yaml", DEFAULT_SENSITIVE_PATHS), undefined)
})

test("findSensitiveCommand catches shell reads", () => {
  assert.equal(findSensitiveCommand("cat .rredact/mapping.json", DEFAULT_SENSITIVE_PATHS), ".rredact/mapping.json")
  assert.equal(findSensitiveCommand("cat .rredact\\sessions\\x.json", DEFAULT_SENSITIVE_PATHS), ".rredact/sessions")
  assert.equal(findSensitiveCommand("cat src/index.ts", DEFAULT_SENSITIVE_PATHS), undefined)
})

test("findSensitiveAccess inspects path and command fields but not content", () => {
  assert.equal(
    findSensitiveAccess({ filePath: ".rredact/sessions/x.json" }, DEFAULT_SENSITIVE_PATHS, "read"),
    ".rredact/sessions",
  )
  assert.equal(
    findSensitiveAccess({ edits: [{ filePath: ".rredact/calibration/a.env" }] }, DEFAULT_SENSITIVE_PATHS, "edit"),
    ".rredact/calibration",
  )
  assert.equal(
    findSensitiveAccess({ command: "cat .rredact/mapping.json" }, DEFAULT_SENSITIVE_PATHS, "bash"),
    ".rredact/mapping.json",
  )
  assert.equal(
    findSensitiveAccess(
      { patchText: "*** Update File: .rredact/mapping.json" },
      DEFAULT_SENSITIVE_PATHS,
      "apply_patch",
    ),
    ".rredact/mapping.json",
  )
  assert.equal(
    findSensitiveAccess(
      { filePath: "docs/notes.md", content: "never read .rredact/mapping.json" },
      DEFAULT_SENSITIVE_PATHS,
      "write",
    ),
    undefined,
  )
  assert.equal(
    findSensitiveAccess({ paths: ["src", ".rredact/out"] }, DEFAULT_SENSITIVE_PATHS, "grep"),
    ".rredact/out",
  )
})
