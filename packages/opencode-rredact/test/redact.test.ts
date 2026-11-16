import assert from "node:assert/strict"
import test from "node:test"

import {
  clearMentions,
  containsPlaceholder,
  redactContext,
  redactPrompt,
  redactToolResult,
  restoreToolInput,
  type PromptLike,
} from "../src/redact.ts"

const SECRET = "hunter2"
const PLACEHOLDER = "[REDACTED:SECRET:1]"

async function fakeRedact(text: string): Promise<string> {
  return text.replaceAll(SECRET, PLACEHOLDER)
}

async function fakeRestore(text: string): Promise<string> {
  return text.replaceAll(PLACEHOLDER, SECRET)
}

test("redactPrompt rewrites text and clears stale mention offsets", async () => {
  const prompt: PromptLike = {
    text: `password is ${SECRET}`,
    files: [{ description: `file with ${SECRET}`, mention: { start: 0, end: 5, text: "@a" } }],
    agents: [{ mention: { start: 0, end: 2, text: "@b" } }],
    skills: [{ mention: { start: 1, end: 3, text: "@c" } }],
  }

  const changed = await redactPrompt(prompt, fakeRedact)

  assert.equal(changed, true)
  assert.equal(prompt.text, `password is ${PLACEHOLDER}`)
  assert.equal(prompt.files?.[0]?.description, `file with ${PLACEHOLDER}`)
  assert.equal(prompt.files?.[0]?.mention, undefined)
  assert.equal(prompt.agents?.[0]?.mention, undefined)
  assert.equal(prompt.skills?.[0]?.mention, undefined)
})

test("redactPrompt keeps mentions when nothing changed", async () => {
  const mention = { start: 0, end: 5, text: "@file" }
  const prompt: PromptLike = { text: "nothing to redact", files: [{ mention }] }

  const changed = await redactPrompt(prompt, fakeRedact)

  assert.equal(changed, false)
  assert.deepEqual(prompt.files?.[0]?.mention, mention)
})

test("clearMentions only drops offsets", async () => {
  const prompt: PromptLike = {
    text: "x",
    files: [{ description: "kept", mention: { start: 0, end: 1, text: "@a" } }],
  }
  clearMentions(prompt)
  assert.equal(prompt.files?.[0]?.mention, undefined)
  assert.equal(prompt.files?.[0]?.description, "kept")
})

test("redactContext covers system, text, reasoning and tool results", async () => {
  const context = {
    system: [{ type: "text", text: `system ${SECRET}` }],
    messages: [
      {
        role: "user",
        content: [{ type: "text", text: `user ${SECRET}` }],
      },
      {
        role: "assistant",
        content: [{ type: "reasoning", text: `thinking about ${SECRET}` }],
      },
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            result: {
              type: "content",
              value: [
                { type: "text", text: `output ${SECRET}` },
                { type: "file", uri: "file:///tmp/x", mime: "text/plain" },
              ],
            },
          },
          {
            type: "tool-result",
            result: { type: "json", value: { nested: [`json ${SECRET}`] } },
          },
        ],
      },
    ],
  }

  await redactContext(context, fakeRedact)

  assert.equal(context.system[0]?.text, `system ${PLACEHOLDER}`)
  assert.equal((context.messages[0] as any).content[0].text, `user ${PLACEHOLDER}`)
  assert.equal((context.messages[1] as any).content[0].text, `thinking about ${PLACEHOLDER}`)
  const tool = context.messages[2] as any
  assert.equal(tool.content[0].result.value[0].text, `output ${PLACEHOLDER}`)
  assert.equal(tool.content[0].result.value[1].uri, "file:///tmp/x")
  assert.equal(tool.content[1].result.value.nested[0], `json ${PLACEHOLDER}`)
})

test("redactToolResult rewrites output and content but keeps file parts", async () => {
  const result = {
    output: { message: `structured ${SECRET}` },
    content: [
      { type: "text", text: `text ${SECRET}` },
      { type: "file", uri: "file:///tmp/a", mime: "text/plain", name: "a" },
    ],
    metadata: { untouched: SECRET },
  }

  await redactToolResult(result, fakeRedact)

  assert.deepEqual(result.output, { message: `structured ${PLACEHOLDER}` })
  assert.equal(result.content[0]?.text, `text ${PLACEHOLDER}`)
  assert.equal(result.content[1]?.uri, "file:///tmp/a")
  assert.equal(result.metadata.untouched, SECRET)
})

test("binary values are never sent through the redactor", async () => {
  const bytes = new Uint8Array([1, 2, 3])
  const dataUri = "data:image/png;base64,aHVudGVyMg=="
  const result = { output: { bytes, dataUri } }

  await redactToolResult(result, fakeRedact)

  assert.equal(result.output.bytes, bytes)
  assert.equal(result.output.dataUri, dataUri)
})

test("restoreToolInput restores nested placeholders only", async () => {
  const input = {
    filePath: "/tmp/.env",
    content: `PASSWORD=${PLACEHOLDER}`,
    nested: [{ text: `x ${PLACEHOLDER} y` }, "plain"],
  }

  await restoreToolInput(input, fakeRestore)

  assert.equal(input.content, `PASSWORD=${SECRET}`)
  const nested = input.nested[0]
  assert.ok(nested !== undefined)
  assert.equal(typeof nested === "string" ? nested : nested.text, `x ${SECRET} y`)
  assert.equal(input.nested[1], "plain")
})

test("restoreToolInput survives cycles", async () => {
  const input: Record<string, unknown> = { text: PLACEHOLDER }
  input.self = input

  await restoreToolInput(input, fakeRestore)

  assert.equal(input.text, SECRET)
  assert.equal(input.self, input)
})

test("containsPlaceholder recognizes the engine format", () => {
  assert.equal(containsPlaceholder("[REDACTED:ENV_SECRET:1]"), true)
  assert.equal(containsPlaceholder("[REDACTED:PII:A7]"), true)
  assert.equal(containsPlaceholder("[redacted:env_secret:1]"), false)
  assert.equal(containsPlaceholder("plain"), false)
})
