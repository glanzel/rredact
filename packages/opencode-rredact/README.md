# opencode-rredact

Automatic, fail-closed redaction of secrets and PII for OpenCode V2.

The plugin hooks into OpenCode and sends prompts, tool results and assembled
model requests through a local [`rredact serve`](../../README.md) process before
they can reach a model provider. Placeholders are restored locally for
`write`/`edit` tool inputs, so redacted file contents do not overwrite the real
values with placeholders.

> Runtime redaction must be automatic. This plugin does not ask the model to be
> careful, and it does not depend on the model cooperating.

## How it works

```text
OpenCode server
  ├─ session.prompt      -> redact user prompt at admission
  ├─ tool.execute.after  -> redact tool output before it is stored
  ├─ tool.execute.before -> restore placeholders for write/edit inputs
  └─ session.context     -> redact system text + transcript before dispatch
      (also compaction, title and generate requests)

                    HTTP (loopback, random token)
                              |
                     rredact serve (Rust)
                              |
                   rules + per-session mapping
```

The `context` hooks are the authoritative egress point: they run immediately
before a model request is dispatched and also cover content that bypasses the
prompt hook, such as synthetic messages and skill or attachment text.

Every OpenCode session gets its own mapping file under
`.rredact/sessions/<sha256>.json`. Session files are written with mode `0600`
and are ignored by Git. They are deleted when OpenCode emits `session.deleted`.

## Requirements

- OpenCode V2 (`@opencode/plugin` 2.x)
- The `rredact` binary, either on `PATH`, built from this repository, or
  configured with the `binary` option

Build the binary:

```bash
cargo build --release
# target/release/rredact
```

## Load the plugin

Local package (recommended while developing):

```jsonc
// opencode.jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "./packages/opencode-rredact",
      "options": {
        "binary": "/absolute/path/to/rredact"
      }
    }
  ]
}
```

Published package:

```jsonc
{
  "plugins": ["opencode-rredact"]
}
```

Plugins under `.opencode/plugins/` load automatically. A minimal local wrapper:

```ts
// .opencode/plugins/rredact/index.ts
export { default } from "../../../packages/opencode-rredact/src/index.ts"
```

Do not enable the plugin in a repository until the `rredact` binary is
available. The default is fail-closed: if rredact cannot start, prompts and
model requests are blocked rather than sent unredacted.

## Options

Pass options through the object form in `opencode.json(c)`:

```jsonc
{
  "plugins": [
    {
      "package": "opencode-rredact",
      "options": {
        "failClosed": true,
        "restoreToolInputs": true
      }
    }
  ]
}
```

| Option | Default | Meaning |
| --- | --- | --- |
| `binary` | `RREDACT_BIN` or `rredact` | Path to the rredact binary. |
| `url` | `RREDACT_URL` | Use an already running server instead of spawning one. |
| `token` | `RREDACT_API_TOKEN` | Bearer token for an external server. |
| `args` | `[]` | Extra arguments for `rredact serve`, e.g. `["--config", ".rredact.yaml"]`. |
| `env` | `{}` | Extra environment variables for the spawned process. |
| `failClosed` | `true` | Block prompts/tool calls/model requests when redaction fails. |
| `redactPrompts` | `true` | Redact user prompts at admission. |
| `redactToolResults` | `true` | Redact tool results before they enter the transcript. |
| `redactContext` | `true` | Redact the assembled model request (including compaction, title and generate). |
| `restoreToolInputs` | `true` | Restore placeholders in write/edit tool inputs. |
| `restoreTools` | `write`, `edit`, `multiedit`, `apply_patch` | Tools whose inputs may be restored. |
| `startupTimeoutMs` | `10_000` | How long to wait for `rredact serve` to report its address. |
| `requestTimeoutMs` | `15_000` | Timeout for one API request. |

## Server lifecycle

If `url` is not set, the plugin starts:

```bash
rredact serve --host 127.0.0.1 --port 0 --token <random>
```

It reads the address from the `listening on http://...` line, verifies
`GET /health`, and keeps the token in memory only. The process is terminated
when the plugin unloads.

The server runs with the OpenCode project directory as its working directory,
so the project's `.rredact.yaml` and `.rredact/rules.d/*.yaml` are used
automatically.

## Fail-closed behavior

With `failClosed: true` (the default), a startup or request failure throws an
error in the hook. OpenCode then aborts the prompt, tool call or model request
instead of continuing with plaintext.

`failClosed: false` is available for debugging, but it sends unredacted content
when rredact is unavailable. Do not use it in a real workspace.

## What is redacted

- User prompt text and file descriptions.
- Tool result `output`, string content and text content parts.
- Tool error messages.
- System instructions and all text, reasoning, compaction and tool-result
  content in model requests.

Binary data is never sent to rredact: `Uint8Array`/`ArrayBuffer` values and
`data:...;base64,` strings are left untouched. File attachments keep their URI
and MIME type.

## Restoring write/edit inputs

When a tool reads a file, the model sees placeholders. If it then writes the
file back, the plugin restores placeholders in the `write`/`edit` input before
the tool runs. This keeps the real values in the file instead of replacing them
with `[REDACTED:...]`.

Restoration only replaces placeholders that exist in the current session
mapping. Unknown placeholders stay as they are. Restoration is local; it does
not send the real values to the model.

## Security notes

- The mapping is local and contains the original values. Never commit it and
  never send it to a model.
- Redaction is regex- and heuristic-based. It cannot prove that content is
  secret-free. Calibrate the rules for the workspace (see the
  [rredact skill](../../.opencode/skills/rredact/SKILL.md)).
- The plugin limits what reaches the model. It does not prevent a
  prompt-injected model from misusing tools that are allowed to run locally.
- Calibration is a separate, explicit trust boundary. Do not confuse it with
  runtime redaction.

## Development

```bash
npm install
npm run typecheck
npm test          # unit tests; integration tests need target/debug/rredact
```

The integration tests are skipped when no rredact binary is found. Build it
first with `cargo build`.
