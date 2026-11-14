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
  ├─ tool.execute.before -> block secret paths + restore write/edit inputs
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

Every OpenCode session gets its own mapping. By default the mapping lives only
in the memory of the `rredact serve` process (`--no-store`), so there is no
session file for a tool to read. Set `storeSessionMappings: true` only if you
need persistence and accept that the file contains the original values.

The plugin also blocks tool access to known secret-bearing paths such as
`.rredact/mapping.json` and `.rredact/sessions/`. That is defense in depth, not
a sandbox: a shell command can obfuscate a path.

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
| `storeSessionMappings` | `false` | Persist session mappings under `.rredact/sessions/`. |
| `blockSensitivePaths` | `true` | Block tools from reading secret-bearing local files. |
| `sensitivePaths` | `.rredact/mapping.json`, `.rredact/sessions`, `.rredact/calibration`, `.rredact/redacted`, `.rredact/out` | Paths that tools must not read. |
| `startupTimeoutMs` | `10_000` | How long to wait for `rredact serve` to report its address. |
| `requestTimeoutMs` | `15_000` | Timeout for one API request. |

## Server lifecycle

If `url` is not set, the plugin starts:

```bash
rredact serve --host 127.0.0.1 --port 0 --token <random> --no-store
```

It reads the address from the `listening on http://...` line, verifies
`GET /health`, and keeps the token in memory only. The process is terminated
when the plugin unloads.

The `--no-store` flag is added by default. It keeps the mapping in the server
process only; placeholders stay restorable while the plugin is loaded, but not
after a server restart. Pass `storeSessionMappings: true` to persist mappings
under `.rredact/sessions/<sha256>.json` (mode `0600`, ignored by Git). Those
files contain the original values and are readable by any tool with file
access; the path guard blocks the obvious reads, but a shell can obfuscate a
path. Treat persisted mappings as a deliberate trade-off.

The server runs with the OpenCode project directory as its working directory,
so the project's `.rredact.yaml` and `.rredact/rules.d/*.yaml` are used
automatically.

## Fail-closed behavior

With `failClosed: true` (the default), a startup or request failure throws an
error in the hook. OpenCode then aborts the prompt, tool call or model request
instead of continuing with plaintext.

`failClosed: false` is available for debugging, but it sends unredacted content
when rredact is unavailable. Do not use it in a real workspace.

Path blocking (`blockSensitivePaths`) always fails closed, independent of
`failClosed`: a tool call that targets a secret-bearing path is rejected.

## What is redacted

- User prompt text and file descriptions.
- Tool result `output`, string content and text content parts.
- Tool error messages.
- System instructions and all text, reasoning, compaction and tool-result
  content in model requests.

Binary data is never sent to rredact: `Uint8Array`/`ArrayBuffer` values and
`data:...;base64,` strings are left untouched. File attachments keep their URI
and MIME type.

## What is not protected

- Rule-based detection cannot prove that a file is secret-free. A bare password
  without a sensitive variable name, or an unknown token format, can pass
  through. Calibrate the rules for the workspace.
- Media and binary parts are not rewritten.
- Tool schemas and provider request options are not redacted.
- Persisted mappings (`storeSessionMappings: true`) contain the original values
  and are readable by any process with the same user. The path guard blocks
  obvious reads, not obfuscated shell commands.
- The plugin is not a sandbox. It limits what reaches the model, but a
  prompt-injected model can still misuse tools that are allowed to run locally.

## Restoring write/edit inputs

When a tool reads a file, the model sees placeholders. If it then writes the
file back, the plugin restores placeholders in the `write`/`edit` input before
the tool runs. This keeps the real values in the file instead of replacing them
with `[REDACTED:...]`.

Restoration only replaces placeholders that exist in the current session
mapping. Unknown placeholders stay as they are. Restoration is local; it does
not send the real values to the model. With the default in-memory mapping,
restoration works only while the plugin's `rredact serve` process is running.

## Security notes

- By default the mapping is memory-only. If you enable
  `storeSessionMappings`, the files contain the original values: never commit
  them and never send them to a model.
- The path guard blocks tool reads of `.rredact/mapping.json`,
  `.rredact/sessions/`, `.rredact/calibration/`, `.rredact/redacted/` and
  `.rredact/out/`. It is defense in depth, not a sandbox; a shell command can
  obfuscate a path. Add custom mapping paths from `.rredact.yaml` or `--mapping`
  to `sensitivePaths`.
- Redaction is regex- and heuristic-based. It cannot prove that content is
  secret-free. Calibrate the rules for the workspace (see the
  [rredact skill](../../.opencode/skills/rredact/SKILL.md)).
- The plugin limits what reaches the model. It does not prevent a
  prompt-injected model from misusing tools that are allowed to run locally.
- Calibration is a separate, explicit trust boundary. The plugin blocks
  `.rredact/calibration/` by default, so run calibration with the plugin
  disabled (or with `blockSensitivePaths: false`).

## Development

```bash
npm install
npm run typecheck
npm test          # unit tests; integration tests need target/debug/rredact
```

The integration tests are skipped when no rredact binary is found. Build it
first with `cargo build`.
