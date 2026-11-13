---
name: rredact
description: Calibrate a workspace/project for rredact by reviewing already-redacted output with a trusted LLM and adding rules for secrets that slipped through. Use when setting up rredact, auditing a repository, improving rules, or verifying that runtime redaction catches project-specific secrets. Triggers: calibrate rredact, initialize rredact, workspace secret audit, redaction gaps, no unredacted secrets, redaction rules.
---

# rredact calibration

This skill sets up a workspace for rredact and calibrates its rules.

The important principle is:

> **rredact must redact automatically at runtime. The LLM must never be trusted
> to redact voluntarily.**

This skill is only the one-time (or periodic) **calibration** step. It assumes
that rredact is installed and that runtime redaction/interception is active
(CLI, local API or the OpenCode plugin under `packages/opencode-rredact`).

During calibration, known rules are applied first. The LLM then reads the
**already-redacted output** and looks for secrets that slipped through the
standard rules. This is deliberately different from asking an LLM to avoid
reading sensitive values.

## Privacy warning — read this before calibrating

Calibration is a trust boundary. The redacted output removes known secrets, but
**unknown secrets may still be present**. Sending it to an LLM can therefore
send real secrets to that provider.

Before starting, the user must be told explicitly:

- Calibration may transmit secrets that the current rules do not catch.
- Use an LLM/provider the user trusts.
- Prefer a provider with zero data retention (ZDR) or, for maximum safety, a
  local model.
- Do not start calibration without explicit user consent.
- Never send the original workspace or `.rredact/mapping.json` to the LLM.

The critical production risk is prompt injection during normal LLM use. That is
mitigated by automatic runtime redaction, **not** by this skill and not by
trusting the model.

## Definition of done

A calibrated workspace has all of the following:

- rredact is installed and runtime redaction is active (or the user has been
  told exactly how it will be activated).
- `.rredact.yaml`, `.rredact/rules.d/user.yaml` and
  `.rredact/rules.d/llm.yaml` exist.
- A full audit was run, including ignored files such as local `.env`:
  `rredact scan . --all`.
- Known rules were applied to create a calibration copy.
- The LLM reviewed the calibration copy and reported remaining secret-like
  values without copying full secrets into its response.
- New project rules were written to `.rredact/rules.d/llm.yaml`.
- `rredact rules validate .rredact/rules.d/llm.yaml` passes.
- `rredact scan . --all --fail-on low` exits with code `0`.
- CI and/or pre-commit scan future changes.
- Calibration output and mapping are local, ignored and cleaned up.
- Any real secret that appeared during calibration is reported to the user as
  requiring rotation.

“Clean” means all **detected** candidates are handled and future scans fail on
new findings. Regex detection cannot prove that a repository is secret-free.

## 1. Install and activate runtime redaction first

The tool must not depend on model cooperation.

Current options:

- CLI: `rredact redact ...` before content leaves the machine.
- Local API: `rredact serve` for an integration.
- OpenCode plugin: `packages/opencode-rredact` redacts prompts, tool results and
  assembled model requests automatically before they reach the model.

Do not use this skill as a substitute for runtime redaction. Calibration only
improves the rules that runtime redaction uses.

## 2. Initialize the project configuration

If `.rredact.yaml` does not exist:

```bash
rredact init
```

This creates:

```text
.rredact.yaml
.rredact/rules.d/user.yaml   # human-maintained rules
.rredact/rules.d/llm.yaml    # this skill writes here
.rredact/.gitignore
```

`init` does not scan or redact anything. It only creates the configuration.

## 3. Record the current state

Inspect existing rules:

```bash
rredact rules list --format json
```

Run a full audit, including ignored local files:

```bash
rredact scan . --all --format json > /tmp/rredact-audit.json
```

The JSON report contains paths, line numbers, rule IDs and fingerprints — not
raw values.

## 4. Create the calibration copy

Apply the known rules to produce redacted copies:

```bash
rredact redact . --all --output-dir .rredact/calibration
```

This directory contains:

- placeholders for everything the current rules caught,
- **raw values for anything the rules missed**.

Treat `.rredact/calibration/` as sensitive data. It must not be committed and
must be deleted after calibration.

Do **not** give the LLM:

- the original workspace instead of the calibration copy,
- `.rredact/mapping.json`,
- the original files alongside the calibration output.

## 5. Let the LLM review the calibration copy

The LLM should read the files under `.rredact/calibration/` completely and look
for secrets that are still visible, for example:

- hardcoded passwords, tokens, API keys and private keys,
- credentials in URLs or connection strings,
- internal IDs that are secret in this project,
- customer or employee data,
- unusual high-entropy values,
- project-specific patterns already known from `user.yaml`.

The LLM must not try to avoid reading values. Its job is to find gaps in the
rules. It should, however, avoid copying full secret values into its final answer
or into rule files. Report findings by file, line, kind and a short description.

## 6. Write rules for the gaps

Write new rules only to `.rredact/rules.d/llm.yaml`. Do not edit generated files
under `defaults/`, and leave `user.yaml` to the human.

Prefer assignment rules for variable names:

```yaml
version: 1
rules:
  - id: workspace-secrets
    description: Workspace-specific secret variables
    category: secret
    severity: high
    type: assignment
    name_pattern: '(?i)(?:^|[_.-])(?:db_password_production|internal_api_salt|jwt_signing_key)(?:$|[_.-])'
    name_match: search
    bare_values: auto
    placeholder: WORKSPACE_SECRET
```

Use regex rules for structured values:

```yaml
  - id: internal-employee-id
    description: Internal employee ID
    category: pii
    severity: medium
    pattern: '\bEMP-\d{6}\b'
    placeholder: EMPLOYEE_ID
```

Use a capture group when only part of the match is sensitive:

```yaml
  - id: internal-account
    description: Internal account number
    category: pii
    severity: high
    pattern: 'account=(?P<number>[0-9]{8})'
    group: number
    placeholder: ACCOUNT
```

Use context checks for ambiguous identifiers:

```yaml
  - id: invoice-number
    description: Invoice number only in an invoice context
    category: pii
    severity: medium
    pattern: '\bINV-[0-9]{4}\b'
    context_required:
      - '(?i)invoice|rechnung|bill'
    context_excluded:
      - '(?i)example|test'
    context_window: 200
    placeholder: INVOICE
```

### Rule fields

| Field | Meaning |
| --- | --- |
| `id` | unique; letters, digits, `.`, `-`, `_` |
| `category` | `secret`, `credential`, `pii`, `other` |
| `severity` | `low`, `medium`, `high`, `critical` |
| `pattern` | Rust regex |
| `group` | capture group index or name to replace |
| `placeholder` | kind in `[REDACTED:KIND:N]` |
| `priority` | lower wins; default 100 |
| `paths` | optional globs, e.g. `["**/*.py"]` |
| `validate` | `luhn`, `iban`, `phone`, `basic_auth`, `ipv4`, `email` |
| `type` | `regex` (default), `assignment`, `entropy` |
| `name_pattern` | key regex for `assignment` rules |
| `allow_keys` | keys that must never be redacted |
| `bare_values` | `auto`, `always`, `never` |
| `context_required` | context regexes that must all match |
| `context_excluded` | context regexes that must not match |
| `context_window` | characters around the match; default 200 |

Built-in fallback rules use priority `190`–`200`. A project rule with the
default `priority: 100` wins over them.

Gitleaks-compatible TOML works too:

```toml
[[rules]]
id = "workspace-secrets"
description = "Workspace-specific secrets"
regex = '''(?i)(db_password_production|internal_api_salt)\s*=\s*(.*)'''
secretGroup = 2
```

## 7. Validate and test the new rules

```bash
rredact rules validate .rredact/rules.d/llm.yaml
```

Test against harmless example text, never a real secret:

```bash
printf 'db_password_production=example-value\n' \
  | rredact redact - --no-store --quiet
```

Expected:

```text
db_password_production=[REDACTED:WORKSPACE_SECRET:1]
```

Confirm the rule is loaded:

```bash
rredact rules list | grep workspace-secrets
```

## 8. Repeat calibration

Regenerate the calibration copy from the original workspace, now with the new
rules:

```bash
rredact redact . --all --output-dir .rredact/calibration
```

Review again with the LLM. Repeat until:

- no obvious secret remains in the calibration copy,
- every finding from `rredact scan . --all` is covered, allowlisted or
  reviewed as a false positive,
- no real secret is placed in a rule file.

## 9. Handle findings correctly

### Real secret

- Add a rule if the pattern is project-specific.
- Tell the user the value may already be in Git history and should be rotated.
- Never paste the full value into a rule, report or chat.

### False positive or intended example

- Add a narrow allowlist entry or a `context_excluded` check.
- Do not use a broad rule to hide it.

### Accepted false positive

Only after review, add it to the baseline:

```bash
rredact baseline create . --all
rredact scan . --all --baseline .rredact/baseline.json
```

Never baseline an actual secret.

## 10. Make the check permanent

Runtime redaction must be automatic. Calibration is not enough.

For CI/local verification:

```bash
rredact scan . --all --fail-on low
```

Use `--fail-on low` for a strict policy. Add pre-commit if desired:

```yaml
repos:
  - repo: https://github.com/<owner>/rredact
    rev: v0.1.0
    hooks:
      - id: rredact
```

Ensure `.rredact/mapping.json` and `.rredact/calibration/` are ignored:

```gitignore
.rredact/mapping.json
.rredact/calibration/
```

## 11. Clean up

After calibration:

- Delete `.rredact/calibration/` securely.
- Keep the mapping local; never commit it.
- Do not commit any sample text that contains real secrets.
- Report any secret that needs rotation.

The calibration copy contains real values for everything the rules missed. It
is not safe to keep around.

## 12. Final report

Report:

- which files were created or changed,
- which rules were added,
- validation result,
- final scan result,
- any real secrets that need rotation,
- any baseline entries and why they are false positives,
- how runtime redaction will be activated (CLI/API/OpenCode plugin),
- that calibration artifacts were removed.

## When a rule does not match

Check, in this order:

1. Is the file under `.rredact/rules.d/` and does it end in `.yaml`, `.yml` or
   `.toml`?
2. Does `rredact rules validate` pass?
3. Does `rredact rules list` show the rule and `ON = yes`?
4. Is a `paths` filter excluding the file?
5. Is a higher-priority rule (lower number) claiming the same span?
6. For `assignment` rules: does `name_pattern` match the actual key? Is the
   value quoted or bare, and is `bare_values` correct?
7. For code files: unquoted values are ignored in `bare_values: auto` mode; use
   a regex rule with `paths` if necessary.
8. Does a `context_required` check reject the match? Widen `context_window` or
   test the surrounding line.

## Important limitation

Detection is regex- and heuristic-based. It cannot prove that a repository is
secret-free. Calibration improves coverage; automatic runtime redaction limits
what reaches the model; CI fails on new detected findings. Prompt injection and
model misbehaviour are separate risks and must be handled by the runtime
integration, not by hoping the model cooperates.
