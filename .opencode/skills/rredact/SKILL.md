---
name: rredact
description: Initialize a workspace, project or system for rredact and create/validate CLI rules until no detected secrets remain unredacted. Use when setting up rredact, auditing a repository, adding or fixing rules, or verifying that scans are clean. Triggers: initialize rredact, workspace secret scan, no unredacted secrets, rredact init, redaction rules.
---

# rredact workspace initialization

This skill initializes a workspace/project for safe use with rredact and then
creates, validates and tests the rules needed so that **no detected secrets
remain unredacted**.

It is a CLI-only workflow. Do not use the HTTP API, do not restore placeholders,
and do not read or write mapping files.

## Definition of done

A workspace is initialized when all of the following are true:

- `rredact init` has created `.rredact.yaml`, `.rredact/rules.d/user.yaml` and
  `.rredact/rules.d/llm.yaml`.
- The current rules have been inspected (`rredact rules list`).
- A full audit has run, including ignored files such as local `.env` files
  (`rredact scan . --all`).
- Every reported finding is either:
  - covered by a project rule,
  - a reviewed false positive that is allowlisted, or
  - a reviewed false positive recorded in the baseline.
- `rredact scan . --all --fail-on low` exits with code `0`.
- `rredact rules validate .rredact/rules.d/llm.yaml` passes.
- CI and/or pre-commit run a scan on future changes.
- No original secret value appears in a rule file or in the final report.
- The mapping file was not read, changed or committed.
- The user has been told about any real secret that must be rotated and about
  the limits of regex detection.

Regex detection cannot prove that a workspace is secret-free. “Clean” means
that all detected candidates are handled and that future scans fail on new
findings.

## Non-negotiable rules

1. Never put real secrets into rule files. Rules contain only patterns and
   metadata.
2. Never read, print, commit or modify `.rredact/mapping.json`.
3. Do not baseline real secrets. Baselines are only for reviewed false
   positives.
4. Do not rewrite tracked files in place without explicit user approval. The
   normal safe output is a redacted copy under `.rredact/redacted/`.
5. Do not edit generated files under `defaults/`.
6. Write new rules to `.rredact/rules.d/llm.yaml`. Leave
   `.rredact/rules.d/user.yaml` to the human.
7. The engine is the Rust `regex` crate (RE2-like). Do **not** use lookarounds
   (`(?=`, `(?!`, `(?<=`, `(?<!`) or backreferences.
8. With `flags: x`, whitespace inside character classes is ignored too. Use
   `\x20` for a literal space, e.g. `[\x20-]` instead of `[ -]`.
9. Validate before reporting success.

## 1. Initialize the tooling

Check the binary and initialize the project if needed:

```bash
rredact --version

# only if .rredact.yaml does not exist yet
rredact init
```

`init` creates:

```text
.rredact.yaml
.rredact/rules.d/user.yaml   # human-maintained rules
.rredact/rules.d/llm.yaml    # this skill writes here
.rredact/.gitignore
```

## 2. Inspect what already exists

```bash
rredact rules list --format json
```

Check for existing IDs before adding anything. Never duplicate an `id`.

## 3. Audit the whole workspace

Use `--all` so that gitignored local files such as `.env` are included. The
configured skip paths still apply.

```bash
rredact scan . --all --format json > /tmp/rredact-audit.json
```

The JSON report contains fingerprints and positions, not raw values.

Review findings by rule, category, severity and path. Do not print raw values
unless the user explicitly asks for local debugging.

## 4. Extract variable names without values

If the user has not supplied names, collect names only:

```bash
rredact variables . --all-names --format json
```

For an external LLM, generate a ready-to-use prompt:

```bash
rredact variables . --all-names --format prompt > /tmp/rredact-prompt.txt
```

`variables` never prints variable values. It is safe to hand the names to an
LLM.

## 5. Write project rules

Write to `.rredact/rules.d/llm.yaml`. Prefer assignment rules for variable
names, because they redact only the value and keep the key intact.

Example assignment rule:

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

Example regex rule:

```yaml
  - id: internal-employee-id
    description: Internal employee ID
    category: pii
    severity: medium
    pattern: '\bEMP-\d{6}\b'
    placeholder: EMPLOYEE_ID
```

Example with a capture group:

```yaml
  - id: internal-account
    description: Internal account number
    category: pii
    severity: high
    pattern: 'account=(?P<number>[0-9]{8})'
    group: number
    placeholder: ACCOUNT
```

Context-aware rule:

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

Gitleaks-compatible TOML is also supported in the same directory:

```toml
[[rules]]
id = "workspace-secrets"
description = "Workspace-specific secrets"
regex = '''(?i)(db_password_production|internal_api_salt)\s*=\s*(.*)'''
secretGroup = 2
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

## 6. Validate and test

```bash
rredact rules validate .rredact/rules.d/llm.yaml
```

Test against harmless example text (never a real secret):

```bash
printf 'db_password_production=example-value\n' \
  | rredact redact - --no-store --quiet
```

Expected output:

```text
db_password_production=[REDACTED:WORKSPACE_SECRET:1]
```

Confirm that the rule is loaded:

```bash
rredact rules list | grep workspace-secrets
```

## 7. Resolve every finding

After adding rules, rerun the audit:

```bash
rredact scan . --all --format json > /tmp/rredact-audit.json
```

Handle the remaining findings in this order:

1. **Real secret**  
   Add a rule if the format is project-specific. Tell the user that the value
   may already be in Git history and should be rotated. Do not paste the value
   into a report, rule or chat.

2. **False positive / intended example**  
   Add a narrow allowlist entry or a `context_excluded` check. Do not use a
   broad rule to hide it.

3. **Accepted false positive**  
   Only after review, add it to the baseline:

   ```bash
   rredact baseline create . --all
   ```

   Then verify:

   ```bash
   rredact scan . --all --baseline .rredact/baseline.json
   ```

Never baseline an actual secret.

## 8. Produce redacted copies

By default, redact to a separate directory; do not modify the workspace:

```bash
rredact redact . --all --output-dir .rredact/redacted
```

Only use `--in-place` after explicit user approval:

```bash
rredact redact . --all --in-place
```

Verify the result:

```bash
rredact restore .rredact/redacted/app.env
```

## 9. Make the check permanent

Ensure CI and/or pre-commit fail on new findings:

```bash
# CI / local verification
rredact scan . --all --fail-on high
```

For a strict workspace policy, use `--fail-on low` so any finding fails.

The repository already contains a GitHub Actions workflow and a pre-commit hook.
If the project does not have them yet, recommend adding:

```yaml
repos:
  - repo: https://github.com/<owner>/rredact
    rev: v0.1.0
    hooks:
      - id: rredact
```

The mapping file must remain in `.gitignore`:

```gitignore
.rredact/mapping.json
```

## 10. Definition of done check

Run:

```bash
rredact rules validate .rredact/rules.d/llm.yaml
rredact scan . --all --fail-on low
```

Both must succeed.

Then report:

- which files were created or changed,
- which rules were added,
- the validation result,
- the final scan result,
- any real secrets that need rotation,
- any baseline entries and why they are false positives,
- whether CI/pre-commit is configured.

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
8. Does a `context_required` check reject the match? Test with the surrounding
   line or widen `context_window`.

## Important limitation

Detection is regex- and heuristic-based. It cannot prove that a repository is
secret-free. The initialization is complete when all detected candidates are
handled and CI scans fail on new findings, not when every possible secret in the
universe is guaranteed to be found.
