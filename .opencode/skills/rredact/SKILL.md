---
name: rredact
description: Create and validate project-specific rredact regex rules via the CLI. Use when an LLM should add or fix rules in .rredact/rules.d/*.yaml or a Gitleaks-compatible .toml file. Triggers: rredact rule, regex rule, redaction rule, .rredact/rules.d, rule generation.
---

# rredact: Regex-Regeln anlegen

This skill is **only** about creating, validating and testing rredact rules with
the CLI.

## Rules for rule authoring

1. Never put real secrets into a rule file. Rules contain only patterns and
   metadata.
2. Do not duplicate an existing `id`. Check with:
   ```bash
   rredact rules list --format json
   ```
3. The engine is the Rust `regex` crate (RE2-like). Do **not** use lookarounds
   (`(?=`, `(?!`, `(?<=`, `(?<!`) or backreferences.
4. With `flags: x`, whitespace inside character classes is ignored too. Use
   `\x20` for a literal space, e.g. `[\x20-]` instead of `[ -]`.
5. Anchor patterns with `\b` and keep them narrow.
6. Validate before reporting success:
   ```bash
   rredact rules validate .rredact/rules.d/llm.yaml
   ```

## Optional: get variable names without values

If the user has not supplied names, extract names only:

```bash
rredact variables . --format text
rredact variables . --format json
```

This never prints variable values. Use the names to build assignment rules.

## Where rules go

Write new rules to `.rredact/rules.d/llm.yaml`. This file is loaded
automatically. A Gitleaks-compatible `.toml` file in the same directory also
works.

## YAML format

Minimal regex rule:

```yaml
version: 1
rules:
  - id: internal-employee-id
    description: Internal employee ID
    category: pii
    severity: medium
    pattern: '\bEMP-\d{6}\b'
    placeholder: EMPLOYEE_ID
```

Replace only a capture group:

```yaml
  - id: internal-account
    description: Internal account number
    category: pii
    severity: high
    pattern: 'account=(?P<number>[0-9]{8})'
    group: number
    placeholder: ACCOUNT
```

Variable-name rule (preferred for `.env`, YAML, JSON, TOML):

```yaml
  - id: my-workspace-secrets
    description: Workspace-specific secret variables
    category: secret
    severity: high
    type: assignment
    name_pattern: '(?i)(?:^|[_.-])(?:db_password_production|internal_api_salt|jwt_signing_key)(?:$|[_.-])'
    name_match: search
    bare_values: auto
    placeholder: WORKSPACE_SECRET
```

Fields:

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
| `validate` | optional `luhn`, `iban`, `phone`, `basic_auth` |
| `type` | `regex` (default), `assignment`, `entropy` |
| `name_pattern` | key regex for `assignment` rules |
| `allow_keys` | keys that must never be redacted |
| `bare_values` | `auto`, `always`, `never` |

Built-in fallback rules use priority `190`–`200`. A project rule with the
default `priority: 100` wins over them.

## Gitleaks TOML

```toml
[[rules]]
id = "workspace-secrets"
description = "Workspace-specific secrets"
regex = '''(?i)(db_password_production|internal_api_salt)\s*=\s*(.*)'''
secretGroup = 2
```

## Workflow

1. Inspect existing IDs:
   ```bash
   rredact rules list --format json
   ```
2. Optionally collect variable names:
   ```bash
   rredact variables . --format text
   ```
3. Write the new rule file:
   ```bash
   cat > .rredact/rules.d/llm.yaml <<'EOF'
   version: 1
   rules:
     - id: workspace-secrets
       description: Workspace-specific secrets
       category: secret
       severity: high
       type: assignment
       name_pattern: '(?i)(?:^|[_.-])(?:db_password_production|internal_api_salt)(?:$|[_.-])'
       placeholder: WORKSPACE_SECRET
   EOF
   ```
4. Validate:
   ```bash
   rredact rules validate .rredact/rules.d/llm.yaml
   ```
5. Test against harmless example text:
   ```bash
   printf 'db_password_production=example-value\n' | rredact redact - --no-store --quiet
   ```
   The output should contain `[REDACTED:WORKSPACE_SECRET:1]`.
6. Confirm the rule is loaded:
   ```bash
   rredact rules list | grep workspace-secrets
   ```

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

## Done

Report:

- the rule file changed,
- the validation result,
- the command and output that proves the rule matched.
