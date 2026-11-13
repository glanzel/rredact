# Regeln

## Aufbau

Jede Regel ist ein YAML-Mapping. Der minimale Regex-Fall:

```yaml
version: 1
rules:
  - id: internal-ticket
    description: Internes Ticket
    category: secret
    severity: high
    pattern: '\bTICKET-[0-9]{6}\b'
    placeholder: TICKET
```

| Feld | Pflicht | Bedeutung |
| --- | --- | --- |
| `id` | ja | eindeutig; Buchstaben, Zahlen, `.`, `-`, `_` |
| `description` | empfohlen | Text im Report |
| `category` | nein | `secret`, `credential`, `pii`, `other` |
| `severity` | nein | `low`, `medium`, `high`, `critical` |
| `type` | nein | `regex` (Default), `assignment`, `entropy` |
| `pattern` | bei `regex` | Rust-`regex`-Syntax (RE2-ähnlich; keine Lookarounds/Backreferences) |
| `flags` | nein | `i`, `m`, `s`, `x`, `a`, `u` |
| `group` | nein | Nummer oder Name der Gruppe, die ersetzt wird |
| `strip_quotes` | nein | Anführungszeichen um den Treffer herum stehen lassen |
| `placeholder` | nein | Typ im Platzhalter; Default aus `id` |
| `priority` | nein | kleiner = wird zuerst angewendet (Default 100) |
| `enabled` | nein | Default `true` |
| `paths` | nein | Globs, auf die die Regel angewendet wird |
| `exclude_paths` | nein | Globs, die ausgeschlossen werden |
| `allow_keys` | bei `assignment` | Variablennamen, die nie redigiert werden |
| `bare_values` | nein | `auto` (Default), `always`, `never`; in Quellcode-Dateien werden unquotierte Werte nur mit `always` redigiert |
| `validate` | nein | `luhn`, `iban`, `phone`, `basic_auth`, `ipv4`, `email` |
| `context_required` | nein | Liste von Regexen, die im Kontextfenster vorkommen müssen |
| `context_excluded` | nein | Liste von Regexen, die im Kontextfenster nicht vorkommen dürfen |
| `context_window` | nein | Zeichen links/rechts um den Treffer (Default 200) |
| `tags` | nein | freie Tags |

## Regex-Regeln

Nur eine Gruppe ersetzen:

```yaml
  - id: internal-account
    description: Interne Kontonummer
    category: pii
    severity: high
    pattern: 'account=(?P<number>[0-9]{8})'
    group: number
    placeholder: ACCOUNT
```

`group: number` ist gleichbedeutend mit `group: 1` (named group). Die
umgebende Struktur `account=` bleibt erhalten.

Die Rust-`regex`-Engine unterstützt **keine Lookarounds** (`(?=...)`, `(?!...)`)
und keine Backreferences. Nutze stattdessen Capture-Groups, Alternationen und
Prioritäten. Das ist Absicht: Die Regeln bleiben schnell und RE2-kompatibel.

Bei `flags: x` ignoriert die Rust-Engine Whitespace auch **innerhalb** von
Zeichenklassen. Für ein literales Leerzeichen `\x20` verwenden, z. B.
`[\x20-]` statt `[ -]`.

Mehrzeilige oder verbose Muster:

```yaml
  - id: private-key
    description: PEM Private Key
    category: secret
    severity: critical
    pattern: |-
      -----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----
    placeholder: PRIVATE_KEY
```

## Assignment-Regeln (Variablennamen)

Diese Regeln lesen Zeilen wie `.env`, YAML, TOML und einfaches JSON und
redigieren nur den Wert, wenn der Name passt:

```yaml
  - id: my-secret-variables
    description: Secret-Variablen
    category: secret
    severity: high
    type: assignment
    name_pattern: '(?i)(?:^|[_.-])(?:secret|token|passw(?:or)?d|api[_-]?key)(?:$|[_.-])'
    name_match: search        # oder fullmatch
    allow_keys: [TOKEN_TYPE, AUTH_METHOD]
    placeholder: ENV_SECRET
```

Unterstützte Formen:

```dotenv
export API_TOKEN="..."
DATABASE_PASSWORD='...'
```
```yaml
db_password: ...
```
```json
{"client_secret": "...", "public": "x"}
```
```toml
api_key = "..."
```

Anführungszeichen, Kommentare und JSON-Kommas bleiben erhalten.

`bare_values: auto` (Default) bedeutet: In `.env`, YAML, JSON, TOML und
ähnlichen Dateien werden auch unquotierte Werte redigiert. In Quellcode-Dateien
(`.py`, `.js`, `.ts`, `.go`, `.rs`, …) nur, wenn der Wert in Anführungszeichen
steht. Dadurch bleiben Typannotationen und Code-Ausdrücke wie
`token: str | None = None` oder `token = os.environ.get(...)` unangetastet,
während `password = "…"` erkannt wird.

Kommentarzeilen (`#`, `;`, `//`) werden ignoriert.

## Gitleaks-TOML

Dateien unter `.rredact/rules.d/*.toml` dürfen im Gitleaks-Format vorliegen:

```toml
[[rules]]
id = "workspace-secrets"
description = "Workspace-spezifische Secrets"
regex = '(?i)\b(db_password_production|internal_api_salt)\b\s*=\s*(.*)'
secretGroup = 2
```

`secretGroup` wird als `group` übernommen. Die Regel bekommt `category =
secret`, `severity = high` und `priority = 100`. Das ist praktisch für
LLM-generierte Regeldateien; die Rust-`regex`-Engine bleibt RE2-kompatibel.

## Kontextregeln

Ein Treffer kann zusätzlich vom umgebenden Text abhängen:

```yaml
  - id: invoice-number
    description: Rechnungsnummer nur im Rechnungskontext
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

`context_required` muss vollständig passen, `context_excluded` darf nicht
passen. Das Fenster wird um den Treffer gelegt und auf Zeichen-Grenzen
zugeschnitten.

Der OpenRedaction-Importer extrahiert einfache `regex.test(context)`-Checks aus
den JS-Validatoren nach diesem Schema. Komplexe oder beliebige JS-Logik kann
nicht exakt ausgeführt werden; solche Patterns bleiben standardmäßig
deaktiviert.

## Entropy-Regeln

Erkennt lange Zeichenketten mit hoher Shannon-Entropie. Standardmäßig
deaktiviert, weil Hashes, Base64-Assets und lange IDs False Positives erzeugen.

```yaml
  - id: high-entropy
    description: Zufälliger Token
    category: secret
    severity: medium
    type: entropy
    min_length: 32
    min_entropy: 4.2
    charset: base64       # oder hex, alnum
    enabled: true
    placeholder: HIGH_ENTROPY
```

## Prioritäten und Überlappungen

Regeln mit kleinerer `priority` gewinnen. Das ist wichtig, damit z. B. ein
bekannter Stripe-Key als `STRIPE_KEY` erkannt wird und nicht als generischer
`ENV_SECRET`:

- `5`–`10`: sehr spezifische Token-Formate
- `15`–`30`: Auth-Header, URL-Credentials
- `70`–`100`: PII und generische Variablennamen
- `900`: Entropy-Fallback

Überlappende Treffer werden verworfen; der spezifischere Treffer bleibt.

## Allowlist

Global in `.rredact.yaml`:

```yaml
allowlist:
  values:
    - changeme
    - my-public-placeholder
  patterns:
    - '^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$'
  keys:
    - PUBLIC_KEY
    - AUTH_TYPE
```

Die Default-Allowlist bleibt erhalten; eigene Einträge kommen hinzu.

## Laden und Überschreiben

Dateien mit `rredact:ignore-file` in den ersten 8 KB werden übersprungen.
Akzeptierte Findings lassen sich mit `rredact baseline create` in eine
`.rredact/baseline.json` schreiben; `scan --baseline ...` filtert sie anhand
von Regel-ID und Fingerprint.

Standardreihenfolge:

1. Core-Bundles (`builtin`): `secrets`, `env`
2. Default-Sets aus `defaults/*.yaml`, `*.yml` oder `*.toml`: Der Dateiname ist der Source-Name
   (`defaults/openredaction.yaml` → `openredaction`). Ohne `sources` werden **alle**
   Default-Sets geladen.
3. Inline-`rules` aus `.rredact.yaml`
4. `.rredact/rules.d/*.yaml`, `*.yml` und `*.toml`
5. `--rules DATEI` bzw. `RREDACT_RULES`

Lokal auswählen:

```yaml
# Default: Core + alle Default-Sets
builtin: [secrets, env]

# Nur die importierten OpenRedaction-Regeln
builtin: []
sources: [openredaction]

# Ohne importierte Default-Sets
builtin: [secrets, env]
sources: []

# Core + OpenRedaction
builtin: [secrets, env]
sources: [openredaction]
```

Aus Kompatibilitätsgründen kann ein Source-Name auch in `builtin` stehen:
`builtin: [secrets, env, openredaction]`.

Regel-IDs müssen eindeutig sein. Regeln deaktivieren:

```yaml
disable_rules:
  - openredaction-name
```

Standardmäßig deaktivierte Regeln wieder aktivieren:

```yaml
enable_rules:
  - openredaction-name

# Oder alle kontextabhängigen Regeln auf einmal:
enable_context_rules: true
  - high-entropy-token
```

Weitere Tools: einfach `defaults/<tool>.yaml` (oder `.yml`/`.toml`) ablegen;
die Datei wird standardmäßig geladen und ist über `sources: [<tool>]`
auswählbar.

`defaults/` ist ausschließlich für **generierte Importe** gedacht:

- `defaults/openredaction.yaml` – OpenRedaction (500+ Patterns)

Der Workflow `.github/workflows/update-defaults.yml` aktualisiert die Datei
wöchentlich. Importe überschreiben ihre Zieldatei vollständig; es wird nichts
gemerged.

```bash
rredact rules import-openredaction --force
```

Eigene Regeln gehören in getrennte Dateien:

- `.rredact/rules.d/user.yaml` – manuell gepflegt
- `.rredact/rules.d/llm.yaml` – vom LLM erzeugt

Breite, kontextabhängige OpenRedaction-Patterns werden importiert, aber
standardmäßig deaktiviert (`needs-context`). Sie lassen sich per
`enable_rules` gezielt aktivieren.

## Regeln von einem LLM schreiben lassen

Die Skill-Datei
[.opencode/skills/rredact/SKILL.md](../.opencode/skills/rredact/SKILL.md)
beschreibt die CLI-Initialisierung eines Workspace: scannen, Variablennamen
extrahieren, Regeln anlegen und validieren sowie einen sauberen Scan
verifizieren. Wichtig:

- Keine echten Secrets in Regeldateien schreiben.
- Immer `rredact rules validate DATEI` ausführen.
- Neue Regeln in `.rredact/rules.d/llm.yaml` ablegen; sie werden beim nächsten
  Scan/Redact automatisch geladen.
- Keine Lookarounds oder Backreferences verwenden.
- Regex lieber mit `\b` verankern und nicht zu breit machen.
- Für Strukturen `group` verwenden, statt den ganzen Treffer zu ersetzen.
