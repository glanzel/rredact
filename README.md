# rredact

`rredact` entfernt Secrets und personenbezogene Daten aus Text, bevor er an ein
LLM oder eine externe API geht – und kann die Platzhalter danach wieder
zurücksetzen. Es ist eine einzelne, schnelle Rust-Binärdatei mit CLI, lokaler
HTTP-API und Bibliothek.

```
PASSWORD=hunter2  ->  PASSWORD=[REDACTED:ENV_SECRET:1]
```

Der Platzhalter ist umkehrbar, solange die Mapping-Datei vorhanden ist. Diese
Datei enthält die Originalwerte und darf **niemals** committet oder an ein LLM
geschickt werden.

## Warum Rust

- **Single Binary:** kein Python, kein Node, keine Runtime.
- **Schnell:** Regex-Vorfilter im Mikrosekundenbereich; der LLM-Aufruf bleibt
  der langsame Teil.
- **Wenig Ressourcen:** kein NLP-Modell, kein Hintergrunddienst nur zum Tippen.
- **Erweiterbar:** Gitleaks-TOML, eigenes YAML, OpenRedaction-Import und später
  ein OpenCode-Plugin.

## Installation

```bash
cargo build --release
# Binary: target/release/rredact

# oder systemweit:
cargo install --path .
```

Im Projekt initialisieren:

```bash
rredact init
```

Das erzeugt `.rredact.yaml`, `.rredact/rules.d/user.yaml`,
`.rredact/rules.d/llm.yaml` und passende `.gitignore`-Einträge.

## Schnellstart

```bash
# Nur prüfen (Exit 1 bei Findings ab "high")
rredact scan .

# Redigierte Kopien nach .rredact/redacted/ schreiben
rredact redact .

# Einzelne Datei nach stdout
rredact redact app.env

# Platzhalter wiederherstellen
rredact restore .rredact/redacted/app.env

# Lokale API für ein externes LLM
rredact serve --token "$RREDACT_API_TOKEN"
```

### Formate

```bash
rredact scan . --format json
rredact scan . --format sarif --output rredact.sarif
rredact scan . --fail-on critical
rredact scan . --baseline .rredact/baseline.json   # optional
```

### Modi

- `placeholder` (Default): `[REDACTED:KIND:1]`, umkehrbar.
- `mask`: `***`, nicht umkehrbar.
- `hash`: `[REDACTED:KIND:abcdef123456]`, nicht umkehrbar.

```bash
rredact redact app.env --mode mask
```

## Variablennamen für LLM-Regeln extrahieren

Genau für den ressourcenschonenden Workflow gedacht: erst einmalig die
Variablennamen extrahieren, dann vom LLM eine Regeldatei bauen lassen. Es
werden **nur Namen und Positionen** ausgegeben, **keine Werte**.

```bash
# Standard: nur verdächtige Namen (secret, token, password, key, ...)
rredact variables . --format text

# Alle erkannten Zuweisungsnamen
rredact variables . --all-names --format json

# Fertigen Prompt für ein lokales/Cloud-LLM ausgeben
rredact variables . --format prompt > prompt.txt
```

Das LLM kann daraus YAML für `.rredact/rules.d/llm.yaml` oder eine
Gitleaks-kompatible `.toml` bauen:

```toml
[[rules]]
id = "workspace-secrets"
description = "Workspace-spezifische Secrets"
regex = '(?i)\b(db_password_production|internal_api_salt)\b\s*=\s*(.*)'
secretGroup = 2
```

`rredact` lädt `.rredact/rules.d/*.yaml`, `*.yml` und `*.toml` automatisch.
Gitleaks-Regeln werden als `secret`/`high` mit `secretGroup` übernommen.

## Regeln

Regeln werden aus mehreren Quellen geladen:

1. Core-Bundles: `secrets`, `env`
2. Default-Sets aus `defaults/*.yaml`, `*.yml` oder `*.toml` – der Dateiname ist der Source-Name,
   z. B. `defaults/openredaction.yaml` → `openredaction`. **Standardmäßig werden alle
   Default-Sets geladen.**
3. `.rredact.yaml` / `.rredact.toml` → `rules: [...]`
4. `.rredact/rules.d/*.yaml`, `*.yml`, `*.toml` (hier schreibt auch ein LLM)
5. `--rules DATEI` und `RREDACT_RULES`

`defaults/` ist ausschließlich für generierte Importe gedacht. Eigene Regeln
gehören in `.rredact/rules.d/user.yaml`, LLM-Regeln in
`.rredact/rules.d/llm.yaml`.

Lokal auswählen:

```yaml
# Default: Core + alle Default-Sets (sources einfach weglassen)
builtin: [secrets, env]

# Core + OpenRedaction
builtin: [secrets, env]
sources: [openredaction]

# Nur Core, keine importierten Defaults
builtin: [secrets, env]
sources: []

# Nur die importierten OpenRedaction-Regeln
builtin: []
sources: [openredaction]
```

`builtin` und `sources` sind additiv. Aus Kompatibilitätsgründen funktioniert
auch noch `builtin: [secrets, env, openredaction]`; neue Default-Dateien sollten
aber über `sources` ausgewählt werden.

Beispiel für eine eigene YAML-Regel:

```yaml
version: 1
rules:
  - id: internal-employee-id
    description: Interne Mitarbeiter-ID
    category: pii
    severity: medium
    pattern: '\bEMP-\d{6}\b'
    placeholder: EMPLOYEE_ID
```

Validieren:

```bash
rredact rules validate .rredact/rules.d/llm.yaml
rredact rules list
```

Mehr dazu in [docs/rules.md](docs/rules.md).

### Variablennamen aus `.env` & Co.

Die Regel `sensitive-variable-assignment` redigiert den Wert, wenn der
Variablenname nach einem Secret aussieht, z. B.:

```dotenv
export DATABASE_PASSWORD="..."   # wird redigiert
STRIPE_SECRET_KEY=...            # wird redigiert
PUBLIC_KEY=...                   # bleibt
AUTH_TYPE=oauth                  # bleibt
```

Das funktioniert auch für `KEY: value` (YAML), `"key": "value"` (JSON) und
`key = value` (TOML). Kommentare und Anführungszeichen bleiben erhalten.

## Importierte Defaults

`defaults/` enthält ausschließlich **generierte Importe** von Plattformen. Diese
Datei wird nicht von Hand bearbeitet und nicht gemerged:

- `defaults/openredaction.yaml` – OpenRedaction (TypeScript-Patterns, 500+
  Patterns: Kontakt-, Finanz-, Behörden-, Personal-, Branchen- und
  Digital-Identity-PII)

Der Workflow
[.github/workflows/update-defaults.yml](.github/workflows/update-defaults.yml)
aktualisiert die Datei wöchentlich und committet Änderungen. Jeder Import
überschreibt seine Zieldatei vollständig; es wird nichts aus lokalen Regeln
hineingemischt.

Manuell:

```bash
rredact rules import-openredaction --force
```

Optional mit eigener Quelle/Zieldatei:

```bash
rredact rules import-openredaction \
  --source ./openredaction \
  --output defaults/openredaction.yaml \
  --force
```

Der Importer liest die TypeScript-Pattern-Objekte. Nicht unterstützte
Regex-Konstrukte werden mit Hinweis übersprungen. Es werden **alle** Patterns
importiert, die OpenRedaction anbietet.

Breite, kontextabhängige OpenRedaction-Patterns (z. B. `NAME`, `USERNAME`,
nationale IDs, Nummern-IDs) werden zwar importiert, aber standardmäßig
**deaktiviert** und mit `needs-context` getaggt. Ihre JS-Validatoren können wir
nicht ausführen; ohne diese Validatoren würden sie zu viele False Positives
erzeugen. Gezielt aktivieren:

```yaml
enable_rules:
  - openredaction-name

# Oder alle als "needs-context" markierten Regeln auf einmal:
enable_context_rules: true
```

### Getrennte Dateien für Import, Handarbeit und LLM

- `defaults/*` → **nur Importe**, generiert, nicht bearbeiten.
- `.rredact/rules.d/user.yaml` → **manuell** gepflegte Projektregeln.
- `.rredact/rules.d/llm.yaml` → Regeln, die ein **LLM** erzeugt.

`rredact init` legt `user.yaml` und `llm.yaml` getrennt an. Beide werden
automatisch geladen.

## API für ein externes LLM

`rredact serve` startet standardmäßig nur auf `127.0.0.1:8787`.

```bash
rredact serve --token "$RREDACT_API_TOKEN"

curl -s http://127.0.0.1:8787/redact \
  -H "Authorization: Bearer $RREDACT_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"text":"PASSWORD=hunter2","path":"app.env"}'
```

Endpunkte: `GET /health`, `GET /rules`, `POST /redact`, `POST /restore`,
`POST /rules/validate`, `POST /rules/reload`. Details in
[docs/api.md](docs/api.md).

Die mitgelieferte Skill
[.opencode/skills/rredact/SKILL.md](.opencode/skills/rredact/SKILL.md)
beschreibt **ausschließlich** das Anlegen und Validieren eigener Regex-Regeln
per CLI. Sie enthält keine API- oder Restore-Anweisungen.

## OpenCode-Plugin

Der Kern ist als Bibliothek + lokale API geschnitten. Die geplante
Plugin-Integration (Tool-Hooks, Session-Mappings, Cleanup) ist in
[docs/opencode-plugin.md](docs/opencode-plugin.md) beschrieben.

## CI

Der Workflow [.github/workflows/rredact.yml](.github/workflows/rredact.yml)
führt `cargo fmt --check`, Clippy, Tests und den Repository-Scan aus. Findings
ab `high` lassen den Job fehlschlagen; der SARIF-Report wird zu GitHub Code
Scanning hochgeladen. Für GitLab liegt ein Beispiel in
[examples/gitlab-ci.yml](examples/gitlab-ci.yml).

Für Pre-commit:

```yaml
repos:
  - repo: https://github.com/<owner>/rredact
    rev: v0.1.0
    hooks:
      - id: rredact
```

## Sicherheit

- `.rredact/mapping.json` enthält die Originalwerte. Sie wird mit Modus `0600`
  geschrieben und ist in `.gitignore` eingetragen.
- Die API bindet nur an Loopback. Für andere Hosts ist ein Token Pflicht
  (oder explizit `--allow-remote`).
- `scan` schreibt keine Mapping-Datei.
- `--no-store` hält das Mapping nur im Speicher; nach Prozessende ist keine
  Restaurierung mehr möglich.
- `--show-values` gibt Rohwerte im Report aus; nur lokal verwenden.
- Eine Baseline enthält Hashes (Fingerprints), keine Rohwerte.
- Die Erkennung ist regex-/heuristikbasiert. Namen, Adressen ohne Straßenname
  oder frei formulierte Secrets brauchen zusätzliche Regeln oder später ein
  NER-Plugin.

## Entwicklung

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Lizenz

MIT. Die OpenRedaction-Regeln stehen ebenfalls unter MIT; siehe
[NOTICE](NOTICE).
