# OpenCode-Plugin

Das Plugin liegt unter
[`packages/opencode-rredact`](../packages/opencode-rredact/README.md) und ist
für OpenCode V2 (`@opencode/plugin` 2.x) geschrieben. Es redigiert automatisch
und fail-closed; es verlässt sich nicht darauf, dass das Modell freiwillig
vorsichtig ist.

```text
OpenCode server
  ├─ session.prompt      -> Prompt bei der Annahme redigieren
  ├─ tool.execute.after  -> Tool-Ergebnis vor dem Speichern redigieren
  ├─ tool.execute.before -> Platzhalter in write/edit-Inputs wiederherstellen
  └─ session.context     -> Systemtext + Transkript vor dem Versand redigieren
      (zusätzlich compaction, title und generate)

                    HTTP (Loopback, zufälliges Token)
                              |
                     rredact serve (Rust)
                              |
                   Regeln + Mapping pro Session
```

Die `context`-Hooks sind der maßgebliche Egress-Punkt: Sie laufen unmittelbar
vor dem Model-Request und erfassen auch Inhalte, die den Prompt-Hook umgehen,
etwa synthetische Nachrichten, Skill-Inhalte und Anhänge.

## Voraussetzungen

- OpenCode V2
- `rredact`-Binärdatei, entweder im `PATH`, aus diesem Repository gebaut oder
  über die Option `binary` gesetzt

```bash
cargo build --release
# target/release/rredact
```

## Laden

Lokales Paket in `opencode.jsonc`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "./packages/opencode-rredact",
      "options": {
        "binary": "/absoluter/pfad/zu/rredact"
      }
    }
  ]
}
```

Alternativ ein Wrapper unter `.opencode/plugins/rredact/index.ts`:

```ts
export { default } from "../../../packages/opencode-rredact/src/index.ts"
```

Plugins unter `.opencode/plugins/` werden automatisch geladen. Das Plugin
sollte erst aktiviert werden, wenn die Binärdatei verfügbar ist: Der Default
ist fail-closed und blockiert Prompts, wenn rredact nicht startet.

## Optionen

| Option | Default | Bedeutung |
| --- | --- | --- |
| `binary` | `RREDACT_BIN` oder `rredact` | Pfad zur Binärdatei |
| `url` | `RREDACT_URL` | Bereits laufender Server statt Neustart |
| `token` | `RREDACT_API_TOKEN` | Token für einen externen Server |
| `args` | `[]` | Zusätzliche Argumente für `rredact serve` |
| `env` | `{}` | Zusätzliche Umgebungsvariablen |
| `failClosed` | `true` | Bei Fehlern blockieren statt Klartext senden |
| `redactPrompts` | `true` | Prompts bei der Annahme redigieren |
| `redactToolResults` | `true` | Tool-Ergebnisse redigieren |
| `redactContext` | `true` | Model-Requests inkl. compaction/title/generate redigieren |
| `restoreToolInputs` | `true` | Platzhalter in write/edit-Inputs wiederherstellen |
| `restoreTools` | `write`, `edit`, `multiedit`, `apply_patch` | Tools für die Wiederherstellung |
| `startupTimeoutMs` | `10000` | Wartezeit auf die Server-Adresse |
| `requestTimeoutMs` | `15000` | Timeout pro API-Request |

## Server-Lebenszyklus

Ohne `url` startet das Plugin:

```bash
rredact serve --host 127.0.0.1 --port 0 --token <zufällig>
```

Es liest die Adresse aus der Zeile `listening on http://...`, prüft
`GET /health` und hält das Token nur im Speicher. Beim Entladen des Plugins
wird der Prozess beendet. Das Arbeitsverzeichnis ist das OpenCode-Projekt, damit
`.rredact.yaml` und `.rredact/rules.d/*.yaml` automatisch geladen werden.

## Sessions

Jede OpenCode-Session bekommt ein eigenes Mapping unter
`.rredact/sessions/<sha256>.json` (Modus `0600`, von Git ignoriert). Beim
`session.deleted`-Event löscht das Plugin die Datei über
`DELETE /sessions/:session`. Ohne diese Trennung würden parallele Agents ihre
Platzhalter vermischen.

## Fail-closed

Mit `failClosed: true` (Default) wirft der Hook bei Start- oder Request-Fehlern.
OpenCode bricht dann Prompt, Tool-Aufruf oder Model-Request ab, statt Klartext
weiterzugeben. `failClosed: false` ist nur zum Debuggen gedacht.

## Wiederherstellung

Liest ein Tool eine Datei, sieht das Modell Platzhalter. Schreibt es die Datei
zurück, stellt das Plugin die Platzhalter im `write`/`edit`-Input vor dem
Ausführen wieder her. So überschreibt der Agent echte Werte nicht mit
`[REDACTED:...]`. Die Wiederherstellung ist lokal und sendet keine Werte an das
Modell.

## Sicherheit

- Das Mapping enthält Originalwerte. Nie committen, nie an ein Modell senden.
- Redaktion ist regex- und heuristikbasiert. Sie kann nicht beweisen, dass ein
  Workspace geheimnisfrei ist. Regeln kalibrieren (siehe
  [Skill](../.opencode/skills/rredact/SKILL.md)).
- Das Plugin begrenzt, was das Modell erreicht. Es verhindert nicht, dass ein
  per Prompt-Injection gesteuertes Modell lokal erlaubte Tools missbraucht.
- Kalibrierung ist eine separate, ausdrückliche Trust-Boundary und ersetzt
  keine Runtime-Redaktion.

Details und Beispiele:
[packages/opencode-rredact/README.md](../packages/opencode-rredact/README.md).
