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
  ├─ tool.execute.before -> sensible Pfade blockieren, write/edit-Inputs wiederherstellen
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
| `storeSessionMappings` | `false` | Session-Mappings unter `.rredact/sessions/` speichern |
| `blockSensitivePaths` | `true` | Tools am Lesen sensibler Dateien hindern |
| `sensitivePaths` | `.rredact/mapping.json`, `.rredact/sessions`, `.rredact/calibration`, `.rredact/redacted`, `.rredact/out` | Pfade, die Tools nicht lesen dürfen |
| `startupTimeoutMs` | `10_000` | Wartezeit auf die Server-Adresse |
| `requestTimeoutMs` | `15_000` | Timeout pro API-Request |

## Server-Lebenszyklus

Ohne `url` startet das Plugin:

```bash
rredact serve --host 127.0.0.1 --port 0 --token <zufällig> --no-store
```

Es liest die Adresse aus der Zeile `listening on http://...`, prüft
`GET /health` und hält das Token nur im Speicher. Beim Entladen des Plugins
wird der Prozess beendet. Das Arbeitsverzeichnis ist das OpenCode-Projekt, damit
`.rredact.yaml` und `.rredact/rules.d/*.yaml` automatisch geladen werden.

`--no-store` ist Default: Das Mapping lebt nur im `rredact serve`-Prozess.
Platzhalter bleiben während der Laufzeit wiederherstellbar, aber nicht nach
einem Server-Neustart. Mit `storeSessionMappings: true` werden sie unter
`.rredact/sessions/` persistiert. Diese Dateien enthalten Originalwerte und sind
für jeden Prozess desselben Benutzers lesbar; der Pfad-Guard blockiert nur
offensichtliche Zugriffe.

## Sessions

Jede OpenCode-Session bekommt ein eigenes Mapping, standardmäßig nur im
Speicher. Beim `session.deleted`-Event löscht das Plugin das Mapping über
`DELETE /sessions/:session`. Ohne diese Trennung würden parallele Agents ihre
Platzhalter vermischen.

## Fail-closed

Mit `failClosed: true` (Default) wirft der Hook bei Start- oder Request-Fehlern.
OpenCode bricht dann Prompt, Tool-Aufruf oder Model-Request ab, statt Klartext
weiterzugeben. `failClosed: false` ist nur zum Debuggen gedacht.

Der Pfad-Guard (`blockSensitivePaths`) blockiert unabhängig von `failClosed`
jeden Tool-Aufruf, der auf eine sensible Datei zielt.

## Wiederherstellung

Liest ein Tool eine Datei, sieht das Modell Platzhalter. Schreibt es die Datei
zurück, stellt das Plugin die Platzhalter im `write`/`edit`-Input vor dem
Ausführen wieder her. So überschreibt der Agent echte Werte nicht mit
`[REDACTED:...]`. Die Wiederherstellung ist lokal und sendet keine Werte an das
Modell.

## Sicherheit

- Das Mapping lebt standardmäßig nur im Speicher. Persistierte Mappings
  enthalten Originalwerte: nie committen, nie an ein Modell senden.
- Der Pfad-Guard blockiert Tool-Zugriffe auf `.rredact/mapping.json`,
  `.rredact/sessions/`, `.rredact/calibration/`, `.rredact/redacted/` und
  `.rredact/out/`. Das ist Defense in Depth, keine Sandbox: Ein Shell-Befehl
  kann einen Pfad verschleiern.
- Redaktion ist regex- und heuristikbasiert. Sie kann nicht beweisen, dass ein
  Workspace geheimnisfrei ist. Regeln kalibrieren (siehe
  [Skill](../.opencode/skills/rredact/SKILL.md)).
- Das Plugin begrenzt, was das Modell erreicht. Es verhindert nicht, dass ein
  per Prompt-Injection gesteuertes Modell lokal erlaubte Tools missbraucht.
- Kalibrierung ist eine separate, ausdrückliche Trust-Boundary und ersetzt
  keine Runtime-Redaktion. Da der Pfad-Guard `.rredact/calibration/` blockiert,
  läuft die Kalibrierung mit deaktiviertem Plugin oder mit
  `blockSensitivePaths: false`.

## Was wird redigiert?

Alle Tool-Ergebnisse laufen durch `execute.after` und zusätzlich durch den
`context`-Hook, bevor ein Model-Request rausgeht. Damit werden auch
Dateiinhalte, Shell-Ausgaben und Anhänge erfasst, die über andere Wege in den
Kontext gelangen.

Nicht geschützt sind:

- Secrets, die keine Regel erkennen (z. B. ein Passwort ohne Variablennamen
  oder ein unbekanntes Token-Format),
- Binär- und Medieninhalte,
- Tool-Schemas und Provider-Optionen,
- obfuskierte Shell-Zugriffe auf persistierte Mapping-Dateien.

Details und Beispiele:
[packages/opencode-rredact/README.md](../packages/opencode-rredact/README.md).
