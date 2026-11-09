# OpenCode-Plugin (Ausbaustufe)

Der Kern ist bewusst als Bibliothek + lokale API geschnitten, damit später ein
OpenCode-Plugin ohne Änderungen an der Erkennung ergänzt werden kann. Dieses
Dokument beschreibt die geplante Integration; der eigentliche Plugin-Code folgt
in einem separaten Paket.

## Ziel

Ein OpenCode-Plugin soll:

1. Tool-Ausgaben (Dateiinhalte, Shell-Logs, API-Antworten) redigieren, bevor sie
   im Modellkontext landen.
2. Vom Modell erzeugte Tool-Argumente (z. B. `write`-Inhalte) vor dem Ausführen
   optional wiederherstellen, damit Platzhalter nicht in Dateien landen.
3. Pro OpenCode-Session ein eigenes Mapping verwenden, damit parallele Agents
   sich nicht vermischen.
4. Bei Sitzungsende das Mapping löschen oder explizit aufbewahren.

## Warum eine API und keine direkte Bibliothek?

OpenCode-Plugins laufen in einer TypeScript/Node-Umgebung. Der `rredact`-Kern
ist eine Rust-Binärdatei mit lokaler HTTP-API. Die API entkoppelt beides:

```
OpenCode plugin (TS)  --HTTP-->  rredact serve (Rust)  -->  Regeln + Mapping
```

Alternativ kann das Plugin die CLI per `child_process` aufrufen; die API ist
aber schneller und hält das Mapping im Prozess.

## Benötigte API-Erweiterung

Aktuell ist das Mapping global pro Server. Für Plugins kommt ein optionales
`session`-Feld hinzu:

```json
POST /redact
{"text": "...", "session": "ses_abc123"}

POST /restore
{"text": "...", "session": "ses_abc123"}
```

Serverseitig:

```
.rredact/sessions/<session>.json   (Modus 0600, in .gitignore)
```

Damit kann das Plugin:

- pro Session redigieren/restaurieren,
- beim Session-Ende `DELETE /sessions/<id>` aufrufen,
- bei Absturz verwaiste Dateien über eine TTL aufräumen.

Bis dahin kann das Plugin ein eigenes Mapping-Verzeichnis über
`--mapping .rredact/sessions/<id>.json` und einen eigenen Serverstart pro
Session verwenden (langsamer, aber isoliert).

## Plugin-Skizze

Die genaue Hook-Signatur hängt von der OpenCode-Version ab. Die relevante Logik
bleibt gleich:

```ts
// pseudocode, not a complete plugin yet
import type { Plugin } from "@opencode-ai/plugin"

const API = "http://127.0.0.1:8787"
const TOKEN = process.env.RREDACT_API_TOKEN

async function redact(text: string, session: string) {
  const response = await fetch(`${API}/redact`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${TOKEN}`,
    },
    body: JSON.stringify({ text, session }),
  })
  return response.json()
}

async function restore(text: string, session: string) {
  const response = await fetch(`${API}/restore`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${TOKEN}`,
    },
    body: JSON.stringify({ text, session }),
  })
  return response.json()
}

export const RRedactPlugin: Plugin = async ({ directory }) => {
  return {
    // Tool-Ausgabe vor dem Modellkontext redigieren
    "tool.execute.after": async (input, output) => {
      if (typeof output.output !== "string") return
      const redacted = await redact(output.output, input.sessionID)
      output.output = redacted.text
    },

    // Optional: schreibende Tool-Argumente vor dem Ausführen restaurieren
    "tool.execute.before": async (input, output) => {
      if (input.tool !== "write" && input.tool !== "edit") return
      // strings in output.args rekursiv restaurieren
    },
  }
}
```

Wichtig:

- Nur Strings redigieren; Binärdaten nicht durch die API schicken.
- Fehler dürfen den Agent nicht blockieren: bei API-Ausfall entweder
  unverändert weiterarbeiten (mit Warnung) oder abbrechen – das muss eine
  bewusste Policy sein.
- Keine Rohwerte loggen.
- Das Plugin darf `.rredact/mapping.json` nie an das Modell geben.

## Vorgesehene Paketstruktur

```
packages/opencode-rredact/
  package.json
  src/index.ts
  src/client.ts        # fetch-Wrapper, Timeouts, Retry
  src/redact.ts        # rekursive String-Redaktion
  src/session.ts       # Session-Mapping, Cleanup
  test/
```

Veröffentlichung als eigenständiges npm-Paket, damit der `rredact`-Kern eine
einzelne Rust-Binärdatei bleibt.

## Roadmap

1. `session`-Unterstützung in API und MappingStore.
2. Plugin-Paket mit `tool.execute.before`/`after`.
3. Policy-Konfiguration (fail-open/fail-closed, Pfad-Globs, Tool-Allowlist).
4. Optional: MCP-Server statt HTTP, damit auch andere Agents andocken.
