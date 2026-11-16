# Lokale HTTP-API

Start:

```bash
export RREDACT_API_TOKEN="$(openssl rand -hex 24)"
rredact serve
# rredact 0.1.0 listening on http://127.0.0.1:8787
```

`--host`, `--port`, `--token` und `--no-store` sind verfügbar. Ein
Nicht-Loopback-Host erfordert ein Token (oder explizit `--allow-remote`).

Authentifizierung, falls ein Token gesetzt ist:

```
Authorization: Bearer <token>
```

oder `X-RRedact-Token: <token>`.

## Endpunkte

| Methode | Pfad | Zweck |
| --- | --- | --- |
| `GET` | `/health` | Status, Version, Regelanzahl (ohne Token) |
| `GET` | `/rules` | Metadaten der geladenen Regeln |
| `POST` | `/redact` | Text redigieren |
| `POST` | `/restore` | Platzhalter wiederherstellen |
| `DELETE` | `/sessions/:session` | Mapping einer Session löschen |
| `POST` | `/rules/validate` | Regeln prüfen, ohne sie zu speichern |
| `POST` | `/rules/reload` | `.rredact/rules.d/*.yaml` neu laden |

## `POST /redact`

```bash
curl -s http://127.0.0.1:8787/redact \
  -H "Authorization: Bearer $RREDACT_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "PASSWORD=hunter2\nGITHUB_TOKEN=ghp_...",
    "path": "app.env",
    "mode": "placeholder"
  }'
```

Body:

| Feld | Pflicht | Bedeutung |
| --- | --- | --- |
| `text` | ja | zu redigierender Text |
| `session` | nein | Session-ID für ein isoliertes Mapping |
| `path` | nein | virtueller Pfad für `paths`-Filter der Regeln |
| `mode` | nein | `placeholder`, `mask`, `hash` |
| `extra_rules` | nein | Liste zusätzlicher Regel-Objekte (nicht persistiert) |

Antwort:

```json
{
  "text": "PASSWORD=[REDACTED:ENV_SECRET:1]",
  "mode": "placeholder",
  "mapping_stored": true,
  "findings": [
    {
      "rule_id": "sensitive-variable-assignment",
      "description": "Value assigned to a secret-looking variable name",
      "category": "secret",
      "severity": "high",
      "path": "app.env",
      "line": 1,
      "column": 10,
      "kind": "ENV_SECRET",
      "fingerprint": "6f1ed002ab559585",
      "value_length": 7,
      "placeholder": "[REDACTED:ENV_SECRET:1]"
    }
  ],
  "summary": {
    "findings": 1,
    "files": 1,
    "by_severity": {"low": 0, "medium": 0, "high": 1, "critical": 0},
    "by_category": {"secret": 1},
    "mapping_stored": true
  }
}
```

Die `/redact`-Antwort enthält **nie** die Originalwerte. `fingerprint` ist ein
SHA-256-Auszug und nur zum Vergleich/Baselining gedacht. `/restore` gibt die
Originalwerte erwartungsgemäß lokal zurück.

## `POST /restore`

```bash
curl -s http://127.0.0.1:8787/restore \
  -H "Authorization: Bearer $RREDACT_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"text":"PASSWORD=[REDACTED:ENV_SECRET:1]"}'
```

```json
{
  "text": "PASSWORD=hunter2",
  "restored": 1,
  "unresolved": []
}
```

`unresolved` enthält Platzhalter, die nicht im Mapping stehen – z. B. aus einem
`hash`-Modus oder aus einer anderen Sitzung.

## Sessions

`/redact` und `/restore` akzeptieren ein optionales `session`-Feld:

```json
{"text": "...", "session": "ses_abc123"}
```

Jede Session bekommt ein eigenes Mapping unter
`.rredact/sessions/<sha256-der-session>.json` (Modus `0600`). Ohne `session`
wird weiterhin das globale `.rredact/mapping.json` verwendet. So können
mehrere Agents parallel laufen, ohne Platzhalter zu vermischen.

Eine Session wird explizit gelöscht mit:

```bash
curl -s -X DELETE http://127.0.0.1:8787/sessions/ses_abc123 \
  -H "Authorization: Bearer $RREDACT_API_TOKEN"
# {"deleted": true}
```

Danach lassen sich die zugehörigen Platzhalter nicht mehr wiederherstellen.
`--no-store` deaktiviert auch die Session-Dateien; die Mappings bleiben dann
nur im Speicher.

## `POST /rules/validate`

```bash
curl -s http://127.0.0.1:8787/rules/validate \
  -H "Authorization: Bearer $RREDACT_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "rules": [{
      "id": "internal-id",
      "description": "Interne ID",
      "category": "pii",
      "severity": "medium",
      "pattern": "\\bINT-[0-9]{4}\\b",
      "placeholder": "INTERNAL"
    }]
  }'
```

Antwort: `{"valid": true, "errors": [], "count": 1, "rules": [...]}`.
Ungültige Regeln liefern HTTP 200 mit `valid: false` (damit ein LLM die
Fehlermeldung sieht) – Request-Fehler wie fehlender Text liefern 4xx.

## `POST /rules/reload`

Nach dem Schreiben einer neuen Regeldatei:

```bash
curl -s -X POST http://127.0.0.1:8787/rules/reload \
  -H "Authorization: Bearer $RREDACT_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

## Fehler

| Status | Bedeutung |
| --- | --- |
| `400` | ungültiger Body, unbekannter Modus, Regel-Fehler |
| `401` | Token fehlt/falsch |
| `404` | unbekannter Pfad |
| `413` | Body > 20 MB |
| `500` | unerwarteter interner Fehler |

## Sicherheit

- Standard-Bind ist `127.0.0.1`.
- Das Mapping wird bei jedem erfolgreichen `/redact` gespeichert
  (außer `--no-store`).
- `--no-store` bedeutet: Wiederherstellen funktioniert nur innerhalb desselben
  Prozesses, nicht nach einem Neustart.
- Session-Mappings liegen unter `.rredact/sessions/`, sind ignoriert und
  enthalten Originalwerte. Nach dem Ende einer Session löschen.
- Die API ist kein Mehrbenutzer-Dienst. Für mehrere Agents getrennte
  Mapping-Dateien/Sessions verwenden.
