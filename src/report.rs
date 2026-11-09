//! Human, JSON and SARIF reports plus baseline support.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde_json::{json, Value};

use crate::models::{summary_json, Finding, Severity, VERSION};

const URI_SAFE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'/')
    .remove(b':')
    .remove(b'.')
    .remove(b'-')
    .remove(b'_')
    .remove(b'~');

pub fn sort_findings(findings: &[Finding]) -> Vec<Finding> {
    let mut sorted = findings.to_vec();
    sorted.sort_by(|a, b| {
        (
            a.path.as_deref().unwrap_or(""),
            a.line,
            a.column,
            &a.rule_id,
            &a.fingerprint,
        )
            .cmp(&(
                b.path.as_deref().unwrap_or(""),
                b.line,
                b.column,
                &b.rule_id,
                &b.fingerprint,
            ))
    });
    sorted
}

pub fn format_text(findings: &[Finding], show_values: bool) -> String {
    let findings = sort_findings(findings);
    let mut lines = Vec::new();
    for finding in &findings {
        let location = finding.path.as_deref().unwrap_or("<stdin>");
        let mut line = format!(
            "{:<8} {}:{}:{}  {}  {} ({} chars, fingerprint {})",
            finding.severity.as_str().to_ascii_uppercase(),
            location,
            finding.line,
            finding.column,
            finding.rule_id,
            finding.description,
            finding.value_length,
            finding.fingerprint
        );
        if show_values {
            if let Some(value) = &finding.value {
                let mut preview = value.replace('\n', "\\n");
                if preview.chars().count() > 120 {
                    preview = preview.chars().take(117).collect::<String>() + "...";
                }
                line.push_str(&format!("  value={preview:?}"));
            }
        }
        lines.push(line);
    }
    if findings.is_empty() {
        lines.push("No findings.".into());
    } else {
        let summary = summary_json(&findings, false);
        let counts = summary["by_severity"]
            .as_object()
            .map(|map| {
                map.iter()
                    .filter_map(|(name, count)| {
                        count
                            .as_u64()
                            .filter(|count| *count > 0)
                            .map(|count| format!("{name}: {count}"))
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        lines.push(String::new());
        lines.push(format!(
            "{} finding(s) in {} file(s){}",
            findings.len(),
            summary["files"].as_u64().unwrap_or(0),
            if counts.is_empty() {
                String::new()
            } else {
                format!(" ({counts})")
            }
        ));
    }
    lines.join("\n")
}

pub fn to_json(findings: &[Finding], show_values: bool) -> Value {
    json!({
        "version": 1,
        "tool": {"name": "rredact", "version": VERSION},
        "findings": sort_findings(findings)
            .iter()
            .map(|finding| finding.to_json(show_values))
            .collect::<Vec<_>>(),
        "summary": summary_json(findings, false),
    })
}

pub fn to_sarif(findings: &[Finding]) -> Value {
    let findings = sort_findings(findings);
    let mut rules: BTreeMap<String, Value> = BTreeMap::new();
    let mut results = Vec::new();
    for finding in &findings {
        rules.entry(finding.rule_id.clone()).or_insert_with(|| {
            json!({
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": {"text": finding.description},
                "fullDescription": {"text": finding.description},
                "defaultConfiguration": {"level": sarif_level(finding.severity)},
                "properties": {
                    "category": finding.category,
                    "severity": finding.severity.as_str(),
                    "tags": [finding.category],
                }
            })
        });
        let Some(path) = &finding.path else {
            continue;
        };
        let uri = utf8_percent_encode(&path.replace('\\', "/"), URI_SAFE).to_string();
        results.push(json!({
            "ruleId": finding.rule_id,
            "level": sarif_level(finding.severity),
            "message": {
                "text": format!(
                    "{} ({} characters, fingerprint {})",
                    finding.description, finding.value_length, finding.fingerprint
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": finding.line,
                        "startColumn": finding.column,
                        "endLine": finding.end_line,
                        "endColumn": finding.end_column,
                    }
                }
            }],
            "partialFingerprints": {"rredactFingerprint/v1": finding.fingerprint},
            "properties": {
                "category": finding.category,
                "severity": finding.severity.as_str(),
                "kind": finding.kind,
            }
        }));
    }
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "rredact",
                    "version": VERSION,
                    "rules": rules.values().cloned().collect::<Vec<_>>(),
                }
            },
            "results": results,
        }]
    })
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

pub fn write_report(content: &str, output: Option<&Path>) -> Result<()> {
    match output {
        Some(path) if path.to_string_lossy() != "-" => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, format!("{content}\n"))
                .with_context(|| format!("cannot write {}", path.display()))
        }
        _ => {
            println!("{content}");
            Ok(())
        }
    }
}

pub fn baseline_key(finding: &Finding) -> String {
    format!("{}:{}", finding.rule_id, finding.fingerprint)
}

pub fn load_baseline(path: Option<&Path>) -> Result<HashSet<String>> {
    let Some(path) = path else {
        return Ok(HashSet::new());
    };
    if !path.exists() {
        return Ok(HashSet::new());
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("cannot read baseline {}", path.display()))?;
    let value: Value = serde_json::from_str(&text)
        .with_context(|| format!("invalid baseline {}", path.display()))?;
    let entries = value
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut keys = HashSet::new();
    for entry in entries {
        let rule_id = entry.get("rule_id").and_then(Value::as_str);
        let fingerprint = entry.get("fingerprint").and_then(Value::as_str);
        if let (Some(rule_id), Some(fingerprint)) = (rule_id, fingerprint) {
            keys.insert(format!("{rule_id}:{fingerprint}"));
        }
    }
    Ok(keys)
}

pub fn filter_baseline(
    findings: Vec<Finding>,
    baseline: &HashSet<String>,
) -> (Vec<Finding>, usize) {
    if baseline.is_empty() {
        return (findings, 0);
    }
    let mut remaining = Vec::new();
    let mut suppressed = 0;
    for finding in findings {
        if baseline.contains(&baseline_key(&finding)) {
            suppressed += 1;
        } else {
            remaining.push(finding);
        }
    }
    (remaining, suppressed)
}

pub fn save_baseline(path: &Path, findings: &[Finding]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let entries: Vec<Value> = sort_findings(findings)
        .iter()
        .map(|finding| {
            json!({
                "rule_id": finding.rule_id,
                "fingerprint": finding.fingerprint,
                "severity": finding.severity.as_str(),
                "category": finding.category,
                "description": finding.description,
                "path": finding.path,
                "line": finding.line,
            })
        })
        .collect();
    let payload = json!({
        "version": 1,
        "created": chrono::Utc::now().to_rfc3339(),
        "note": "Accepted findings. Fingerprints are hashes, not the original values.",
        "findings": entries,
    });
    fs::write(path, serde_json::to_string_pretty(&payload)? + "\n")
        .with_context(|| format!("cannot write baseline {}", path.display()))
}
