//! Extract variable names only (never values) for LLM rule generation.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;
use serde::Serialize;

use crate::rules::iter_assignments;
use crate::scanner::SourceFile;

#[derive(Debug, Clone, Serialize)]
pub struct VariableInfo {
    pub name: String,
    pub path: String,
    pub line: usize,
}

pub fn extract_variables(files: &[SourceFile], sensitive_only: bool) -> Vec<VariableInfo> {
    let mut found: BTreeMap<String, VariableInfo> = BTreeMap::new();
    for file in files {
        let starts = line_starts(&file.text);
        for assignment in iter_assignments(&file.text) {
            let name = assignment.key;
            if sensitive_only && !is_sensitive_name(&name) {
                continue;
            }
            let line = line_for_offset(&starts, &file.text, assignment.start);
            found.entry(name.clone()).or_insert(VariableInfo {
                name,
                path: file.rel.clone(),
                line,
            });
        }
        for captures in declaration_regex().captures_iter(&file.text) {
            let Some(name) = captures.get(1).map(|m| m.as_str().to_string()) else {
                continue;
            };
            if sensitive_only && !is_sensitive_name(&name) {
                continue;
            }
            let line = line_for_offset(&starts, &file.text, captures.get(0).unwrap().start());
            found.entry(name.clone()).or_insert(VariableInfo {
                name,
                path: file.rel.clone(),
                line,
            });
        }
    }
    found.into_values().collect()
}

pub fn prompt(variables: &[VariableInfo]) -> String {
    let names = variables
        .iter()
        .map(|variable| format!("- {}", variable.name))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"Du bist ein Experte für Regex und IT-Sicherheit.
Erstelle Regeln für rredact, die die Werte der folgenden Variablen redigieren,
aber die Variablennamen unverändert lassen. Nutze Capture-Groups.
Gib ausschließlich gültiges YAML im rredact-Regelformat aus.

Variablennamen (keine Werte):
{names}

Beispiel:
version: 1
rules:
  - id: workspace-secrets
    description: Workspace-spezifische Secrets
    category: secret
    severity: high
    type: assignment
    name_pattern: '(?i)(?:^|[_.-])(?:db_password_production|internal_api_salt)(?:$|[_.-])'
    placeholder: WORKSPACE_SECRET
"#
    )
}

fn is_sensitive_name(name: &str) -> bool {
    sensitive_regex().is_match(name)
}

fn sensitive_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r"(?i)(secret|token|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credential|auth|signing[_-]?key|encryption[_-]?key|salt|dsn|database[_-]?url|connection[_-]?string|session[_-]?secret|webhook[_-]?url)",
        )
        .unwrap()
    })
}

fn declaration_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?m)^\s*(?:const|let|var|final|val)\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap()
    })
}

fn line_starts(text: &str) -> Vec<usize> {
    let mut starts = vec![0];
    starts.extend(text.match_indices('\n').map(|(index, _)| index + 1));
    starts
}

fn line_for_offset(starts: &[usize], text: &str, offset: usize) -> usize {
    let index = match starts.binary_search(&offset) {
        Ok(index) => index,
        Err(index) => index.saturating_sub(1),
    };
    let _ = text;
    index + 1
}
