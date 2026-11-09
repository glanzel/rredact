//! Shared data types.

use std::collections::BTreeMap;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ValueEnum, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    #[default]
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Placeholder,
    Mask,
    Hash,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Placeholder => "placeholder",
            Self::Mask => "mask",
            Self::Hash => "hash",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum FailOn {
    Critical,
    #[default]
    High,
    Medium,
    Low,
    Any,
    None,
}

impl FailOn {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "critical" => Some(Self::Critical),
            "high" => Some(Self::High),
            "medium" => Some(Self::Medium),
            "low" => Some(Self::Low),
            "any" => Some(Self::Any),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Any => "any",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
    pub description: String,
    pub category: String,
    pub severity: Severity,
    pub start: usize,
    pub end: usize,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub kind: String,
    pub fingerprint: String,
    pub value_length: usize,
    pub placeholder: Option<String>,
    pub path: Option<String>,
    pub value: Option<String>,
}

impl Finding {
    pub fn to_json(&self, show_values: bool) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert("rule_id".into(), self.rule_id.clone().into());
        map.insert("description".into(), self.description.clone().into());
        map.insert("category".into(), self.category.clone().into());
        map.insert("severity".into(), self.severity.as_str().into());
        map.insert(
            "path".into(),
            self.path
                .clone()
                .map_or(serde_json::Value::Null, Into::into),
        );
        map.insert("line".into(), self.line.into());
        map.insert("column".into(), self.column.into());
        map.insert("end_line".into(), self.end_line.into());
        map.insert("end_column".into(), self.end_column.into());
        map.insert("kind".into(), self.kind.clone().into());
        map.insert("fingerprint".into(), self.fingerprint.clone().into());
        map.insert("value_length".into(), self.value_length.into());
        map.insert(
            "placeholder".into(),
            self.placeholder
                .clone()
                .map_or(serde_json::Value::Null, Into::into),
        );
        if show_values {
            if let Some(value) = &self.value {
                map.insert("value".into(), value.clone().into());
            }
        }
        serde_json::Value::Object(map)
    }
}

#[derive(Debug, Clone)]
pub struct RedactionResult {
    pub text: String,
    pub findings: Vec<Finding>,
    pub mode: Mode,
    pub mapping_stored: bool,
}

impl RedactionResult {
    pub fn summary(&self) -> serde_json::Value {
        summary_json(&self.findings, self.mapping_stored)
    }
}

pub fn summary_json(findings: &[Finding], mapping_stored: bool) -> serde_json::Value {
    let mut by_severity: BTreeMap<&'static str, usize> = BTreeMap::new();
    for severity in [
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        by_severity.insert(severity.as_str(), 0);
    }
    let mut by_category: BTreeMap<String, usize> = BTreeMap::new();
    let mut files = std::collections::BTreeSet::new();
    for finding in findings {
        *by_severity.entry(finding.severity.as_str()).or_default() += 1;
        *by_category.entry(finding.category.clone()).or_default() += 1;
        if let Some(path) = &finding.path {
            files.insert(path.clone());
        }
    }
    serde_json::json!({
        "findings": findings.len(),
        "files": files.len(),
        "by_severity": by_severity,
        "by_category": by_category,
        "mapping_stored": mapping_stored,
    })
}

pub fn should_fail(findings: &[Finding], fail_on: FailOn) -> bool {
    if findings.is_empty() {
        return false;
    }
    match fail_on {
        FailOn::None => false,
        FailOn::Any => true,
        FailOn::Critical => findings.iter().any(|f| f.severity == Severity::Critical),
        FailOn::High => findings
            .iter()
            .any(|f| f.severity.rank() >= Severity::High.rank()),
        FailOn::Medium => findings
            .iter()
            .any(|f| f.severity.rank() >= Severity::Medium.rank()),
        FailOn::Low => true,
    }
}

/// 1-based line/column for a byte offset.
pub fn position_at(line_starts: &[usize], text: &str, offset: usize) -> (usize, usize) {
    let index = match line_starts.binary_search(&offset) {
        Ok(index) => index,
        Err(index) => index.saturating_sub(1),
    };
    let line_start = line_starts.get(index).copied().unwrap_or(0);
    let column = text
        .get(line_start..offset)
        .map(|slice| slice.chars().count() + 1)
        .unwrap_or(1);
    (index + 1, column)
}

pub fn line_starts(text: &str) -> Vec<usize> {
    let mut starts = vec![0];
    starts.extend(text.match_indices('\n').map(|(index, _)| index + 1));
    starts
}
