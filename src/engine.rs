//! Redaction engine.

use std::sync::{Arc, OnceLock};

use anyhow::Result;
use regex::Regex;

use crate::config::Config;
use crate::mapping::{fingerprint, MappingStore};
use crate::models::{line_starts, position_at, Finding, Mode, RedactionResult};
use crate::rules::{compile_rule_configs, Rule, RuleConfig};

#[derive(Debug, Clone)]
struct Candidate {
    rule: Arc<Rule>,
    start: usize,
    end: usize,
    value: String,
}

pub struct Engine {
    pub config: Config,
    pub mapping: MappingStore,
    pub mode: Mode,
}

impl Engine {
    pub fn new(config: Config, mapping: MappingStore, mode: Option<Mode>) -> Self {
        let mode = mode.unwrap_or(config.mode);
        Self {
            config,
            mapping,
            mode,
        }
    }

    pub fn redact(
        &mut self,
        text: &str,
        path: Option<&str>,
        mode: Option<Mode>,
        extra_rules: Option<Vec<RuleConfig>>,
        assign_placeholders: bool,
    ) -> Result<RedactionResult> {
        let mode = mode.unwrap_or(self.mode);
        let mut rules = self.config.rules.clone();
        if let Some(configs) = extra_rules {
            rules.extend(compile_rule_configs(configs, "extra")?);
        }
        rules.sort_by(|a, b| (a.priority, &a.id).cmp(&(b.priority, &b.id)));

        let starts = line_starts(text);
        let placeholder_spans = placeholder_spans(text);
        let mut candidates = Vec::new();
        for rule in &rules {
            for (start, end, value) in rule.find_candidates(text, path, &self.config.allowlist_keys)
            {
                if start >= end || end > text.len() {
                    continue;
                }
                if self.config.allows_value(&value) {
                    continue;
                }
                if placeholder_spans
                    .iter()
                    .any(|(span_start, span_end)| start < *span_end && *span_start < end)
                {
                    continue;
                }
                candidates.push(Candidate {
                    rule: rule.clone(),
                    start,
                    end,
                    value,
                });
            }
        }

        candidates.sort_by(|a, b| {
            (a.rule.priority, a.start, std::cmp::Reverse(a.end - a.start)).cmp(&(
                b.rule.priority,
                b.start,
                std::cmp::Reverse(b.end - b.start),
            ))
        });
        let mut accepted: Vec<Candidate> = Vec::new();
        for candidate in candidates {
            if accepted
                .iter()
                .any(|existing| candidate.start < existing.end && existing.start < candidate.end)
            {
                continue;
            }
            accepted.push(candidate);
        }
        accepted.sort_by_key(|candidate| candidate.start);

        let mut output = String::with_capacity(text.len());
        let mut cursor = 0usize;
        let mut findings = Vec::new();
        for candidate in &accepted {
            output.push_str(&text[cursor..candidate.start]);
            let mut placeholder = None;
            if assign_placeholders {
                placeholder = Some(match mode {
                    Mode::Mask => "***".to_string(),
                    Mode::Hash => format!(
                        "[REDACTED:{}:{}]",
                        candidate.rule.kind(),
                        &fingerprint(&candidate.value)[..12]
                    ),
                    Mode::Placeholder => self
                        .mapping
                        .placeholder_for(&candidate.rule.kind(), &candidate.value),
                });
                if let Some(value) = &placeholder {
                    output.push_str(value);
                } else {
                    output.push_str(&text[candidate.start..candidate.end]);
                }
            } else {
                output.push_str(&text[candidate.start..candidate.end]);
            }
            cursor = candidate.end;

            let (line, column) = position_at(&starts, text, candidate.start);
            let (end_line, end_column) = position_at(&starts, text, candidate.end.min(text.len()));
            findings.push(Finding {
                rule_id: candidate.rule.id.clone(),
                description: candidate.rule.description.clone(),
                category: candidate.rule.category.clone(),
                severity: candidate.rule.severity,
                start: candidate.start,
                end: candidate.end,
                line,
                column,
                end_line,
                end_column,
                kind: candidate.rule.kind(),
                fingerprint: fingerprint(&candidate.value)[..16].to_string(),
                value_length: candidate.value.chars().count(),
                placeholder,
                path: path.map(str::to_string),
                value: Some(candidate.value.clone()),
            });
        }
        output.push_str(&text[cursor..]);

        let mapping_stored = mode == Mode::Placeholder
            && assign_placeholders
            && !accepted.is_empty()
            && self.mapping.stored();
        if mapping_stored {
            self.mapping.save()?;
        }

        Ok(RedactionResult {
            text: output,
            findings,
            mode,
            mapping_stored,
        })
    }

    pub fn scan(&mut self, text: &str, path: Option<&str>) -> Result<RedactionResult> {
        self.redact(text, path, None, None, false)
    }

    pub fn restore(&self, text: &str) -> (String, usize, Vec<String>) {
        self.mapping.restore(text)
    }

    pub fn rule_metadata(&self) -> Vec<serde_json::Value> {
        self.config
            .rules
            .iter()
            .map(|rule| serde_json::to_value(rule.metadata()).unwrap_or_default())
            .collect()
    }

    pub fn reload(&mut self, config: Config) {
        self.mode = config.mode;
        self.config = config;
    }
}

fn placeholder_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"\[REDACTED:[A-Z0-9_]+:\d+\]").unwrap())
}

fn token_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"\[REDACTED:[A-Z0-9_]+:[A-Za-z0-9]+\]").unwrap())
}

fn placeholder_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans: Vec<(usize, usize)> = placeholder_regex()
        .find_iter(text)
        .map(|matched| (matched.start(), matched.end()))
        .collect();
    spans.extend(
        token_regex()
            .find_iter(text)
            .map(|matched| (matched.start(), matched.end())),
    );
    spans
}
