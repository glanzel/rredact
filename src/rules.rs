//! Rule loading, validation and matching.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::models::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FlagsValue {
    String(String),
    Int(i64),
    List(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GroupValue {
    Index(usize),
    Name(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BareValues {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NameMatch {
    #[default]
    Search,
    FullMatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validator {
    Luhn,
    Iban,
    Phone,
    BasicAuth,
    Ipv4,
    Email,
}

impl Validator {
    fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "luhn" => Ok(Self::Luhn),
            "iban" => Ok(Self::Iban),
            "phone" => Ok(Self::Phone),
            "basic_auth" => Ok(Self::BasicAuth),
            "ipv4" => Ok(Self::Ipv4),
            "email" => Ok(Self::Email),
            other => bail!("unknown validator {other:?}"),
        }
    }

    fn validate(self, value: &str) -> bool {
        match self {
            Self::Luhn => validate_luhn(value),
            Self::Iban => validate_iban(value),
            Self::Phone => validate_phone(value),
            Self::BasicAuth => validate_basic_auth(value),
            Self::Ipv4 => validate_ipv4(value),
            Self::Email => validate_email(value),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    pub id: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_category")]
    pub category: String,
    #[serde(default)]
    pub severity: Severity,
    #[serde(rename = "type", default = "default_rule_type")]
    pub rule_type: String,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub flags: Option<FlagsValue>,
    #[serde(default)]
    pub group: Option<GroupValue>,
    #[serde(default)]
    pub strip_quotes: bool,
    #[serde(default)]
    pub placeholder: Option<String>,
    #[serde(default = "default_priority")]
    pub priority: i64,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub validate: Option<String>,
    #[serde(default)]
    pub context_required: Vec<String>,
    #[serde(default)]
    pub context_excluded: Vec<String>,
    #[serde(default = "default_context_window")]
    pub context_window: usize,
    #[serde(default)]
    pub name_pattern: Option<String>,
    #[serde(default = "default_name_match")]
    pub name_match: String,
    #[serde(default)]
    pub allow_keys: Vec<String>,
    #[serde(default)]
    pub bare_values: BareValues,
    #[serde(default = "default_min_length")]
    pub min_length: usize,
    #[serde(default = "default_min_entropy")]
    pub min_entropy: f64,
    #[serde(default = "default_charset")]
    pub charset: String,
}

fn default_category() -> String {
    "secret".into()
}
fn default_rule_type() -> String {
    "regex".into()
}
fn default_priority() -> i64 {
    100
}
fn default_true() -> bool {
    true
}
fn default_name_match() -> String {
    "search".into()
}
fn default_min_length() -> usize {
    32
}
fn default_min_entropy() -> f64 {
    4.0
}
fn default_charset() -> String {
    "base64".into()
}
fn default_context_window() -> usize {
    200
}

#[derive(Debug, Clone)]
pub enum Group {
    Index(usize),
    Name(String),
}

#[derive(Debug, Clone)]
pub enum CompiledKind {
    Regex {
        re: Regex,
        group: Group,
        strip_quotes: bool,
        validate: Option<Validator>,
    },
    Assignment {
        name_re: Regex,
        name_match: NameMatch,
        allow_keys: Vec<String>,
        bare_values: BareValues,
        validate: Option<Validator>,
    },
    Entropy {
        token_re: Regex,
        min_entropy: f64,
    },
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub description: String,
    pub category: String,
    pub severity: Severity,
    pub priority: i64,
    pub enabled: bool,
    pub placeholder: String,
    pub paths: Option<GlobSet>,
    pub exclude_paths: Option<GlobSet>,
    pub tags: Vec<String>,
    pub source: String,
    pub context_required: Vec<Regex>,
    pub context_excluded: Vec<Regex>,
    pub context_window: usize,
    pub compiled: CompiledKind,
}

impl Rule {
    pub fn compile(config: RuleConfig, source: &str) -> Result<Self> {
        if config.id.is_empty() {
            bail!("rule in {source} is missing 'id'");
        }
        if !valid_rule_id(&config.id) {
            bail!(
                "invalid rule id {:?}: use letters, digits, dot, dash and underscore",
                config.id
            );
        }
        if !matches!(
            config.category.as_str(),
            "secret" | "credential" | "pii" | "other"
        ) {
            bail!(
                "rule {:?}: invalid category {:?}",
                config.id,
                config.category
            );
        }
        let description = if config.description.is_empty() {
            config.id.clone()
        } else {
            config.description.clone()
        };
        let placeholder = sanitize_kind(
            config
                .placeholder
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or(&config.id),
        );
        let paths = build_globset(&config.paths)
            .with_context(|| format!("rule {:?}: invalid paths", config.id))?;
        let exclude_paths = build_globset(&config.exclude_paths)
            .with_context(|| format!("rule {:?}: invalid exclude_paths", config.id))?;
        let validate = config
            .validate
            .as_deref()
            .map(Validator::parse)
            .transpose()
            .with_context(|| format!("rule {:?}: invalid validator", config.id))?;

        let mut context_required = Vec::new();
        for pattern in &config.context_required {
            context_required.push(
                Regex::new(pattern)
                    .with_context(|| format!("rule {:?}: invalid context_required", config.id))?,
            );
        }
        let mut context_excluded = Vec::new();
        for pattern in &config.context_excluded {
            context_excluded.push(
                Regex::new(pattern)
                    .with_context(|| format!("rule {:?}: invalid context_excluded", config.id))?,
            );
        }
        let compiled = match config.rule_type.to_ascii_lowercase().as_str() {
            "regex" => {
                let pattern = config
                    .pattern
                    .as_deref()
                    .ok_or_else(|| anyhow!("rule {:?}: regex rules need a 'pattern'", config.id))?;
                let flags = config.flags.as_ref().map(flags_to_string).transpose()?;
                let full_pattern = match flags {
                    Some(flags) if !flags.is_empty() => format!("(?{flags}){pattern}"),
                    _ => pattern.to_string(),
                };
                let re = Regex::new(&full_pattern)
                    .with_context(|| format!("rule {:?}: invalid regex", config.id))?;
                let group = match config.group {
                    Some(GroupValue::Index(index)) => {
                        if index >= re.captures_len() {
                            bail!(
                                "rule {:?}: group {index} does not exist (regex has {} groups)",
                                config.id,
                                re.captures_len().saturating_sub(1)
                            );
                        }
                        Group::Index(index)
                    }
                    Some(GroupValue::Name(name)) => {
                        if !re
                            .capture_names()
                            .flatten()
                            .any(|candidate| candidate == name)
                        {
                            bail!("rule {:?}: unknown named group {:?}", config.id, name);
                        }
                        Group::Name(name)
                    }
                    None => Group::Index(0),
                };
                CompiledKind::Regex {
                    re,
                    group,
                    strip_quotes: config.strip_quotes,
                    validate,
                }
            }
            "assignment" => {
                let name_pattern = config.name_pattern.as_deref().ok_or_else(|| {
                    anyhow!("rule {:?}: assignment rules need 'name_pattern'", config.id)
                })?;
                let name_re = Regex::new(name_pattern)
                    .with_context(|| format!("rule {:?}: invalid name_pattern", config.id))?;
                let name_match = match config.name_match.to_ascii_lowercase().as_str() {
                    "search" => NameMatch::Search,
                    "fullmatch" => NameMatch::FullMatch,
                    other => bail!(
                        "rule {:?}: name_match must be search or fullmatch, got {other:?}",
                        config.id
                    ),
                };
                CompiledKind::Assignment {
                    name_re,
                    name_match,
                    allow_keys: config.allow_keys,
                    bare_values: config.bare_values,
                    validate,
                }
            }
            "entropy" => {
                if config.min_length < 8 {
                    bail!("rule {:?}: min_length must be >= 8", config.id);
                }
                let token_re = match config.charset.to_ascii_lowercase().as_str() {
                    "hex" => Regex::new(&format!(r"[0-9a-fA-F]{{{},}}", config.min_length))?,
                    "alnum" => Regex::new(&format!(r"[A-Za-z0-9]{{{},}}", config.min_length))?,
                    "base64" => {
                        Regex::new(&format!(r"[A-Za-z0-9+/=_-]{{{},}}", config.min_length))?
                    }
                    other => bail!(
                        "rule {:?}: charset must be base64, hex or alnum, got {other:?}",
                        config.id
                    ),
                };
                CompiledKind::Entropy {
                    token_re,
                    min_entropy: config.min_entropy,
                }
            }
            other => bail!("rule {:?}: unknown type {other:?}", config.id),
        };

        Ok(Self {
            id: config.id,
            description,
            category: config.category,
            severity: config.severity,
            priority: config.priority,
            enabled: config.enabled,
            placeholder,
            paths,
            exclude_paths,
            tags: config.tags,
            source: source.to_string(),
            context_required,
            context_excluded,
            context_window: config.context_window.max(1),
            compiled,
        })
    }

    pub fn kind(&self) -> String {
        self.placeholder.clone()
    }

    pub fn applies_to(&self, path: Option<&str>) -> bool {
        let Some(path) = path else {
            return true;
        };
        let normalized = path.replace('\\', "/");
        if let Some(exclude) = &self.exclude_paths {
            if exclude.is_match(&normalized) {
                return false;
            }
        }
        match &self.paths {
            Some(paths) => paths.is_match(&normalized),
            None => true,
        }
    }

    pub fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: self.id.clone(),
            description: self.description.clone(),
            category: self.category.clone(),
            severity: self.severity,
            rule_type: match self.compiled {
                CompiledKind::Regex { .. } => "regex",
                CompiledKind::Assignment { .. } => "assignment",
                CompiledKind::Entropy { .. } => "entropy",
            }
            .to_string(),
            priority: self.priority,
            enabled: self.enabled,
            placeholder: self.kind(),
            tags: self.tags.clone(),
            source: self.source.clone(),
            paths: self.paths.as_ref().map(|_| "configured".to_string()),
        }
    }

    pub fn context_ok(&self, text: &str, start: usize, end: usize) -> bool {
        if self.context_required.is_empty() && self.context_excluded.is_empty() {
            return true;
        }
        let mut before = start.saturating_sub(self.context_window);
        while before > 0 && !text.is_char_boundary(before) {
            before += 1;
        }
        let mut after = (end + self.context_window).min(text.len());
        while after < text.len() && !text.is_char_boundary(after) {
            after -= 1;
        }
        let context = &text[before..after];
        if self
            .context_excluded
            .iter()
            .any(|pattern| pattern.is_match(context))
        {
            return false;
        }
        self.context_required
            .iter()
            .all(|pattern| pattern.is_match(context))
    }

    pub fn find_candidates(
        &self,
        text: &str,
        path: Option<&str>,
        global_allow_keys: &HashSet<String>,
    ) -> Vec<(usize, usize, String)> {
        if !self.enabled || !self.applies_to(path) {
            return Vec::new();
        }
        match &self.compiled {
            CompiledKind::Regex {
                re,
                group,
                strip_quotes,
                validate,
            } => {
                let mut out = Vec::new();
                for caps in re.captures_iter(text) {
                    let matched = match group {
                        Group::Index(index) => caps.get(*index),
                        Group::Name(name) => caps.name(name),
                    };
                    let Some(matched) = matched else {
                        continue;
                    };
                    let mut start = matched.start();
                    let mut end = matched.end();
                    if end <= start {
                        continue;
                    }
                    if *strip_quotes && end >= start + 2 {
                        let bytes = text.as_bytes();
                        let first = bytes[start];
                        let last = bytes[end - 1];
                        if (first == b'"' || first == b'\'') && first == last {
                            start += 1;
                            end -= 1;
                        }
                    }
                    if end <= start {
                        continue;
                    }
                    let value = &text[start..end];
                    if let Some(validator) = validate {
                        if !validator.validate(value) {
                            continue;
                        }
                    }
                    if !self.context_ok(text, start, end) {
                        continue;
                    }
                    out.push((start, end, value.to_string()));
                }
                out
            }
            CompiledKind::Assignment {
                name_re,
                name_match,
                allow_keys,
                bare_values,
                validate,
            } => {
                let code_path = is_code_path(path);
                let mut out = Vec::new();
                for assignment in iter_assignments(text) {
                    let key_upper = assignment.key.to_ascii_uppercase();
                    if allow_keys
                        .iter()
                        .any(|key| key.eq_ignore_ascii_case(&key_upper))
                        || global_allow_keys.contains(&key_upper)
                    {
                        continue;
                    }
                    let matched = match name_match {
                        NameMatch::Search => name_re.is_match(&assignment.key),
                        NameMatch::FullMatch => name_re
                            .find(&assignment.key)
                            .map(|m| m.start() == 0 && m.end() == assignment.key.len())
                            .unwrap_or(false),
                    };
                    if !matched {
                        continue;
                    }
                    if !assignment.quoted {
                        if *bare_values == BareValues::Never {
                            continue;
                        }
                        if *bare_values == BareValues::Auto && code_path {
                            continue;
                        }
                    }
                    if let Some(validator) = validate {
                        if !validator.validate(&assignment.value) {
                            continue;
                        }
                    }
                    out.push((assignment.start, assignment.end, assignment.value));
                }
                out
            }
            CompiledKind::Entropy {
                token_re,
                min_entropy,
            } => token_re
                .find_iter(text)
                .filter_map(|m| {
                    let value = m.as_str();
                    (shannon_entropy(value) >= *min_entropy
                        && self.context_ok(text, m.start(), m.end()))
                    .then(|| (m.start(), m.end(), value.to_string()))
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleMetadata {
    pub id: String,
    pub description: String,
    pub category: String,
    pub severity: Severity,
    #[serde(rename = "type")]
    pub rule_type: String,
    pub priority: i64,
    pub enabled: bool,
    pub placeholder: String,
    pub tags: Vec<String>,
    pub source: String,
    pub paths: Option<String>,
}

fn valid_rule_id(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

pub fn sanitize_kind(value: &str) -> String {
    let mut kind: String = value
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    while kind.contains("__") {
        kind = kind.replace("__", "_");
    }
    let kind = kind.trim_matches('_').to_ascii_uppercase();
    if kind.is_empty() {
        "SECRET".into()
    } else {
        kind.chars().take(48).collect()
    }
}

fn flags_to_string(value: &FlagsValue) -> Result<String> {
    match value {
        FlagsValue::String(value) => {
            let mut out = String::new();
            for ch in value.to_ascii_lowercase().chars() {
                if matches!(ch, 'i' | 'm' | 's' | 'x' | 'a' | 'u' | ' ' | '\t' | ',') {
                    if !ch.is_whitespace() && ch != ',' {
                        out.push(ch);
                    }
                } else {
                    bail!("unknown regex flag {ch:?}");
                }
            }
            Ok(out)
        }
        FlagsValue::List(values) => {
            let mut out = String::new();
            for value in values {
                out.push_str(&flags_to_string(&FlagsValue::String(value.clone()))?);
            }
            Ok(out)
        }
        FlagsValue::Int(bits) => {
            let mut out = String::new();
            if bits & 2 != 0 {
                out.push('i');
            }
            if bits & 8 != 0 {
                out.push('m');
            }
            if bits & 16 != 0 {
                out.push('s');
            }
            if bits & 32 != 0 {
                out.push('u');
            }
            if bits & 64 != 0 {
                out.push('x');
            }
            if bits & 256 != 0 {
                out.push('a');
            }
            Ok(out)
        }
    }
}

fn build_globset(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern).with_context(|| format!("invalid glob {pattern:?}"))?);
    }
    Ok(Some(builder.build()?))
}

pub fn is_code_path(path: Option<&str>) -> bool {
    let Some(path) = path else {
        return false;
    };
    let extension = Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        extension.as_str(),
        "py" | "pyi"
            | "js"
            | "jsx"
            | "ts"
            | "tsx"
            | "mjs"
            | "cjs"
            | "go"
            | "rs"
            | "java"
            | "kt"
            | "kts"
            | "rb"
            | "php"
            | "cs"
            | "c"
            | "cc"
            | "cpp"
            | "cxx"
            | "h"
            | "hpp"
            | "swift"
            | "scala"
            | "sh"
            | "bash"
            | "zsh"
            | "fish"
            | "ps1"
            | "lua"
            | "ex"
            | "exs"
            | "dart"
            | "sql"
            | "vue"
            | "svelte"
    )
}

// ---------------------------------------------------------------------------
// Assignment parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Assignment {
    pub key: String,
    pub start: usize,
    pub end: usize,
    pub value: String,
    pub quoted: bool,
}

pub fn iter_assignments(text: &str) -> Vec<Assignment> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    for raw_line in text.split_inclusive('\n') {
        let mut body = raw_line;
        if let Some(stripped) = body.strip_suffix('\n') {
            body = stripped;
        }
        if let Some(stripped) = body.strip_suffix('\r') {
            body = stripped;
        }
        let trimmed = body.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with(';') || trimmed.starts_with("//") {
            offset += raw_line.len();
            continue;
        }
        if let Some(assignment) = parse_assignment(body, offset) {
            out.push(assignment);
        }
        offset += raw_line.len();
    }
    out
}

fn parse_assignment(body: &str, base: usize) -> Option<Assignment> {
    let bytes = body.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() && matches!(bytes[index], b' ' | b'\t') {
        index += 1;
    }
    if index < bytes.len() && bytes[index] == b'{' {
        index += 1;
        while index < bytes.len() && matches!(bytes[index], b' ' | b'\t') {
            index += 1;
        }
    }
    if index < bytes.len() && bytes[index] == b'-' {
        index += 1;
        while index < bytes.len() && matches!(bytes[index], b' ' | b'\t') {
            index += 1;
        }
    }
    for prefix in ["export", "set"] {
        if body[index..].starts_with(prefix) {
            let after = index + prefix.len();
            if after < bytes.len() && matches!(bytes[after], b' ' | b'\t') {
                index = after;
                while index < bytes.len() && matches!(bytes[index], b' ' | b'\t') {
                    index += 1;
                }
                break;
            }
        }
    }
    if index >= bytes.len() {
        return None;
    }

    let (key, mut index) = if matches!(bytes[index], b'"' | b'\'') {
        let quote = bytes[index];
        let key_start = index + 1;
        index = key_start;
        while index < bytes.len() && bytes[index] != quote {
            index += 1;
        }
        if index >= bytes.len() {
            return None;
        }
        let key = body[key_start..index].to_string();
        (key, index + 1)
    } else {
        let key_start = index;
        if !(bytes[index].is_ascii_alphabetic() || bytes[index] == b'_') {
            return None;
        }
        while index < bytes.len()
            && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'.' | b'-'))
        {
            index += 1;
        }
        (body[key_start..index].to_string(), index)
    };
    if key.is_empty() {
        return None;
    }

    while index < bytes.len() && matches!(bytes[index], b' ' | b'\t') {
        index += 1;
    }
    if index >= bytes.len() || !matches!(bytes[index], b':' | b'=') {
        return None;
    }
    index += 1;
    while index < bytes.len() && matches!(bytes[index], b' ' | b'\t') {
        index += 1;
    }
    let value_start = index;
    let (rel_start, rel_end, quoted) = parse_value_span(&body[value_start..])?;
    let start = base + value_start + rel_start;
    let end = base + value_start + rel_end;
    if end <= start {
        return None;
    }
    Some(Assignment {
        key,
        start,
        end,
        value: body[value_start + rel_start..value_start + rel_end].to_string(),
        quoted,
    })
}

fn parse_value_span(raw: &str) -> Option<(usize, usize, bool)> {
    let bytes = raw.as_bytes();
    let mut start = 0usize;
    while start < bytes.len() && matches!(bytes[start], b' ' | b'\t') {
        start += 1;
    }
    if start >= bytes.len() || bytes[start] == b'#' {
        return None;
    }
    if matches!(bytes[start], b'"' | b'\'') {
        let quote = bytes[start];
        let mut index = start + 1;
        let mut escaped = false;
        while index < bytes.len() {
            let ch = bytes[index];
            if escaped {
                escaped = false;
            } else if ch == b'\\' {
                escaped = true;
            } else if ch == quote {
                if index <= start + 1 {
                    return None;
                }
                return Some((start + 1, index, true));
            }
            index += 1;
        }
        let end = raw.trim_end().len();
        return (end > start + 1).then_some((start + 1, end, true));
    }

    let mut end = comment_index(raw);
    while end > start && matches!(bytes[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    if end > start && bytes[end - 1] == b',' {
        end -= 1;
        while end > start && matches!(bytes[end - 1], b' ' | b'\t') {
            end -= 1;
        }
    }
    if end > start && matches!(bytes[end - 1], b'}' | b']') {
        end -= 1;
        while end > start && matches!(bytes[end - 1], b' ' | b'\t') {
            end -= 1;
        }
    }
    (end > start).then_some((start, end, false))
}

fn comment_index(value: &str) -> usize {
    let bytes = value.as_bytes();
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    for (index, ch) in bytes.iter().copied().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == b'\\' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if ch == active {
                quote = None;
            }
        } else if ch == b'"' || ch == b'\'' {
            quote = Some(ch);
        } else if ch == b'#' && (index == 0 || matches!(bytes[index - 1], b' ' | b'\t')) {
            return index;
        }
    }
    value.len()
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

pub fn validate_luhn(value: &str) -> bool {
    let digits: Vec<u32> = value.chars().filter_map(|ch| ch.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let parity = digits.len() % 2;
    let sum: u32 = digits
        .iter()
        .enumerate()
        .map(|(index, digit)| {
            let mut digit = *digit;
            if index % 2 == parity {
                digit *= 2;
                if digit > 9 {
                    digit -= 9;
                }
            }
            digit
        })
        .sum();
    sum % 10 == 0
}

pub fn validate_iban(value: &str) -> bool {
    let iban: String = value.chars().filter(|ch| !ch.is_whitespace()).collect();
    let iban = iban.to_ascii_uppercase();
    if !(15..=34).contains(&iban.len())
        || !iban
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
    {
        return false;
    }
    let rearranged = format!("{}{}", &iban[4..], &iban[..4]);
    let mut remainder: u32 = 0;
    for ch in rearranged.chars() {
        let value = ch.to_digit(36).unwrap_or(0);
        if value >= 10 {
            remainder = (remainder * 100 + value) % 97;
        } else {
            remainder = (remainder * 10 + value) % 97;
        }
    }
    remainder == 1
}

pub fn validate_phone(value: &str) -> bool {
    let stripped = value.trim();
    let digits: String = stripped.chars().filter(|ch| ch.is_ascii_digit()).collect();
    if !(7..=15).contains(&digits.len()) {
        return false;
    }
    if phone_false_positive_regexes()
        .iter()
        .any(|pattern| pattern.is_match(stripped))
    {
        return false;
    }
    if digits == stripped && digits.len() < 10 {
        return false;
    }
    if digits
        .chars()
        .next()
        .is_some_and(|first| digits.chars().all(|ch| ch == first))
    {
        return false;
    }
    true
}

fn phone_false_positive_regexes() -> &'static [Regex] {
    static REGEXES: std::sync::OnceLock<Vec<Regex>> = std::sync::OnceLock::new();
    REGEXES.get_or_init(|| {
        vec![
            Regex::new(r"^\d{1,3}(?:\.\d{1,3}){3}$").unwrap(),
            Regex::new(r"^\d{1,4}[./-]\d{1,2}[./-]\d{1,4}$").unwrap(),
            Regex::new(r"\b\d{4}[ -]\d{4}[ -]\d{4}\b").unwrap(),
        ]
    })
}

pub fn validate_email(value: &str) -> bool {
    let mut parts = value.split('@');
    let Some(local) = parts.next() else {
        return false;
    };
    let Some(domain) = parts.next() else {
        return false;
    };
    if parts.next().is_some() || local.is_empty() || domain.is_empty() {
        return false;
    }
    if local.contains(['/', '\\', ' ']) || domain.contains(['/', '\\', ' ']) {
        return false;
    }
    let Some((_, tld)) = domain.rsplit_once('.') else {
        return false;
    };
    tld.len() >= 2 && tld.chars().all(|ch| ch.is_ascii_alphabetic())
}

pub fn validate_ipv4(value: &str) -> bool {
    let parts: Vec<&str> = value.trim().split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let mut octets = [0u8; 4];
    for (index, part) in parts.iter().enumerate() {
        let Ok(octet) = part.parse::<u8>() else {
            return false;
        };
        octets[index] = octet;
    }
    !(octets[0] == 0
        || octets[0] == 10
        || octets[0] == 127
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 255 && octets[1] == 255 && octets[2] == 255 && octets[3] == 255))
}

pub fn validate_basic_auth(value: &str) -> bool {
    let padded = format!("{}{}", value, "=".repeat((4 - value.len() % 4) % 4));
    match base64::engine::general_purpose::STANDARD.decode(padded) {
        Ok(decoded) => decoded.contains(&b':'),
        Err(_) => false,
    }
}

pub fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for ch in value.chars() {
        *counts.entry(ch).or_insert(0usize) += 1;
    }
    let length = value.chars().count() as f64;
    counts
        .values()
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

// ---------------------------------------------------------------------------
// Document parsing
// ---------------------------------------------------------------------------

pub fn parse_rule_document(value: &serde_yaml::Value, source: &str) -> Result<Vec<RuleConfig>> {
    let raw = if value.is_sequence() {
        value.clone()
    } else if let Some(rules) = value.get("rules") {
        rules.clone()
    } else {
        bail!("{source}: expected a mapping with 'rules' or a list");
    };
    let rules: Vec<RuleConfig> =
        serde_yaml::from_value(raw).with_context(|| format!("{source}: invalid rules document"))?;
    deduplicate_configs(rules, source)
}

pub fn deduplicate_configs(rules: Vec<RuleConfig>, source: &str) -> Result<Vec<RuleConfig>> {
    let mut seen = HashSet::new();
    for rule in &rules {
        if !seen.insert(rule.id.clone()) {
            bail!("duplicate rule id {:?} in {source}", rule.id);
        }
    }
    Ok(rules)
}

pub fn compile_rules(rules: Vec<RuleConfig>, source: &str) -> Result<Vec<Rule>> {
    let rules = deduplicate_configs(rules, source)?;
    rules
        .into_iter()
        .map(|rule| Rule::compile(rule, source))
        .collect()
}

pub fn compile_rule_configs(
    configs: Vec<RuleConfig>,
    source: &str,
) -> Result<Vec<std::sync::Arc<Rule>>> {
    Ok(compile_rules(configs, source)?
        .into_iter()
        .map(std::sync::Arc::new)
        .collect())
}
