//! Best-effort importer for OpenRedaction (sam247/openredaction).
//!
//! OpenRedaction describes its patterns as TypeScript objects such as:
//!
//! ```ts
//! {
//!   type: "EMAIL",
//!   regex: /.../gi,
//!   priority: 100,
//!   description: "Email address",
//!   severity: "high",
//! }
//! ```
//!
//! This importer extracts those objects with a small, non-executing parser and
//! converts the regex literals to Rust `regex` syntax. Unsupported constructs
//! are reported as notes and skipped.

use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use regex::Regex;

use crate::models::Severity;
use crate::rules::{GroupValue, Rule, RuleConfig};

const DISABLE_TYPES: &[&str] = &[
    "NAME",
    "USERNAME",
    "EMPLOYEE_ID",
    "CUSIP",
    "ISIN",
    "SEDOL",
    "LEI",
    "LEBANON_NATIONAL_ID",
    "PASSPORT_US",
    "OMAN_CIVIL_ID",
    "ARGENTINA_DNI",
    "INDIAN_AADHAAR",
];

const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "tests",
    "test",
    "__tests__",
    "examples",
    "docs",
];

pub fn import_openredaction(
    source: &str,
    timeout: Duration,
    include_all: bool,
) -> Result<(Vec<RuleConfig>, Vec<String>, String)> {
    let (data, origin, is_archive) = if source.starts_with("http://")
        || source.starts_with("https://")
    {
        let agent = ureq::AgentBuilder::new().timeout(timeout).build();
        let response = agent
            .get(source)
            .call()
            .with_context(|| format!("cannot download {source}"))?;
        let mut data = Vec::new();
        response
            .into_reader()
            .read_to_end(&mut data)
            .context("cannot read download")?;
        let lower = source.to_ascii_lowercase();
        let is_archive = lower.ends_with(".tar.gz")
            || lower.ends_with(".tgz")
            || lower.ends_with(".tar")
            || lower.ends_with(".tar.bz2")
            || lower.ends_with(".tar.xz")
            || lower.ends_with(".zip")
            || data.starts_with(b"\x1f\x8b")
            || data.starts_with(b"PK");
        (data, source.to_string(), is_archive)
    } else {
        let path = PathBuf::from(source);
        if !path.exists() {
            bail!("source not found: {}", path.display());
        }
        if path.is_dir() {
            return collect_and_parse(&path, source, include_all)
                .map(|(rules, notes)| (rules, notes, path.display().to_string()));
        }
        let data = fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
        let is_archive = matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("gz" | "tgz" | "zip" | "tar")
        );
        (data, path.display().to_string(), is_archive)
    };

    if is_archive {
        let temp = tempfile::tempdir().context("cannot create temporary directory")?;
        crate::openredact::extract_archive(&data, &origin, temp.path())?;
        let (rules, notes) = collect_and_parse(temp.path(), &origin, include_all)?;
        return Ok((rules, notes, origin));
    }

    let text = String::from_utf8_lossy(&data).into_owned();
    let (rules, notes) = parse_typescript_source(&text, &origin);
    Ok((rules, notes, origin))
}

fn collect_and_parse(
    root: &Path,
    origin: &str,
    include_all: bool,
) -> Result<(Vec<RuleConfig>, Vec<String>)> {
    let mut files = Vec::new();
    collect_ts_paths(root, root, &mut files)?;
    files.sort();
    let has_patterns_dir = files
        .iter()
        .any(|path| path.to_string_lossy().contains("/patterns/"));
    let mut rules = Vec::new();
    let mut notes = Vec::new();
    for file in files {
        let path_text = file.to_string_lossy();
        if has_patterns_dir && !path_text.contains("/patterns/") {
            continue;
        }
        if !include_all
            && (path_text.contains("/patterns/industries/")
                || path_text.ends_with("/digital-identity.ts"))
        {
            continue;
        }
        let text =
            fs::read_to_string(&file).with_context(|| format!("cannot read {}", file.display()))?;
        let (mut found, mut file_notes) =
            parse_typescript_source(&text, &file.display().to_string());
        rules.append(&mut found);
        notes.append(&mut file_notes);
    }
    deduplicate_ids(&mut rules);
    let _ = origin;
    Ok((rules, notes))
}

fn collect_ts_paths(root: &Path, directory: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)
        .with_context(|| format!("cannot read {}", directory.display()))?
        .flatten()
    {
        let path = entry.path();
        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if SKIP_DIRS.contains(&name) {
                continue;
            }
            collect_ts_paths(root, &path, out)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("ts")
            && !path.to_string_lossy().ends_with(".d.ts")
        {
            let _ = root;
            out.push(path);
        }
    }
    Ok(())
}

fn deduplicate_ids(rules: &mut [RuleConfig]) {
    let mut seen = HashSet::new();
    for rule in rules {
        let base = rule.id.clone();
        if seen.insert(rule.id.clone()) {
            continue;
        }
        let mut suffix = 2;
        while !seen.insert(format!("{base}-{suffix}")) {
            suffix += 1;
        }
        rule.id = format!("{base}-{suffix}");
    }
}

fn parse_typescript_source(source: &str, origin: &str) -> (Vec<RuleConfig>, Vec<String>) {
    let type_re = Regex::new(r#"(?m)^\s*type:\s*["']([A-Za-z0-9_]+)["']"#).unwrap();
    let matches: Vec<_> = type_re.captures_iter(source).collect();
    let mut rules = Vec::new();
    let mut notes = Vec::new();
    for (index, captures) in matches.iter().enumerate() {
        let Some(type_match) = captures.get(1) else {
            continue;
        };
        let segment_start = captures.get(0).map(|m| m.start()).unwrap_or(0);
        let segment_end = matches
            .get(index + 1)
            .and_then(|next| next.get(0).map(|m| m.start()))
            .unwrap_or(source.len());
        let segment = &source[segment_start..segment_end];
        let pattern_type = type_match.as_str();
        let Some(regex_field) = find_field(segment, "regex") else {
            continue;
        };
        let Some((pattern, flags)) = parse_regex_literal(regex_field) else {
            notes.push(format!(
                "{origin}: {pattern_type}: could not parse regex literal"
            ));
            continue;
        };
        let Some((pattern, flags)) = sanitize_regex(&pattern, &flags) else {
            notes.push(format!(
                "{origin}: {pattern_type}: skipped unsupported JS regex construct"
            ));
            continue;
        };
        let priority = extract_number(segment, "priority").unwrap_or(100) as i64;
        let severity = extract_field_string(segment, "severity")
            .and_then(|value| parse_severity(&value))
            .unwrap_or(Severity::Medium);
        let description = extract_field_string(segment, "description")
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| pattern_type.to_string());
        let validate = if pattern_type == "EMAIL" {
            Some("email".to_string())
        } else if pattern_type == "CREDIT_CARD" || segment.contains("validateLuhn") {
            Some("luhn".to_string())
        } else if pattern_type == "IBAN" || segment.contains("validateIBAN") {
            Some("iban".to_string())
        } else if pattern_type == "IPV4" {
            Some("ipv4".to_string())
        } else if pattern_type.starts_with("PHONE") {
            Some("phone".to_string())
        } else {
            None
        };
        let context_heavy_name = pattern_type.contains("NATIONAL_ID")
            || pattern_type.ends_with("_ID")
            || pattern_type.contains("DNI")
            || pattern_type.contains("CIVIL")
            || pattern_type.contains("PASSPORT");
        let safe_numeric = pattern_type.starts_with("PHONE")
            || matches!(
                pattern_type,
                "CREDIT_CARD" | "IPV4" | "SSN" | "SIN_CA" | "ITIN" | "EIN" | "NHS_NUMBER"
            );
        let needs_context = DISABLE_TYPES.contains(&pattern_type)
            || (context_heavy_name && is_numeric_only_pattern(&pattern))
            || (is_numeric_only_pattern(&pattern) && !safe_numeric);
        let mut tags = vec!["openredaction".into(), pattern_type.to_ascii_lowercase()];
        if needs_context {
            tags.push("needs-context".into());
        }
        let id = format!(
            "openredaction-{}",
            pattern_type.to_ascii_lowercase().replace('_', "-")
        );
        let candidate = RuleConfig {
            id: id.clone(),
            description,
            category: "pii".into(),
            severity,
            rule_type: "regex".into(),
            pattern: Some(pattern),
            flags: flags.map(crate::rules::FlagsValue::String),
            group: None::<GroupValue>,
            strip_quotes: false,
            placeholder: Some(pattern_type.to_string()),
            priority,
            enabled: !needs_context,
            paths: Vec::new(),
            exclude_paths: Vec::new(),
            tags,
            validate,
            name_pattern: None,
            name_match: "search".into(),
            allow_keys: Vec::new(),
            bare_values: crate::rules::BareValues::Auto,
            min_length: 32,
            min_entropy: 4.0,
            charset: "base64".into(),
        };
        match Rule::compile(candidate.clone(), origin) {
            Ok(_) => rules.push(candidate),
            Err(error) => notes.push(format!(
                "{origin}: {pattern_type}: skipped invalid pattern ({error:#})"
            )),
        }
    }
    (rules, notes)
}

fn is_numeric_only_pattern(pattern: &str) -> bool {
    let mut value = pattern.to_string();
    for token in ["\\d", "\\s", "\\b", "\\-"] {
        value = value.replace(token, "");
    }
    let unicode = Regex::new(r"\\u\{[0-9A-Fa-f]+\}").unwrap();
    value = unicode.replace_all(&value, "").into_owned();
    !value.chars().any(|ch| ch.is_ascii_alphabetic())
}

fn find_field<'a>(segment: &'a str, field: &str) -> Option<&'a str> {
    let pattern = Regex::new(&format!(r"(?m)\b{}\s*:\s*", regex::escape(field))).ok()?;
    let matched = pattern.find(segment)?;
    Some(&segment[matched.end()..])
}

fn extract_number(segment: &str, field: &str) -> Option<u32> {
    let pattern = Regex::new(&format!(r"(?m)\b{}\s*:\s*(\d+)", regex::escape(field))).ok()?;
    pattern
        .captures(segment)
        .and_then(|captures| captures.get(1))
        .and_then(|value| value.as_str().parse().ok())
}

fn extract_field_string(segment: &str, field: &str) -> Option<String> {
    let rest = find_field(segment, field)?;
    parse_js_string(rest)
}

fn parse_js_string(value: &str) -> Option<String> {
    let value = value.trim_start();
    let quote = value.chars().next()?;
    if quote != '"' && quote != '\'' && quote != '`' {
        return None;
    }
    let mut out = String::new();
    let mut escaped = false;
    for ch in value[quote.len_utf8()..].chars() {
        if escaped {
            out.push(match ch {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                other => other,
            });
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == quote {
            return Some(out);
        } else {
            out.push(ch);
        }
    }
    None
}

fn parse_regex_literal(value: &str) -> Option<(String, String)> {
    let value = value.trim_start();
    if !value.starts_with('/') {
        return None;
    }
    let bytes = value.as_bytes();
    let mut pattern = String::new();
    let mut in_class = false;
    let mut escaped = false;
    let mut index = 1usize;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        if escaped {
            pattern.push('\\');
            pattern.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if in_class {
            pattern.push(ch);
            if ch == ']' {
                in_class = false;
            }
        } else if ch == '[' {
            in_class = true;
            pattern.push(ch);
        } else if ch == '/' {
            let rest = &value[index + 1..];
            let flags: String = rest
                .chars()
                .take_while(|ch| ch.is_ascii_alphabetic())
                .collect();
            return Some((pattern, flags));
        } else {
            pattern.push(ch);
        }
        index += 1;
    }
    None
}

fn sanitize_regex(pattern: &str, flags: &str) -> Option<(String, Option<String>)> {
    let mut pattern = pattern.replace("\\/", "/");
    pattern = convert_unicode_escapes(&pattern);
    // The OpenRedaction credit-card pattern uses digit lookarounds. Rust's
    // regex engine is RE2-like; word boundaries are the closest equivalent.
    pattern = pattern.replace("(?<!\\d)", "\\b").replace("(?!\\d)", "\\b");
    if ["(?=", "(?!", "(?<=", "(?<!", "\\k<"]
        .iter()
        .any(|needle| pattern.contains(needle))
    {
        return None;
    }
    pattern = pattern.replace("(?<", "(?P<");
    let mut kept_flags = String::new();
    for flag in flags.chars() {
        match flag {
            'i' | 'm' | 's' => kept_flags.push(flag),
            'g' | 'u' | 'y' | 'd' | 'v' => {}
            _ => return None,
        }
    }
    Some((pattern, (!kept_flags.is_empty()).then_some(kept_flags)))
}

fn convert_unicode_escapes(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len());
    let mut index = 0usize;
    while index < chars.len() {
        if chars[index] == '\\'
            && index + 5 < chars.len()
            && chars[index + 1] == 'u'
            && chars[index + 2..index + 6]
                .iter()
                .all(|ch| ch.is_ascii_hexdigit())
            && chars.get(index + 6) != Some(&'{')
        {
            out.push_str("\\u{");
            out.extend(&chars[index + 2..index + 6]);
            out.push('}');
            index += 6;
        } else {
            out.push(chars[index]);
            index += 1;
        }
    }
    out
}

fn parse_severity(value: &str) -> Option<Severity> {
    match value.to_ascii_lowercase().as_str() {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}
