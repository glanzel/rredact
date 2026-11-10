//! Best-effort OpenRedact/nerwhal importer.
//!
//! OpenRedact keeps most regex recognizers as small Python classes. We read
//! those classes with a deliberately small, non-executing extractor. Statistical
//! NER and spaCy entity-ruler patterns are reported as notes and skipped.

use std::collections::HashSet;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::Serialize;
use serde_json::json;

use crate::models::Severity;
use crate::rules::{GroupValue, RuleConfig};

const SKIP_TAGS: &[&str] = &["NUMBER", "MONEY"];
const SKIP_PATH_PARTS: &[&str] = &[
    "test",
    "tests",
    "fixtures",
    "examples",
    "docs",
    "benchmarks",
];

#[derive(Debug, Serialize)]
struct OutputDocument {
    version: u32,
    metadata: serde_json::Value,
    rules: Vec<RuleConfig>,
}

pub fn import_openredact(
    source: &str,
    timeout: Duration,
) -> Result<(Vec<RuleConfig>, Vec<String>, String)> {
    if source.starts_with("http://") || source.starts_with("https://") {
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
        if lower.ends_with(".tar.gz")
            || lower.ends_with(".tgz")
            || lower.ends_with(".tar")
            || lower.ends_with(".tar.bz2")
            || lower.ends_with(".tar.xz")
            || lower.ends_with(".zip")
            || data.starts_with(b"\x1f\x8b")
            || data.starts_with(b"PK")
        {
            let temp = tempfile::tempdir().context("cannot create temporary directory")?;
            extract_archive(&data, source, temp.path())?;
            let (rules, notes) = collect_python_files(temp.path())?;
            return Ok((rules, notes, source.to_string()));
        }
        let text = String::from_utf8_lossy(&data).into_owned();
        let (rules, notes) = parse_text_source(&text, source)?;
        return Ok((rules, notes, source.to_string()));
    }

    let path = PathBuf::from(source);
    if !path.exists() {
        bail!("source not found: {}", path.display());
    }
    if path.is_dir() {
        let (rules, notes) = collect_python_files(&path)?;
        return Ok((rules, notes, path.display().to_string()));
    }
    let text =
        fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
    let (rules, notes) = parse_text_source(&text, &path.display().to_string())?;
    Ok((rules, notes, path.display().to_string()))
}

fn parse_text_source(text: &str, origin: &str) -> Result<(Vec<RuleConfig>, Vec<String>)> {
    if origin.ends_with(".py") {
        return Ok(parse_python_source(text, origin));
    }
    let document: serde_yaml::Value = if origin.ends_with(".json") {
        serde_json::from_str::<serde_json::Value>(text)
            .map(|value| serde_yaml::to_value(value).unwrap_or(serde_yaml::Value::Null))
            .with_context(|| format!("{origin}: invalid JSON"))?
    } else {
        serde_yaml::from_str(text).with_context(|| format!("{origin}: invalid YAML"))?
    };
    let rules = crate::rules::parse_rule_document(&document, origin)?;
    Ok((rules, Vec::new()))
}

fn collect_python_files(root: &Path) -> Result<(Vec<RuleConfig>, Vec<String>)> {
    let mut files = Vec::new();
    collect_py_paths(root, root, &mut files)?;
    let mut rules = Vec::new();
    let mut notes = Vec::new();
    let mut ids = HashSet::new();
    for file in files {
        let text =
            fs::read_to_string(&file).with_context(|| format!("cannot read {}", file.display()))?;
        let (mut found, mut file_notes) = parse_python_source(&text, &file.display().to_string());
        for rule in &mut found {
            let base = rule.id.clone();
            let mut suffix = 2;
            while ids.contains(&rule.id) {
                rule.id = format!("{base}-{suffix}");
                suffix += 1;
            }
            ids.insert(rule.id.clone());
        }
        rules.extend(found);
        notes.append(&mut file_notes);
    }
    Ok((rules, notes))
}

fn collect_py_paths(root: &Path, directory: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)
        .with_context(|| format!("cannot read {}", directory.display()))?
        .flatten()
    {
        let path = entry.path();
        if path.is_dir() {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            if relative
                .components()
                .any(|part| SKIP_PATH_PARTS.contains(&part.as_os_str().to_string_lossy().as_ref()))
            {
                continue;
            }
            collect_py_paths(root, &path, out)?;
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("py") {
            out.push(path);
        }
    }
    Ok(())
}

fn parse_python_source(source: &str, origin: &str) -> (Vec<RuleConfig>, Vec<String>) {
    let lines: Vec<&str> = source.lines().collect();
    let mut rules = Vec::new();
    let mut notes = Vec::new();
    let mut index = 0usize;
    while index < lines.len() {
        let line = lines[index];
        if !line.starts_with("class ") {
            index += 1;
            continue;
        }
        let class_name = line
            .trim_start_matches("class ")
            .split(['(', ':'])
            .next()
            .unwrap_or("Recognizer")
            .trim()
            .to_string();
        let start = index;
        index += 1;
        while index < lines.len() && !lines[index].starts_with("class ") {
            index += 1;
        }
        let block = &lines[start..index];
        if class_name.starts_with("Test") {
            notes.push(format!("{origin}: {class_name}: skipped test recognizer"));
            continue;
        }
        let tag = match extract_constant(block, "TAG") {
            Some(value) if !value.is_empty() => value,
            _ => continue,
        };
        if SKIP_TAGS.contains(&tag.to_ascii_uppercase().as_str()) {
            notes.push(format!(
                "{origin}: {class_name}: skipped broad recognizer {tag:?}"
            ));
            continue;
        }
        let constants = extract_constants(block);
        let pattern = extract_regexp(block, &constants);
        let Some(pattern) = pattern else {
            if block.iter().any(|line| line.contains("def patterns")) {
                notes.push(format!(
                    "{origin}: {class_name}: skipped entity-ruler patterns (not converted)"
                ));
            }
            continue;
        };
        if pattern.trim().is_empty() {
            continue;
        }
        let mut flags = extract_flags(block);
        let normalized = if flags.as_deref().is_some_and(|flags| flags.contains('x')) {
            normalize_verbose_pattern(&pattern)
        } else {
            pattern.clone()
        };
        let Some(pattern) = sanitize_pattern(&normalized) else {
            notes.push(format!(
                "{origin}: {class_name}: skipped pattern with unsupported lookaround"
            ));
            continue;
        };
        if let Some(flags_value) = &flags {
            let filtered: String = flags_value.chars().filter(|ch| *ch != 'x').collect();
            flags = (!filtered.is_empty()).then_some(filtered);
        }
        let score = extract_constant(block, "SCORE")
            .and_then(|value| value.parse::<f64>().ok())
            .unwrap_or(0.8);
        let severity = if score >= 0.9 {
            Severity::High
        } else if score >= 0.75 {
            Severity::Medium
        } else {
            Severity::Low
        };
        let group = extract_constant(block, "GROUP")
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0);
        let id = format!("openredact-{}", tag.to_ascii_lowercase().replace('_', "-"));
        rules.push(RuleConfig {
            id: id.clone(),
            description: first_doc_line(block).unwrap_or(class_name.clone()),
            category: "pii".into(),
            severity,
            rule_type: "regex".into(),
            pattern: Some(pattern),
            flags: flags.map(crate::rules::FlagsValue::String),
            group: group.map(GroupValue::Index),
            strip_quotes: false,
            placeholder: Some(tag.clone()),
            priority: 80,
            enabled: true,
            paths: Vec::new(),
            exclude_paths: Vec::new(),
            tags: vec!["openredact".into(), class_name.to_ascii_lowercase()],
            validate: if tag == "PHONE" {
                Some("phone".to_string())
            } else if tag == "EMAIL" {
                Some("email".to_string())
            } else {
                None
            },
            name_pattern: None,
            name_match: "search".into(),
            allow_keys: Vec::new(),
            bare_values: crate::rules::BareValues::Auto,
            min_length: 32,
            min_entropy: 4.0,
            charset: "base64".into(),
        });
    }
    (rules, notes)
}

fn normalize_verbose_pattern(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    let mut in_class = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if escaped {
            out.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            out.push(ch);
            escaped = true;
            continue;
        }
        if in_class {
            out.push(ch);
            if ch == ']' {
                in_class = false;
            }
            continue;
        }
        if ch == '[' {
            in_class = true;
            out.push(ch);
            continue;
        }
        if ch == '#' {
            while let Some(next) = chars.peek() {
                if *next == '\n' {
                    break;
                }
                chars.next();
            }
            continue;
        }
        if ch.is_whitespace() {
            continue;
        }
        out.push(ch);
    }
    out
}

fn sanitize_pattern(pattern: &str) -> Option<String> {
    // OpenRedact's email recognizer uses a negative lookahead to avoid a
    // leading hyphen in a domain label. The Rust regex engine is RE2-like, so
    // rewrite that one known construct; skip any other lookaround.
    let rewritten = pattern.replace(
        r"((?!-)[a-zA-Z0-9\-]{0,62}[a-zA-Z0-9]\.)+",
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+",
    );
    if ["(?=", "(?!", "(?<=", "(?<!"]
        .iter()
        .any(|needle| rewritten.contains(needle))
    {
        None
    } else {
        Some(rewritten)
    }
}

fn extract_constant(block: &[&str], name: &str) -> Option<String> {
    let pattern = Regex::new(&format!(r"^\s*{}\s*=\s*(.+)$", regex::escape(name))).ok()?;
    for line in block {
        let Some(captures) = pattern.captures(line) else {
            continue;
        };
        let raw = captures.get(1)?.as_str().trim();
        if let Some(value) = parse_python_string(raw) {
            return Some(value);
        }
        let token = raw.split([' ', '\t', '#']).next()?.trim();
        if !token.is_empty() {
            return Some(token.to_string());
        }
    }
    None
}

fn extract_constants(block: &[&str]) -> std::collections::HashMap<String, String> {
    let mut constants = std::collections::HashMap::new();
    for line in block {
        let trimmed = line.trim_start();
        let Some((name, rest)) = trimmed.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty()
            || !name
                .chars()
                .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
        {
            continue;
        }
        let value = rest.trim();
        if let Some(value) = parse_python_string(value) {
            constants.insert(name.to_string(), value);
        }
    }
    constants
}

fn parse_python_string(value: &str) -> Option<String> {
    let mut value = value.trim();
    while value
        .chars()
        .next()
        .is_some_and(|ch| matches!(ch, 'r' | 'R' | 'f' | 'F' | 'b' | 'B' | 'u' | 'U'))
    {
        value = &value[1..];
    }
    let quote = value.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let triple = format!("{quote}{quote}{quote}");
    let body = value
        .strip_prefix(&triple)
        .or_else(|| value.strip_prefix(quote))?;
    let closing = if value.starts_with(&triple) {
        body.find(&triple)?
    } else {
        body.find(quote)?
    };
    Some(body[..closing].to_string())
}

fn extract_regexp(
    block: &[&str],
    constants: &std::collections::HashMap<String, String>,
) -> Option<String> {
    let start = block.iter().position(|line| line.contains("def regexp"))?;
    let return_line = block[start..]
        .iter()
        .position(|line| line.contains("return"))?
        + start;
    let line = block[return_line];
    let return_index = line.find("return")?;
    let expression = line[return_index + "return".len()..].trim_start();

    if let Some(name) = expression.strip_prefix("self.") {
        let name = name.trim();
        return constants.get(name).cloned();
    }

    let mut triple = None;
    for candidate in ["\"\"\"", "'''"] {
        if expression.contains(candidate) {
            triple = Some(candidate);
            break;
        }
    }
    if let Some(triple) = triple {
        let mut content = String::new();
        let opening = expression.find(triple)?;
        let after = &expression[opening + 3..];
        if let Some(closing) = after.find(triple) {
            content.push_str(&after[..closing]);
        } else {
            content.push_str(after);
            for next in &block[return_line + 1..] {
                if let Some(closing) = next.find(triple) {
                    content.push('\n');
                    content.push_str(&next[..closing]);
                    break;
                }
                content.push('\n');
                content.push_str(next);
            }
        }
        return Some(substitute_constants(&content, constants));
    }

    parse_python_string(expression).map(|value| substitute_constants(&value, constants))
}

fn substitute_constants(
    value: &str,
    constants: &std::collections::HashMap<String, String>,
) -> String {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    let pattern = PATTERN.get_or_init(|| Regex::new(r"\{(?:self\.)?([A-Z][A-Z0-9_]*)\}").unwrap());
    let substituted = pattern
        .replace_all(value, |captures: &regex::Captures| {
            constants
                .get(captures.get(1).unwrap().as_str())
                .cloned()
                .unwrap_or_else(|| captures.get(0).unwrap().as_str().to_string())
        })
        .into_owned();
    // Python f-strings escape literal braces as {{ and }}.
    substituted.replace("{{", "{").replace("}}", "}")
}

fn extract_flags(block: &[&str]) -> Option<String> {
    let line = block.iter().find(|line| line.contains("FLAGS"))?;
    let mut flags = String::new();
    for (name, flag) in [
        ("VERBOSE", 'x'),
        ("IGNORECASE", 'i'),
        ("MULTILINE", 'm'),
        ("DOTALL", 's'),
        ("ASCII", 'a'),
        ("UNICODE", 'u'),
    ] {
        if line.contains(name) && !flags.contains(flag) {
            flags.push(flag);
        }
    }
    (!flags.is_empty()).then_some(flags)
}

fn first_doc_line(block: &[&str]) -> Option<String> {
    let start = block
        .iter()
        .position(|line| line.contains("\"\"\"") || line.contains("'''"))?;
    let quote = if block[start].contains("\"\"\"") {
        "\"\"\""
    } else {
        "'''"
    };
    let after = block[start].split_once(quote)?.1;
    if let Some((first, _)) = after.split_once(quote) {
        let first = first.trim();
        return (!first.is_empty()).then(|| first.to_string());
    }
    let first = after.trim();
    (!first.is_empty()).then(|| first.to_string())
}

pub(crate) fn extract_archive(data: &[u8], origin: &str, root: &Path) -> Result<()> {
    if data.starts_with(b"PK") {
        let mut archive = zip::ZipArchive::new(Cursor::new(data))
            .with_context(|| format!("{origin}: invalid ZIP archive"))?;
        for index in 0..archive.len() {
            let mut file = archive.by_index(index)?;
            let Some(path) = file.enclosed_name() else {
                continue;
            };
            let target = root.join(path);
            if file.is_dir() {
                fs::create_dir_all(&target)?;
            } else if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
                let mut output = fs::File::create(&target)?;
                std::io::copy(&mut file, &mut output)?;
            }
        }
        return Ok(());
    }
    let reader: Box<dyn Read> = if data.starts_with(b"\x1f\x8b") {
        Box::new(flate2::read::GzDecoder::new(Cursor::new(data)))
    } else {
        Box::new(Cursor::new(data))
    };
    let mut archive = tar::Archive::new(reader);
    for entry in archive.entries()? {
        let mut entry = entry?;
        entry
            .unpack_in(root)
            .with_context(|| format!("{origin}: unsafe archive entry"))?;
    }
    Ok(())
}

pub fn write_rules_yaml(
    rules: &[RuleConfig],
    output: &Path,
    source: &str,
    _notes: &[String],
) -> Result<()> {
    let document = OutputDocument {
        version: 1,
        metadata: json!({
            "source": source,
            "license": "MIT",
            "generator": "rredact rules import",
        }),
        rules: rules.to_vec(),
    };
    let text = serde_yaml::to_string(&document)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::File::create(output)?;
    file.write_all(text.as_bytes())?;
    Ok(())
}
