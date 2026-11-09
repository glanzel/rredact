//! Reversible placeholder mapping.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::rules::sanitize_kind;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MappingEntry {
    kind: String,
    value: String,
    fingerprint: String,
    created: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct MappingFile {
    #[serde(rename = "_warning", default)]
    warning: String,
    version: u32,
    entries: BTreeMap<String, MappingEntry>,
}

#[derive(Debug)]
pub struct MappingStore {
    pub path: Option<PathBuf>,
    entries: BTreeMap<String, MappingEntry>,
    by_fingerprint: HashMap<String, String>,
    counters: HashMap<String, usize>,
    lock: Mutex<()>,
}

impl MappingStore {
    pub fn new(path: Option<PathBuf>) -> Result<Self> {
        let mut store = Self {
            path,
            entries: BTreeMap::new(),
            by_fingerprint: HashMap::new(),
            counters: HashMap::new(),
            lock: Mutex::new(()),
        };
        if let Some(path) = store.path.clone() {
            if path.exists() {
                store.load(&path)?;
            }
        }
        Ok(store)
    }

    fn load(&mut self, path: &Path) -> Result<()> {
        let data = fs::read_to_string(path)
            .with_context(|| format!("cannot read mapping file {}", path.display()))?;
        let parsed: serde_json::Value = serde_json::from_str(&data)
            .with_context(|| format!("invalid mapping file {}", path.display()))?;
        let entries = parsed
            .get("entries")
            .cloned()
            .unwrap_or_else(|| parsed.clone());
        if let Some(map) = entries.as_object() {
            for (placeholder, value) in map {
                let Some(object) = value.as_object() else {
                    continue;
                };
                let Some(original) = object.get("value").and_then(|v| v.as_str()) else {
                    continue;
                };
                let kind = sanitize_kind(
                    object
                        .get("kind")
                        .and_then(|v| v.as_str())
                        .unwrap_or("SECRET"),
                );
                let fingerprint = object
                    .get("fingerprint")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| fingerprint(original));
                let created = object
                    .get("created")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let entry = MappingEntry {
                    kind: kind.clone(),
                    value: original.to_string(),
                    fingerprint: fingerprint.clone(),
                    created,
                };
                self.entries.insert(placeholder.clone(), entry);
                self.by_fingerprint
                    .entry(fingerprint)
                    .or_insert_with(|| placeholder.clone());
                if let Some(captures) = placeholder_regex().captures(placeholder) {
                    if let Some(number) = captures
                        .get(1)
                        .and_then(|m| m.as_str().parse::<usize>().ok())
                    {
                        let counter = self.counters.entry(kind).or_default();
                        *counter = (*counter).max(number);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn stored(&self) -> bool {
        self.path.is_some()
    }

    pub fn placeholder_for(&mut self, kind: &str, value: &str) -> String {
        let kind = sanitize_kind(kind);
        let fp = fingerprint(value);
        let _guard = self.lock.lock().ok();
        if let Some(existing) = self.by_fingerprint.get(&fp) {
            if self.entries.contains_key(existing) {
                return existing.clone();
            }
        }
        let mut number = self.counters.get(&kind).copied().unwrap_or(0) + 1;
        let mut placeholder = format!("[REDACTED:{kind}:{number}]");
        while self.entries.contains_key(&placeholder) {
            number += 1;
            placeholder = format!("[REDACTED:{kind}:{number}]");
        }
        self.counters.insert(kind.clone(), number);
        self.entries.insert(
            placeholder.clone(),
            MappingEntry {
                kind,
                value: value.to_string(),
                fingerprint: fp.clone(),
                created: Utc::now().to_rfc3339(),
            },
        );
        self.by_fingerprint.insert(fp, placeholder.clone());
        placeholder
    }

    pub fn save(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let _guard = self.lock.lock().ok();
        let payload = MappingFile {
            warning:
                "This file contains the original secrets/PII. Never commit or send it to an LLM."
                    .into(),
            version: 1,
            entries: self.entries.clone(),
        };
        let data = serde_json::to_vec_pretty(&payload)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let mut temp = tempfile::NamedTempFile::new_in(parent)
            .with_context(|| format!("cannot create temporary file in {}", parent.display()))?;
        std::io::Write::write_all(&mut temp, &data)?;
        temp.flush()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = temp
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o600));
        }
        temp.persist(path)
            .map_err(|error| error.error)
            .with_context(|| format!("cannot write mapping file {}", path.display()))?;
        Ok(())
    }

    pub fn restore(&self, text: &str) -> (String, usize, Vec<String>) {
        let _guard = self.lock.lock().ok();
        let mut restored = text.to_string();
        let mut count = 0usize;
        let mut placeholders: Vec<&String> = self.entries.keys().collect();
        placeholders.sort_by_key(|placeholder| std::cmp::Reverse(placeholder.len()));
        for placeholder in placeholders {
            let matches = restored.matches(placeholder.as_str()).count();
            if matches > 0 {
                restored = restored.replace(placeholder, &self.entries[placeholder].value);
                count += matches;
            }
        }
        let mut unresolved = Vec::new();
        for matched in token_regex().find_iter(&restored) {
            let value = matched.as_str().to_string();
            if !self.entries.contains_key(&value) && !unresolved.contains(&value) {
                unresolved.push(value);
            }
        }
        (restored, count, unresolved)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

pub fn fingerprint(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn placeholder_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"^\[REDACTED:([A-Z0-9_]+):(\d+)\]$").unwrap())
}

fn token_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"\[REDACTED:[A-Z0-9_]+:[A-Za-z0-9]+\]").unwrap())
}
