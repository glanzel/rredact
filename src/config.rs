//! Configuration and built-in rule loading.

use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use include_dir::{include_dir, Dir};
use regex::Regex;
use serde::Deserialize;

use crate::models::{FailOn, Mode};
use crate::rules::{compile_rules, parse_rule_document, Rule, RuleConfig};

pub const CORE_BUILTINS: &[&str] = &["secrets", "env"];

static DEFAULT_SOURCES_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/defaults");
pub const CONFIG_NAMES: &[&str] = &[
    ".rredact.yaml",
    ".rredact.yml",
    ".rredact.toml",
    "rredact.yaml",
    "rredact.yml",
    "rredact.toml",
];

const DEFAULT_SKIP_PATHS: &[&str] = &[
    ".git/**",
    ".hg/**",
    ".svn/**",
    "node_modules/**",
    ".venv/**",
    "venv/**",
    "__pycache__/**",
    ".mypy_cache/**",
    ".pytest_cache/**",
    ".ruff_cache/**",
    ".tox/**",
    ".nox/**",
    ".cache/**",
    ".terraform/**",
    "target/**",
    "dist/**",
    "build/**",
    ".rredact/mapping.json",
    ".rredact/redacted/**",
    ".rredact/calibration/**",
    ".rredact/out/**",
    "defaults/**",
    "*.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "*.bak",
    "*.orig",
];

const DEFAULT_ALLOW_VALUES: &[&str] = &[
    "changeme",
    "change-me",
    "example",
    "dummy",
    "placeholder",
    "localhost",
    concat!("AKIA", "IOSFODNN7EXAMPLE"),
    concat!("ghp_", "0000000000000000000000000000000000"),
    "str",
    "string",
    "int",
    "integer",
    "bool",
    "boolean",
    "number",
    "object",
    "array",
    "null",
    "true",
    "false",
    "none",
    "any",
    "value",
    "text",
    "bearer",
    "basic",
    "oauth",
    "authentication",
    "[]",
    "{}",
];

const DEFAULT_ALLOW_PATTERNS: &[&str] = &[
    r#"^["']?\$\{?[A-Za-z_][A-Za-z0-9_]*\}?["']?$"#,
    r"^<[^>]{1,80}>$",
    r"^\*{3,}$",
    r"^x{3,}$",
    r"^\.{3}$",
    r"^\$\([^)]*\)$",
    r"^(?i:bearer|basic)[ \t]+<[^>]+>$",
    r"^(?i:bearer|basic)[ \t]+\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$",
    r"^[^@\s]+@(?:example\.(?:com|org|net)|localhost)$",
];

const DEFAULT_ALLOW_KEYS: &[&str] = &[
    "PUBLIC_KEY",
    "KEY_ID",
    "TOKEN_TYPE",
    "AUTH_TYPE",
    "AUTH_METHOD",
    "AUTH_URL",
    "SECRET_NAME",
    "PASSWORD_FIELD",
];

const DEFAULT_RULE_FILES: &[&str] = &[
    ".rredact/rules.d/*.yaml",
    ".rredact/rules.d/*.yml",
    ".rredact/rules.d/*.toml",
];

#[derive(Debug, Default, Deserialize)]
struct UserConfig {
    #[serde(default)]
    builtin: Option<Vec<String>>,
    #[serde(default)]
    sources: Option<Vec<String>>,
    #[serde(default)]
    disable_rules: Vec<String>,
    #[serde(default)]
    enable_rules: Vec<String>,
    #[serde(default)]
    enable_context_rules: Option<bool>,
    #[serde(default)]
    rules: Vec<RuleConfig>,
    #[serde(default)]
    rule_files: Option<Vec<String>>,
    #[serde(default)]
    allowlist: Option<AllowlistConfig>,
    #[serde(default)]
    skip_paths: Vec<String>,
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    max_file_bytes: Option<u64>,
    #[serde(default)]
    mapping: Option<String>,
    #[serde(default)]
    baseline: Option<String>,
    #[serde(default)]
    mode: Option<Mode>,
    #[serde(default)]
    fail_on: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct AllowlistConfig {
    #[serde(default)]
    values: Vec<String>,
    #[serde(default)]
    patterns: Vec<String>,
    #[serde(default)]
    keys: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub rules: Vec<Arc<Rule>>,
    pub allowlist_values: HashSet<String>,
    pub allowlist_patterns: Vec<Regex>,
    pub allowlist_keys: HashSet<String>,
    pub skip: GlobSet,
    pub include: GlobSet,
    pub exclude: GlobSet,
    pub include_patterns: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub max_file_bytes: u64,
    pub mapping_path: Option<PathBuf>,
    pub baseline_path: Option<PathBuf>,
    pub mode: Mode,
    pub fail_on: FailOn,
    pub root: PathBuf,
    pub config_path: Option<PathBuf>,
}

impl Config {
    pub fn allows_value(&self, value: &str) -> bool {
        let mut stripped = value.trim();
        if stripped.len() >= 2 {
            let bytes = stripped.as_bytes();
            let first = bytes[0];
            let last = bytes[bytes.len() - 1];
            if first == last && (first == b'"' || first == b'\'' || first == b'`') {
                stripped = &stripped[1..stripped.len() - 1];
            }
        }
        if stripped.is_empty() {
            return true;
        }
        if self.allowlist_values.contains(stripped) {
            return true;
        }
        let lower = stripped.to_ascii_lowercase();
        if self
            .allowlist_values
            .iter()
            .any(|candidate| candidate.to_ascii_lowercase() == lower)
        {
            return true;
        }
        self.allowlist_patterns.iter().any(|pattern| {
            pattern
                .find(stripped)
                .map(|matched| matched.start() == 0 && matched.end() == stripped.len())
                .unwrap_or(false)
        })
    }

    pub fn allows_key(&self, key: &str) -> bool {
        self.allowlist_keys.contains(&key.to_ascii_uppercase())
    }

    pub fn is_skipped(&self, path: &str) -> bool {
        self.skip.is_match(path.replace('\\', "/"))
    }

    pub fn is_included(&self, path: &str) -> bool {
        self.include_patterns.is_empty() || self.include.is_match(path.replace('\\', "/"))
    }

    pub fn is_excluded(&self, path: &str) -> bool {
        self.exclude.is_match(path.replace('\\', "/"))
    }

    pub fn add_include(&mut self, patterns: &[String]) -> Result<()> {
        self.include_patterns.extend_from_slice(patterns);
        self.include = build_globset(&self.include_patterns)?;
        Ok(())
    }

    pub fn add_exclude(&mut self, patterns: &[String]) -> Result<()> {
        self.exclude_patterns.extend_from_slice(patterns);
        self.exclude = build_globset(&self.exclude_patterns)?;
        Ok(())
    }
}

pub fn find_config(start: &Path) -> Option<PathBuf> {
    let mut current = Some(start);
    while let Some(directory) = current {
        for name in CONFIG_NAMES {
            let candidate = directory.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        current = directory.parent();
    }
    None
}

pub fn load_config(
    config_path: Option<&Path>,
    extra_rule_files: &[PathBuf],
    cwd: Option<&Path>,
) -> Result<Config> {
    let cwd = cwd
        .map(Path::to_path_buf)
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let explicit = config_path
        .map(Path::to_path_buf)
        .or_else(|| env::var_os("RREDACT_CONFIG").map(PathBuf::from));
    let path = if let Some(explicit) = explicit {
        let path = if explicit.is_absolute() {
            explicit
        } else {
            cwd.join(explicit)
        };
        if !path.is_file() {
            bail!("config file not found: {}", path.display());
        }
        Some(path)
    } else {
        find_config(&cwd)
    };
    let root = path
        .as_ref()
        .and_then(|path| path.parent())
        .unwrap_or(&cwd)
        .to_path_buf();

    let user: UserConfig = if let Some(path) = &path {
        let text =
            fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
        if text.trim().is_empty() {
            UserConfig::default()
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("toml") {
            toml::from_str(&text).with_context(|| format!("invalid TOML in {}", path.display()))?
        } else {
            serde_yaml::from_str(&text)
                .with_context(|| format!("invalid YAML in {}", path.display()))?
        }
    } else {
        UserConfig::default()
    };

    let all_sources = default_source_names();
    let user_builtin = user.builtin.clone();
    let user_sources = user.sources.clone();
    let selected_builtin = user_builtin
        .clone()
        .unwrap_or_else(|| CORE_BUILTINS.iter().map(|name| name.to_string()).collect());
    let core_selected: Vec<String> = selected_builtin
        .iter()
        .filter(|name| CORE_BUILTINS.contains(&name.as_str()))
        .cloned()
        .collect();
    let sources_from_builtin: Vec<String> = selected_builtin
        .iter()
        .filter(|name| all_sources.contains(name))
        .cloned()
        .collect();
    let unknown: Vec<&String> = selected_builtin
        .iter()
        .filter(|name| !CORE_BUILTINS.contains(&name.as_str()) && !all_sources.contains(name))
        .collect();
    if !unknown.is_empty() {
        bail!(
            "unknown rule source(s): {:?}; available core bundles: {}; available default sources: {}",
            unknown,
            CORE_BUILTINS.join(", "),
            if all_sources.is_empty() {
                "(none)".to_string()
            } else {
                all_sources.join(", ")
            }
        );
    }
    let selected_sources = match user_sources {
        Some(sources) => {
            let unknown: Vec<&String> = sources
                .iter()
                .filter(|name| !all_sources.contains(name))
                .collect();
            if !unknown.is_empty() {
                bail!(
                    "unknown default source(s): {:?}; available: {}",
                    unknown,
                    all_sources.join(", ")
                );
            }
            sources
        }
        None if !sources_from_builtin.is_empty() => sources_from_builtin,
        None => all_sources.clone(),
    };
    let mut configs: Vec<RuleConfig> = Vec::new();
    for name in &core_selected {
        configs.extend(load_core_bundle(name)?);
    }
    for name in &selected_sources {
        configs.extend(load_default_source(name)?);
    }
    configs.extend(user.rules);

    let mut rule_files = DEFAULT_RULE_FILES
        .iter()
        .map(|pattern| pattern.to_string())
        .collect::<Vec<_>>();
    if let Some(files) = user.rule_files {
        rule_files.extend(files);
    }
    let mut rule_paths = std::collections::BTreeSet::new();
    for pattern in &rule_files {
        for path in expand_glob(&root, pattern)? {
            rule_paths.insert(path);
        }
    }
    for path in rule_paths {
        configs.extend(parse_rule_file(&path)?);
    }
    let mut extras = extra_rule_files.to_vec();
    if let Some(env_rules) = env::var_os("RREDACT_RULES") {
        for part in env::split_paths(&env_rules) {
            extras.push(part);
        }
    }
    for path in extras {
        let path = if path.is_absolute() {
            path
        } else {
            cwd.join(path)
        };
        if !path.is_file() {
            bail!("extra rule file not found: {}", path.display());
        }
        configs.extend(parse_rule_file(&path)?);
    }

    let mut compiled = compile_rules(configs, "config")?;
    let mut seen = HashSet::new();
    for rule in &compiled {
        if !seen.insert(rule.id.clone()) {
            bail!("duplicate rule id {:?}", rule.id);
        }
    }
    let disabled: HashSet<String> = user.disable_rules.iter().cloned().collect();
    compiled.retain(|rule| !disabled.contains(&rule.id));
    let enabled: HashSet<String> = user.enable_rules.iter().cloned().collect();
    for rule in &mut compiled {
        if enabled.contains(&rule.id) {
            rule.enabled = true;
        }
    }
    if user.enable_context_rules.unwrap_or(false) {
        for rule in &mut compiled {
            if rule.tags.iter().any(|tag| tag == "needs-context") {
                rule.enabled = true;
            }
        }
    }

    let allowlist = user.allowlist.unwrap_or_default();
    let mut allow_values: HashSet<String> = DEFAULT_ALLOW_VALUES
        .iter()
        .map(|value| value.to_string())
        .collect();
    allow_values.extend(allowlist.values);
    let mut allow_patterns: Vec<String> = DEFAULT_ALLOW_PATTERNS
        .iter()
        .map(|pattern| pattern.to_string())
        .collect();
    allow_patterns.extend(allowlist.patterns);
    let mut allow_patterns_compiled = Vec::new();
    for pattern in &allow_patterns {
        allow_patterns_compiled.push(
            Regex::new(pattern)
                .with_context(|| format!("invalid allowlist pattern {pattern:?}"))?,
        );
    }
    let mut allow_keys: HashSet<String> = DEFAULT_ALLOW_KEYS
        .iter()
        .map(|key| key.to_string())
        .collect();
    allow_keys.extend(
        allowlist
            .keys
            .into_iter()
            .map(|key| key.to_ascii_uppercase()),
    );

    let mut skip_paths: Vec<String> = DEFAULT_SKIP_PATHS
        .iter()
        .map(|path| path.to_string())
        .collect();
    skip_paths.extend(user.skip_paths);
    let skip = build_globset(&skip_paths)?;
    let include_patterns = user.include;
    let exclude_patterns = user.exclude;
    let include = build_globset(&include_patterns)?;
    let exclude = build_globset(&exclude_patterns)?;

    let mode = user.mode.unwrap_or_default();
    let fail_on = match user.fail_on.as_deref() {
        Some(value) => FailOn::parse(value).ok_or_else(|| {
            anyhow::anyhow!("fail_on must be one of critical, high, medium, low, any, none")
        })?,
        None => FailOn::default(),
    };
    let max_file_bytes = user.max_file_bytes.unwrap_or(2_000_000);
    if max_file_bytes == 0 {
        bail!("max_file_bytes must be positive");
    }
    let mapping_path = resolve_path(
        &root,
        user.mapping.as_deref().unwrap_or(".rredact/mapping.json"),
    );
    let baseline_path = resolve_path(
        &root,
        user.baseline.as_deref().unwrap_or(".rredact/baseline.json"),
    );

    Ok(Config {
        rules: compiled.into_iter().map(Arc::new).collect(),
        allowlist_values: allow_values,
        allowlist_patterns: allow_patterns_compiled,
        allowlist_keys: allow_keys,
        skip,
        include,
        exclude,
        include_patterns,
        exclude_patterns,
        max_file_bytes,
        mapping_path: Some(mapping_path),
        baseline_path: Some(baseline_path),
        mode,
        fail_on,
        root,
        config_path: path,
    })
}

fn load_core_bundle(name: &str) -> Result<Vec<RuleConfig>> {
    let text = match name {
        "secrets" => include_str!("../data/secrets.yaml"),
        "env" => include_str!("../data/env.yaml"),
        other => bail!(
            "unknown core rule bundle {other:?}; available: {}",
            CORE_BUILTINS.join(", ")
        ),
    };
    let document: serde_yaml::Value = serde_yaml::from_str(text).context("invalid builtin YAML")?;
    parse_rule_document(&document, &format!("builtin:{name}"))
}

pub fn default_source_names() -> Vec<String> {
    let mut names = Vec::new();
    for file in DEFAULT_SOURCES_DIR.files() {
        let path = file.path();
        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if extension != "yaml" && extension != "yml" && extension != "toml" {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) {
            names.push(stem.to_string());
        }
    }
    names.sort();
    names.dedup();
    names
}

fn load_default_source(name: &str) -> Result<Vec<RuleConfig>> {
    let file = DEFAULT_SOURCES_DIR.files().find(|file| {
        let path = file.path();
        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        (extension == "yaml" || extension == "yml" || extension == "toml")
            && path.file_stem().and_then(|stem| stem.to_str()) == Some(name)
    });
    let file = file.ok_or_else(|| {
        anyhow::anyhow!(
            "unknown default source {name:?}; available: {}",
            default_source_names().join(", ")
        )
    })?;
    let text = file
        .contents_utf8()
        .ok_or_else(|| anyhow::anyhow!("default source {name:?} is not valid UTF-8"))?;
    let extension = file
        .path()
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if extension == "toml" {
        return parse_gitleaks(text, Path::new(name))
            .with_context(|| format!("invalid TOML in default source {name:?}"));
    }
    let document: serde_yaml::Value = serde_yaml::from_str(text)
        .with_context(|| format!("invalid YAML in default source {name:?}"))?;
    parse_rule_document(&document, &format!("defaults:{name}"))
}

pub fn parse_rule_file(path: &Path) -> Result<Vec<RuleConfig>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    if path.extension().and_then(|ext| ext.to_str()) == Some("toml") {
        return parse_gitleaks(&text, path);
    }
    let document: serde_yaml::Value = serde_yaml::from_str(&text)
        .with_context(|| format!("invalid YAML in {}", path.display()))?;
    parse_rule_document(&document, &path.display().to_string())
}

#[derive(Debug, Deserialize)]
struct GitleaksFile {
    #[serde(default)]
    rules: Vec<GitleaksRule>,
}

#[derive(Debug, Deserialize)]
struct GitleaksRule {
    id: String,
    #[serde(default)]
    description: String,
    regex: String,
    #[serde(rename = "secretGroup", default)]
    secret_group: usize,
    #[serde(default)]
    tags: Vec<String>,
}

fn parse_gitleaks(text: &str, path: &Path) -> Result<Vec<RuleConfig>> {
    let file: GitleaksFile =
        toml::from_str(text).with_context(|| format!("invalid TOML in {}", path.display()))?;
    let mut rules = Vec::new();
    for rule in file.rules {
        rules.push(RuleConfig {
            id: rule.id.clone(),
            description: if rule.description.is_empty() {
                rule.id.clone()
            } else {
                rule.description
            },
            category: "secret".into(),
            severity: crate::models::Severity::High,
            rule_type: "regex".into(),
            pattern: Some(rule.regex),
            flags: None,
            group: (rule.secret_group > 0)
                .then_some(crate::rules::GroupValue::Index(rule.secret_group)),
            strip_quotes: false,
            placeholder: Some(rule.id),
            priority: 100,
            enabled: true,
            paths: Vec::new(),
            exclude_paths: Vec::new(),
            tags: {
                let mut tags = vec!["gitleaks".to_string()];
                tags.extend(rule.tags);
                tags
            },
            validate: None,
            context_required: Vec::new(),
            context_excluded: Vec::new(),
            context_window: 200,
            name_pattern: None,
            name_match: "search".into(),
            allow_keys: Vec::new(),
            bare_values: crate::rules::BareValues::Auto,
            min_length: 32,
            min_entropy: 4.0,
            charset: "base64".into(),
        });
    }
    Ok(rules)
}

fn expand_glob(root: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
    let pattern = expand_home(pattern);
    let search = if Path::new(&pattern).is_absolute() {
        pattern.clone()
    } else {
        root.join(&pattern).to_string_lossy().into_owned()
    };
    let has_glob = pattern.contains('*') || pattern.contains('?') || pattern.contains('[');
    let mut paths = Vec::new();
    for entry in glob::glob(&search)
        .with_context(|| format!("invalid glob pattern {pattern:?}"))?
        .flatten()
    {
        if entry.is_file() {
            paths.push(entry);
        }
    }
    if paths.is_empty() && !has_glob {
        bail!("rule file not found: {pattern}");
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

pub fn resolve_path(root: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(expand_home(value));
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn expand_home(value: &str) -> String {
    if let Some(rest) = value.strip_prefix("~/") {
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home)
                .join(rest)
                .to_string_lossy()
                .into_owned();
        }
    }
    value.to_string()
}

fn build_globset(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder
            .add(Glob::new(pattern).with_context(|| format!("invalid glob pattern {pattern:?}"))?);
    }
    builder.build().context("cannot build glob set")
}
