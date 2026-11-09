//! File discovery and text I/O.

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ignore::WalkBuilder;

use crate::config::Config;

const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".cache",
    ".terraform",
    "target",
    "dist",
    "build",
    ".rredact",
];

const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "pdf", "zip", "gz", "bz2", "xz", "7z",
    "rar", "tar", "woff", "woff2", "ttf", "otf", "eot", "mp3", "mp4", "mov", "avi", "wav", "ogg",
    "webm", "sqlite", "db", "pyc", "so", "dylib", "dll", "exe", "bin",
];

const IGNORE_DIRECTIVES: &[&str] = &[
    "rredact:ignore-file",
    "rredact: ignore-file",
    "rredact:disable-file",
];

#[derive(Debug, Clone)]
pub struct SourceFile {
    pub path: PathBuf,
    pub rel: String,
    pub text: String,
}

pub fn iter_files(paths: &[String], config: &Config, use_git: bool, cwd: &Path) -> Vec<SourceFile> {
    let mut candidates = BTreeSet::new();
    for item in paths {
        let path = PathBuf::from(item);
        let path = if path.is_absolute() {
            path
        } else {
            cwd.join(path)
        };
        if path.is_file() {
            if !path.is_symlink() {
                candidates.insert(path);
            }
            continue;
        }
        if !path.is_dir() {
            continue;
        }
        let root = path.clone();
        let mut builder = WalkBuilder::new(&path);
        builder
            .hidden(false)
            .follow_links(false)
            .git_ignore(use_git)
            .git_global(use_git)
            .git_exclude(use_git)
            .ignore(use_git)
            .parents(use_git);
        builder.filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            let name = entry.file_name().to_string_lossy();
            !SKIP_DIRS.contains(&name.as_ref())
        });
        for entry in builder.build().flatten() {
            let entry_path = entry.path();
            if entry_path == root {
                continue;
            }
            let Some(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_file() || file_type.is_symlink() {
                continue;
            }
            candidates.insert(entry_path.to_path_buf());
        }
    }

    let mut out = Vec::new();
    for path in candidates {
        let rel = relative_path(&path, cwd);
        if config.is_skipped(&rel) || !config.is_included(&rel) || config.is_excluded(&rel) {
            continue;
        }
        let Ok(metadata) = path.metadata() else {
            continue;
        };
        if metadata.len() > config.max_file_bytes {
            continue;
        }
        if is_binary(&path) {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        if has_ignore_directive(&text) {
            continue;
        }
        out.push(SourceFile { path, rel, text });
    }
    out
}

pub fn relative_path(path: &Path, cwd: &Path) -> String {
    path.strip_prefix(cwd)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn is_binary(path: &Path) -> bool {
    if let Some(extension) = path.extension().and_then(|ext| ext.to_str()) {
        if BINARY_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str()) {
            return true;
        }
    }
    let Ok(mut file) = fs::File::open(path) else {
        return true;
    };
    let mut buffer = [0u8; 8192];
    let Ok(read) = file.read(&mut buffer) else {
        return true;
    };
    buffer[..read].contains(&0)
}

fn has_ignore_directive(text: &str) -> bool {
    let head: String = text.chars().take(8192).collect();
    IGNORE_DIRECTIVES
        .iter()
        .any(|directive| head.contains(directive))
}

pub fn write_text(path: &Path, text: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    fs::write(path, text).with_context(|| format!("cannot write {}", path.display()))
}

pub fn write_text_atomic(path: &Path, text: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let permissions = fs::metadata(path).ok().map(|meta| meta.permissions());
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("cannot create temporary file in {}", parent.display()))?;
    std::io::Write::write_all(&mut temp, text.as_bytes())?;
    temp.flush()?;
    if let Some(permissions) = permissions {
        let _ = temp.as_file().set_permissions(permissions);
    }
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

pub fn read_stdin() -> Result<String> {
    let mut text = String::new();
    std::io::stdin()
        .read_to_string(&mut text)
        .context("cannot read stdin")?;
    Ok(text)
}
