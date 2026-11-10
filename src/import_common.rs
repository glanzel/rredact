//! Shared helpers for rule importers.

use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::json;

use crate::rules::RuleConfig;

#[derive(Debug, Serialize)]
struct OutputDocument {
    version: u32,
    metadata: serde_json::Value,
    rules: Vec<RuleConfig>,
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
