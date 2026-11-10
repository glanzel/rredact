use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::Value;

mod support;

fn run(dir: &Path, args: &[&str], stdin: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rredact"));
    command.current_dir(dir).args(args);
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    if let Some(input) = stdin {
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    child.wait_with_output().unwrap()
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn init_scan_and_json_report() {
    let project = tempfile::tempdir().unwrap();
    let init = run(project.path(), &["init"], None);
    assert!(init.status.success(), "{}", stderr(&init));
    assert!(project.path().join(".rredact.yaml").exists());
    assert!(project.path().join(".rredact/rules.d/user.yaml").exists());
    fs::write(
        project.path().join("app.env"),
        format!(
            "PASSWORD=real-pass-42\nGITHUB_TOKEN={}\n",
            support::github_token()
        ),
    )
    .unwrap();
    let scan = run(
        project.path(),
        &["scan", ".", "--all", "--format", "json"],
        None,
    );
    assert_eq!(scan.status.code(), Some(1), "{}", stderr(&scan));
    let payload: Value = serde_json::from_str(&stdout(&scan)).unwrap();
    assert!(payload["summary"]["findings"].as_u64().unwrap() >= 2);
    assert!(payload["findings"][0].get("value").is_none());

    let softened = run(
        project.path(),
        &[
            "scan",
            ".",
            "--all",
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
        None,
    );
    assert!(softened.status.success(), "{}", stderr(&softened));
}

#[test]
fn redact_stdout_and_restore_stdin() {
    let project = tempfile::tempdir().unwrap();
    let original = "PASSWORD=real-pass-42\n";
    fs::write(project.path().join("app.env"), original).unwrap();
    let redacted = run(project.path(), &["redact", "app.env", "--quiet"], None);
    assert!(redacted.status.success(), "{}", stderr(&redacted));
    let redacted_text = stdout(&redacted);
    assert!(!redacted_text.contains("real-pass-42"));
    assert!(redacted_text.contains("[REDACTED:ENV_SECRET:1]"));
    let mapping = project.path().join(".rredact/mapping.json");
    assert!(mapping.exists());

    let restored = run(
        project.path(),
        &["restore", "-", "--mapping", mapping.to_str().unwrap()],
        Some(&redacted_text),
    );
    assert!(restored.status.success(), "{}", stderr(&restored));
    assert_eq!(stdout(&restored), original);
}

#[test]
fn redact_directory_mirrors_files() {
    let project = tempfile::tempdir().unwrap();
    fs::write(project.path().join("app.env"), "PASSWORD=real-pass-42\n").unwrap();
    let result = run(
        project.path(),
        &["redact", ".", "--all", "--output-dir", "out", "--quiet"],
        None,
    );
    assert!(result.status.success(), "{}", stderr(&result));
    let target = project.path().join("out/app.env");
    assert!(target.exists());
    assert!(!fs::read_to_string(target).unwrap().contains("real-pass-42"));
}

#[test]
fn variables_never_emit_values() {
    let project = tempfile::tempdir().unwrap();
    fs::write(
        project.path().join("config.py"),
        "db_password_production = \"real-pass-42\"\npublic_name = \"visible\"\n",
    )
    .unwrap();
    let output = run(
        project.path(),
        &["variables", ".", "--all-names", "--format", "json"],
        None,
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("db_password_production"));
    assert!(!text.contains("real-pass-42"));
    let payload: Value = serde_json::from_str(&text).unwrap();
    assert!(payload["variables"].as_array().unwrap().len() >= 2);
}

#[test]
fn baseline_suppresses_findings() {
    let project = tempfile::tempdir().unwrap();
    fs::write(project.path().join("app.env"), "PASSWORD=real-pass-42\n").unwrap();
    let baseline = project.path().join("baseline.json");
    let create = run(
        project.path(),
        &[
            "baseline",
            "create",
            ".",
            "--output",
            baseline.to_str().unwrap(),
        ],
        None,
    );
    assert!(create.status.success(), "{}", stderr(&create));
    let scan = run(
        project.path(),
        &[
            "scan",
            ".",
            "--all",
            "--baseline",
            baseline.to_str().unwrap(),
        ],
        None,
    );
    assert!(scan.status.success(), "{}", stderr(&scan));
    assert!(stderr(&scan).contains("suppressed by baseline"));
}

#[test]
fn init_is_idempotent_without_force() {
    let project = tempfile::tempdir().unwrap();
    assert!(run(project.path(), &["init"], None).status.success());
    let second = run(project.path(), &["init"], None);
    assert!(second.status.success());
    assert!(stdout(&second).contains("skipped"));
}

#[test]
fn missing_path_is_a_clean_error() {
    let project = tempfile::tempdir().unwrap();
    let output = run(project.path(), &["scan", "does-not-exist"], None);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("rredact: error:"));
}

#[test]
fn gitleaks_toml_rule_file_is_used_by_cli() {
    let project = tempfile::tempdir().unwrap();
    fs::create_dir_all(project.path().join(".rredact/rules.d")).unwrap();
    fs::write(
        project.path().join(".rredact/rules.d/gitleaks.toml"),
        r#"[[rules]]
id = "workspace-secrets"
description = "Workspace secrets"
regex = '''(?i)(db_password_production)\s*=\s*(.*)'''
secretGroup = 2
"#,
    )
    .unwrap();
    fs::write(
        project.path().join("app.env"),
        "db_password_production=real-pass-42\n",
    )
    .unwrap();
    let output = run(project.path(), &["redact", "app.env", "--quiet"], None);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("[REDACTED:WORKSPACE_SECRETS:1]"));
}

#[test]
fn import_openredaction_overwrites_import_file() {
    let project = tempfile::tempdir().unwrap();
    let output = project.path().join("openredaction.yaml");
    fs::write(
        &output,
        "version: 1\nrules:\n  - id: custom-keep\n    description: Keep me\n    category: pii\n    severity: low\n    pattern: 'CUSTOM-[0-9]+'\n",
    )
    .unwrap();
    let source = project.path().join("patterns.ts");
    fs::write(
        &source,
        r#"export const patterns = [
  {
    type: "EMAIL",
    regex: /\b[a-z]+@[a-z]+\.[a-z]+\b/gi,
    priority: 100,
    description: "Email address",
    severity: "high",
  },
  {
    type: "CREDIT_CARD",
    regex: /(?<!\d)(?:\d{4}[ -]?){3}\d{4}(?!\d)/g,
    priority: 100,
    description: "Credit card number",
    severity: "high",
  },
];
"#,
    )
    .unwrap();
    let result = run(
        project.path(),
        &[
            "rules",
            "import-openredaction",
            "--source",
            source.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--force",
        ],
        None,
    );
    assert!(result.status.success(), "{}", stderr(&result));
    let text = fs::read_to_string(&output).unwrap();
    assert!(text.contains("openredaction-email"));
    assert!(text.contains("openredaction-credit-card"));
    assert!(text.contains("validate: luhn"));
    assert!(!text.contains("custom-keep"));
    let validate = run(
        project.path(),
        &["rules", "validate", output.to_str().unwrap()],
        None,
    );
    assert!(validate.status.success(), "{}", stderr(&validate));
}
