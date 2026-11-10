use std::fs;
use std::path::Path;

use rredact::config::load_config;
use rredact::engine::Engine;
use rredact::mapping::MappingStore;
use tempfile::TempDir;

mod support;

fn project_with_config(config: Option<&str>) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    if let Some(config) = config {
        fs::write(dir.path().join(".rredact.yaml"), config).unwrap();
    }
    dir
}

fn engine(project: &Path, mapping: Option<MappingStore>) -> Engine {
    let config = load_config(None, &[], Some(project)).unwrap();
    Engine::new(
        config,
        mapping.unwrap_or_else(|| MappingStore::new(None).unwrap()),
        None,
    )
}

#[test]
fn detects_known_token_formats() {
    let project = project_with_config(None);
    let aws = support::aws_key();
    let github = support::github_token();
    let stripe = support::stripe_key();
    let openai = support::openai_key();
    let anthropic = support::anthropic_key();
    let jwt = support::jwt();
    let text =
        format!("AWS={aws}\nGH={github}\nST={stripe}\nOAI={openai}\nANT={anthropic}\nJWT={jwt}\n");
    let mut engine = engine(project.path(), None);
    let result = engine
        .redact(&text, Some("sample.env"), None, None, true)
        .unwrap();
    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id.as_str()).collect();
    for id in [
        "aws-access-key",
        "github-token",
        "stripe-secret-key",
        "openai-api-key",
        "anthropic-api-key",
        "jwt",
    ] {
        assert!(ids.contains(&id), "missing {id}: {ids:?}");
    }
    assert!(!result.text.contains(&aws));
    assert!(!result.text.contains(&github));
}

#[test]
fn env_assignment_preserves_quotes_and_comments() {
    let project = project_with_config(None);
    let text = "DATABASE_PASSWORD=\"correct horse battery staple\"\nAPI_KEY=abc123\nPUBLIC_KEY=abc\nAUTH_TYPE=oauth\nPASSWORD=foo # keep this comment\n";
    let mut engine = engine(project.path(), None);
    let result = engine
        .redact(text, Some("sample.env"), None, None, true)
        .unwrap();
    assert!(result
        .text
        .contains("DATABASE_PASSWORD=\"[REDACTED:ENV_SECRET:1]\""));
    assert!(result.text.contains("API_KEY=[REDACTED:ENV_SECRET:2]"));
    assert!(result.text.contains("PUBLIC_KEY=abc"));
    assert!(result.text.contains("AUTH_TYPE=oauth"));
    assert!(result
        .text
        .contains("PASSWORD=[REDACTED:ENV_SECRET:3] # keep this comment"));
    assert!(!result.text.contains("correct horse"));
}

#[test]
fn json_and_yaml_assignments() {
    let project = project_with_config(None);
    let text = "{\"client_secret\": \"s3cr3t\", \"public\": \"x\"}\n\"api_key\": \"abc123\",\ndb_password: hunter2\n";
    let mut engine = engine(project.path(), None);
    let result = engine
        .redact(text, Some("config.json"), None, None, true)
        .unwrap();
    assert!(result
        .text
        .contains("\"client_secret\": \"[REDACTED:JSON_SECRET:1]\""));
    assert!(result.text.contains("\"public\": \"x\""));
    assert!(result
        .text
        .contains("\"api_key\": \"[REDACTED:JSON_SECRET:2]\""));
    assert!(result
        .text
        .contains("db_password: [REDACTED:JSON_SECRET:3]"));
}

#[test]
fn code_paths_require_quoted_values() {
    let project = project_with_config(None);
    let text = "token: str | None = None\ntoken = token\npassword = \"hunter2\"\nAPI_TOKEN = os.environ.get(\"API_TOKEN\")\nconst clientSecret = \"real-secret-42\";\nPASSWORD: str = \"real-pass-42\"\n";
    let mut engine = engine(project.path(), None);
    let result = engine
        .redact(text, Some("app.py"), None, None, true)
        .unwrap();
    assert_eq!(result.findings.len(), 3);
    assert!(!result.text.contains("hunter2"));
    assert!(!result.text.contains("real-secret-42"));
    assert!(!result.text.contains("real-pass-42"));
    assert!(result.text.contains("token: str"));
    assert!(result.text.contains("os.environ"));
}

#[test]
fn allowlisted_values_and_keys_are_ignored() {
    let project = project_with_config(None);
    let text = "PASSWORD=changeme\nTOKEN=${MY_TOKEN}\nSECRET=<provided-at-runtime>\nTOKEN_TYPE=Bearer\nAUTH_METHOD=oauth\nEMAIL=dev@example.com\n";
    let mut engine = engine(project.path(), None);
    let result = engine
        .redact(text, Some("sample.env"), None, None, true)
        .unwrap();
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn mapping_is_deterministic_and_restorable() {
    let project = project_with_config(None);
    let mapping_path = project.path().join(".rredact/mapping.json");
    let mut engine = engine(
        project.path(),
        Some(MappingStore::new(Some(mapping_path.clone())).unwrap()),
    );
    let token = support::github_token();
    let original = format!("TOKEN={token}\nOTHER={token}\n");
    let first = engine
        .redact(&original, Some("a.env"), None, None, true)
        .unwrap();
    let second = engine
        .redact(&original, Some("b.env"), None, None, true)
        .unwrap();
    assert_eq!(first.text, second.text);
    assert_eq!(first.text.matches("[REDACTED:GITHUB_TOKEN:1]").count(), 2);
    assert!(mapping_path.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&mapping_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let (restored, count, unresolved) = engine.restore(&first.text);
    assert_eq!(count, 2);
    assert!(unresolved.is_empty());
    assert_eq!(restored, original);
}

#[test]
fn mask_and_hash_modes_are_not_restorable() {
    let project = project_with_config(None);
    let text = format!("TOKEN={}\n", support::github_token());
    let mut engine = engine(project.path(), None);
    let masked = engine
        .redact(&text, None, Some(rredact::models::Mode::Mask), None, true)
        .unwrap();
    assert_eq!(masked.text, "TOKEN=***\n");
    let hashed = engine
        .redact(&text, None, Some(rredact::models::Mode::Hash), None, true)
        .unwrap();
    assert!(hashed.text.contains("[REDACTED:GITHUB_TOKEN:"));
    let (_, count, unresolved) = engine.restore(&hashed.text);
    assert_eq!(count, 0);
    assert!(!unresolved.is_empty());
}

#[test]
fn validators_reject_false_positives() {
    let project = project_with_config(None);
    let text = "valid card 4111 1111 1111 1111\ninvalid card 4111 1111 1111 1112\nvalid iban DE89 3704 0044 0532 0130 00\ninvalid iban DE00 3704 0044 0532 0130 00\nport 5432\nip 192.168.1.1\ncall +49 30 12345678\n";
    let mut engine = engine(project.path(), None);
    let result = engine
        .redact(text, Some("sample.env"), None, None, true)
        .unwrap();
    assert!(result.text.contains("[REDACTED:CREDIT_CARD:1]"));
    assert!(result.text.contains("4111 1111 1111 1112"));
    assert!(result.text.contains("[REDACTED:IBAN:1]"));
    assert!(result.text.contains("DE00 3704"));
    assert!(result.text.contains("port 5432"));
    assert!(result.text.contains("192.168.1.1"));
    let phones: Vec<_> = result
        .findings
        .iter()
        .filter(|finding| finding.rule_id.contains("phone"))
        .collect();
    assert_eq!(phones.len(), 1);
}

#[test]
fn scan_does_not_create_mapping() {
    let project = project_with_config(None);
    let mapping_path = project.path().join("mapping.json");
    let mut engine = engine(
        project.path(),
        Some(MappingStore::new(Some(mapping_path.clone())).unwrap()),
    );
    let result = engine.scan("PASSWORD=hunter2\n", Some("x.env")).unwrap();
    assert!(!result.findings.is_empty());
    assert!(!mapping_path.exists());
    assert!(result.findings[0].placeholder.is_none());
}

#[test]
fn custom_rule_file_is_loaded() {
    let project = project_with_config(Some(
        "builtin: [secrets]\nrule_files: ['.rredact/rules.d/*.yaml']\n",
    ));
    fs::create_dir_all(project.path().join(".rredact/rules.d")).unwrap();
    fs::write(
        project.path().join(".rredact/rules.d/llm.yaml"),
        "version: 1\nrules:\n  - id: employee-id\n    description: Employee ID\n    category: pii\n    severity: medium\n    pattern: '\\bEMP-[0-9]{6}\\b'\n    placeholder: EMPLOYEE_ID\n",
    )
    .unwrap();
    let mut engine = engine(project.path(), None);
    let result = engine
        .redact("id EMP-123456\n", Some("data.txt"), None, None, true)
        .unwrap();
    assert!(result.text.contains("[REDACTED:EMPLOYEE_ID:1]"));
}

#[test]
fn gitleaks_toml_is_loaded() {
    let project = project_with_config(Some(
        "builtin: []\nrule_files: ['.rredact/rules.d/*.toml']\n",
    ));
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
    let mut engine = engine(project.path(), None);
    let result = engine
        .redact(
            "db_password_production=real-pass-42\n",
            Some("config.env"),
            None,
            None,
            true,
        )
        .unwrap();
    assert!(result.text.contains("[REDACTED:WORKSPACE_SECRETS:1]"));
}

#[test]
fn toml_project_config_is_found() {
    let project = tempfile::tempdir().unwrap();
    fs::write(
        project.path().join("rredact.toml"),
        "builtin = [\"secrets\"]\nsources = []\n",
    )
    .unwrap();
    let config = load_config(None, &[], Some(project.path())).unwrap();
    let ids: Vec<&str> = config.rules.iter().map(|rule| rule.id.as_str()).collect();
    assert!(ids.contains(&"github-token"));
    assert!(!ids.contains(&"openredaction-email"));
}

#[test]
fn enable_rules_activates_disabled_builtin() {
    let project = project_with_config(Some("enable_rules: [openredaction-name]\n"));
    let config = load_config(None, &[], Some(project.path())).unwrap();
    let rule = config
        .rules
        .iter()
        .find(|rule| rule.id == "openredaction-name")
        .unwrap();
    assert!(rule.enabled);
}

#[test]
fn default_sources_are_loaded_by_default() {
    let project = tempfile::tempdir().unwrap();
    let config = load_config(None, &[], Some(project.path())).unwrap();
    let ids: Vec<&str> = config.rules.iter().map(|rule| rule.id.as_str()).collect();
    assert!(ids.contains(&"openredaction-email"));
    assert!(ids.contains(&"sensitive-variable-assignment"));
    assert!(rredact::config::default_source_names().contains(&"openredaction".to_string()));
}

#[test]
fn core_builtin_selection_excludes_sources() {
    let project = project_with_config(Some("builtin: [secrets, env]\nsources: []\n"));
    let config = load_config(None, &[], Some(project.path())).unwrap();
    let ids: Vec<&str> = config.rules.iter().map(|rule| rule.id.as_str()).collect();
    assert!(ids.contains(&"github-token"));
    assert!(!ids.contains(&"openredaction-email"));
}

#[test]
fn sources_can_be_selected_explicitly() {
    let project = project_with_config(Some("builtin: [secrets, env]\nsources: [openredaction]\n"));
    let config = load_config(None, &[], Some(project.path())).unwrap();
    let ids: Vec<&str> = config.rules.iter().map(|rule| rule.id.as_str()).collect();
    assert!(ids.contains(&"github-token"));
    assert!(ids.contains(&"openredaction-email"));
}

#[test]
fn source_only_selection_is_possible() {
    let project = project_with_config(Some("builtin: [openredaction]\n"));
    let config = load_config(None, &[], Some(project.path())).unwrap();
    let ids: Vec<&str> = config.rules.iter().map(|rule| rule.id.as_str()).collect();
    assert!(ids.contains(&"openredaction-email"));
    assert!(!ids.contains(&"github-token"));
}

#[test]
fn context_rules_can_be_enabled_as_a_group() {
    let project = project_with_config(Some("enable_context_rules: true\n"));
    let config = load_config(None, &[], Some(project.path())).unwrap();
    let rule = config
        .rules
        .iter()
        .find(|rule| rule.id == "openredaction-name")
        .unwrap();
    assert!(rule.enabled);
}

#[test]
fn context_required_blocks_matches_without_context() {
    let project = project_with_config(Some(
        "builtin: []\nsources: []\nrules:\n  - id: context-demo\n    description: Context demo\n    category: secret\n    severity: high\n    pattern: '\\bSECRET-[0-9]{4}\\b'\n    context_required: ['(?i)invoice|bill']\n    placeholder: CONTEXT_DEMO\n",
    ));
    let mut engine = engine(project.path(), None);
    let without = engine
        .redact("SECRET-1234\n", Some("sample.env"), None, None, true)
        .unwrap();
    assert!(without.findings.is_empty());
    let with = engine
        .redact(
            "invoice SECRET-1234\n",
            Some("sample.env"),
            None,
            None,
            true,
        )
        .unwrap();
    assert_eq!(with.findings.len(), 1);
    assert!(with.text.contains("[REDACTED:CONTEXT_DEMO:1]"));
}
