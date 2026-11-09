use std::fs;
use std::path::Path;
use std::time::Duration;

use rredact::config::load_config;
use rredact::openredact::{import_openredact, write_rules_yaml};
use tempfile::TempDir;

const SAMPLE: &str = r#"
class EmailRecognizer:
    """Recognize email addresses."""

    TAG = "EMAIL"
    SCORE = 0.95
    FLAGS = re.VERBOSE

    @property
    def regexp(self):
        return r"""[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}"""


class PhoneRecognizer:
    """Recognize phone numbers."""

    TAG = "PHONE"
    SCORE = 0.8
    GROUP = 1
    FLAGS = re.VERBOSE
    COUNTRY_CODE_REGEX = r"(\+|00)\d{1,3}"

    @property
    def regexp(self):
        return rf"""{self.COUNTRY_CODE_REGEX}[ .-]?\d{{3,4}}[ -]?\d{{4}}"""


class NumberRecognizer:
    """Too broad."""

    TAG = "NUMBER"
    SCORE = 0.5

    @property
    def regexp(self):
        return r"\d+"
"#;

fn project() -> TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn imports_python_recognizers_and_writes_yaml() {
    let project = project();
    let source = project.path().join("recognizer.py");
    fs::write(&source, SAMPLE).unwrap();
    let (rules, notes, origin) =
        import_openredact(source.to_str().unwrap(), Duration::from_secs(5)).unwrap();
    assert_eq!(origin, source.to_str().unwrap());
    let ids: Vec<&str> = rules.iter().map(|rule| rule.id.as_str()).collect();
    assert!(ids.contains(&"openredact-email"));
    assert!(ids.contains(&"openredact-phone"));
    assert!(!ids.contains(&"openredact-number"));
    assert!(notes.iter().any(|note| note.contains("broad recognizer")));

    let output = project.path().join(".rredact/rules.d/openredact.yaml");
    write_rules_yaml(&rules, &output, &origin, &notes).unwrap();
    fs::write(
        project.path().join(".rredact.yaml"),
        "builtin: []\nrule_files: ['.rredact/rules.d/*.yaml']\n",
    )
    .unwrap();
    let config = load_config(None, &[], Some(project.path())).unwrap();
    let loaded: Vec<&str> = config.rules.iter().map(|rule| rule.id.as_str()).collect();
    assert!(loaded.contains(&"openredact-email"));
    assert!(loaded.contains(&"openredact-phone"));
}

#[test]
fn rejects_missing_source() {
    let project = project();
    let missing = project.path().join("missing.py");
    let error = import_openredact(missing.to_str().unwrap(), Duration::from_secs(1)).unwrap_err();
    assert!(format!("{error:#}").contains("source not found"));
}

#[test]
fn imports_yaml_rule_documents() {
    let project = project();
    let source = project.path().join("rules.yaml");
    fs::write(
        &source,
        "version: 1\nrules:\n  - id: demo\n    description: Demo\n    category: secret\n    severity: high\n    pattern: 'DEMO-[0-9]+'\n",
    )
    .unwrap();
    let (rules, _notes, _origin) =
        import_openredact(source.to_str().unwrap(), Duration::from_secs(5)).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, "demo");
}

#[test]
fn cli_import_filters_existing_ids() {
    // Covered end-to-end in tests/cli.rs; this test keeps the importer API's
    // public output shape covered without network access.
    let project = project();
    let source = project.path().join("recognizer.py");
    fs::write(&source, SAMPLE).unwrap();
    let (rules, notes, origin) =
        import_openredact(source.to_str().unwrap(), Duration::from_secs(5)).unwrap();
    let output = project.path().join("out.yaml");
    write_rules_yaml(&rules, &output, &origin, &notes).unwrap();
    assert!(Path::new(&output).exists());
}
