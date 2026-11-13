use std::path::Path;

use rredact::api::{self, AppState};
use rredact::config::load_config;
use rredact::engine::Engine;
use rredact::mapping::MappingStore;
use serde_json::json;

mod support;

struct TestServer {
    runtime: Option<tokio::runtime::Runtime>,
    port: u16,
}

impl TestServer {
    fn start(project: &Path, token: Option<&str>, no_store: bool) -> Self {
        let config = load_config(None, &[], Some(project)).unwrap();
        let mapping = MappingStore::new(if no_store {
            None
        } else {
            Some(project.join(".rredact/mapping.json"))
        })
        .unwrap();
        let session_dir = if no_store {
            None
        } else {
            Some(project.join(".rredact/sessions"))
        };
        let state = AppState {
            engine: std::sync::Arc::new(std::sync::Mutex::new(Engine::new(
                config.clone(),
                mapping,
                None,
            ))),
            config: std::sync::Arc::new(std::sync::Mutex::new(config.clone())),
            sessions: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            session_dir,
            token: token.map(str::to_string),
            config_path: config.config_path.clone(),
            root: config.root.clone(),
            extra_rule_files: Vec::new(),
        };
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        runtime.spawn(async move {
            axum::serve(listener, api::router(state)).await.unwrap();
        });
        Self {
            runtime: Some(runtime),
            port,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

fn call(
    server: &TestServer,
    path: &str,
    body: Option<serde_json::Value>,
    token: Option<&str>,
) -> (u16, serde_json::Value) {
    let request = if body.is_some() {
        ureq::post(&server.url(path)).set("Content-Type", "application/json")
    } else {
        ureq::get(&server.url(path))
    };
    let request = if let Some(token) = token {
        request.set("Authorization", &format!("Bearer {token}"))
    } else {
        request
    };
    let result = if let Some(body) = body {
        request.send_string(&body.to_string())
    } else {
        request.call()
    };
    // ureq returns Err for non-2xx; inspect the response in that case.
    let response = match result {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(error) => panic!("request failed: {error}"),
    };
    let status = response.status();
    let text = response.into_string().unwrap();
    let value = serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw": text}));
    (status, value)
}

#[test]
fn health_is_open_but_rules_require_token() {
    let project = tempfile::tempdir().unwrap();
    let server = TestServer::start(project.path(), Some("secret"), false);
    let (status, body) = call(&server, "/health", None, None);
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");

    let (status, body) = call(&server, "/rules", None, None);
    assert_eq!(status, 401);
    assert_eq!(body["error"], "unauthorized");

    let (status, body) = call(&server, "/rules", None, Some("secret"));
    assert_eq!(status, 200);
    assert!(body["count"].as_u64().unwrap() > 0);
}

#[test]
fn redact_and_restore_roundtrip() {
    let project = tempfile::tempdir().unwrap();
    let server = TestServer::start(project.path(), Some("secret"), false);
    let original = format!("PASSWORD=real-pass-42\nTOKEN={}\n", support::github_token());
    let (status, body) = call(
        &server,
        "/redact",
        Some(json!({"text": &original, "path": "app.env"})),
        Some("secret"),
    );
    assert_eq!(status, 200);
    assert!(!body["text"].as_str().unwrap().contains("real-pass-42"));
    assert_eq!(body["summary"]["findings"], 2);

    let (status, restored) = call(
        &server,
        "/restore",
        Some(json!({"text": body["text"]})),
        Some("secret"),
    );
    assert_eq!(status, 200);
    assert_eq!(restored["text"], original);
    assert_eq!(restored["restored"], 2);
}

#[test]
fn validate_and_reload() {
    let project = tempfile::tempdir().unwrap();
    let server = TestServer::start(project.path(), None, false);
    let (status, body) = call(
        &server,
        "/rules/validate",
        Some(
            json!({"rules": [{"id": "demo", "description": "Demo", "category": "secret", "severity": "low", "pattern": "DEMO-[0-9]+"}]}),
        ),
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(body["valid"], true);

    let (status, body) = call(
        &server,
        "/rules/validate",
        Some(json!({"rules": [{"id": "bad", "pattern": "("}]})),
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(body["valid"], false);

    std::fs::create_dir_all(project.path().join(".rredact/rules.d")).unwrap();
    std::fs::write(
        project.path().join(".rredact/rules.d/llm.yaml"),
        "version: 1\nrules:\n  - id: llm-added\n    description: Added\n    category: secret\n    severity: high\n    pattern: 'LLM-SECRET-[0-9]+'\n    placeholder: LLM_SECRET\n",
    )
    .unwrap();
    let direct = load_config(None, &[], Some(project.path())).unwrap();
    eprintln!(
        "project={} root={} direct={}",
        project.path().display(),
        direct.root.display(),
        direct.rules.len()
    );
    let (status, body) = call(&server, "/rules/reload", Some(json!({})), None);
    assert_eq!(status, 200);
    assert_eq!(body["reloaded"], true);
    let (status, body) = call(
        &server,
        "/redact",
        Some(json!({"text": "LLM-SECRET-42"})),
        None,
    );
    assert_eq!(status, 200);
    assert!(body["text"]
        .as_str()
        .unwrap()
        .contains("[REDACTED:LLM_SECRET:1]"));
}

#[test]
fn no_store_keeps_mapping_in_memory_only() {
    let project = tempfile::tempdir().unwrap();
    let server = TestServer::start(project.path(), None, true);
    let (status, body) = call(
        &server,
        "/redact",
        Some(json!({"text": "PASSWORD=real-pass-42"})),
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(body["mapping_stored"], false);
    let (status, restored) = call(
        &server,
        "/restore",
        Some(json!({"text": body["text"]})),
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(restored["restored"], 1);
}

#[test]
fn session_mappings_are_isolated() {
    let project = tempfile::tempdir().unwrap();
    let server = TestServer::start(project.path(), None, false);
    let (status, body) = call(
        &server,
        "/redact",
        Some(json!({"text": "PASSWORD=real-pass-42", "session": "session-a"})),
        None,
    );
    assert_eq!(status, 200);
    let redacted = body["text"].as_str().unwrap().to_string();
    assert!(redacted.contains("[REDACTED:"));

    let (status, other) = call(
        &server,
        "/restore",
        Some(json!({"text": redacted, "session": "session-b"})),
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(other["restored"], 0);
    assert!(!other["unresolved"].as_array().unwrap().is_empty());

    let (status, same) = call(
        &server,
        "/restore",
        Some(json!({"text": redacted, "session": "session-a"})),
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(same["text"], "PASSWORD=real-pass-42");
    assert_eq!(same["restored"], 1);
}
