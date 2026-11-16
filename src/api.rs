//! Local HTTP API for LLM/plugin integrations.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::config::{load_config, Config};
use crate::engine::Engine;
use crate::mapping::MappingStore;
use crate::models::{Mode, VERSION};
use crate::rules::{compile_rule_configs, RuleConfig};

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Mutex<Engine>>,
    pub config: Arc<Mutex<Config>>,
    pub sessions: Arc<Mutex<HashMap<String, Arc<Mutex<Engine>>>>>,
    pub session_dir: Option<PathBuf>,
    pub token: Option<String>,
    pub config_path: Option<PathBuf>,
    pub root: PathBuf,
    pub extra_rule_files: Vec<PathBuf>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/rules", get(rules))
        .route("/redact", post(redact))
        .route("/restore", post(restore))
        .route("/sessions/:session", axum::routing::delete(delete_session))
        .route("/rules/validate", post(validate_rules))
        .route("/rules/reload", post(reload_rules))
        .layer(DefaultBodyLimit::max(20 * 1024 * 1024))
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let rules = state
        .config
        .lock()
        .map(|config| config.rules.len())
        .unwrap_or(0);
    Json(json!({
        "status": "ok",
        "version": VERSION,
        "rules": rules,
    }))
}

async fn rules(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_auth(&headers, &state.token)?;
    let engine = state.engine.lock().map_err(|_| ApiError::internal())?;
    let rules = engine.rule_metadata();
    Ok(Json(json!({"count": rules.len(), "rules": rules})))
}

#[derive(Debug, Deserialize)]
struct RedactRequest {
    text: String,
    #[serde(default)]
    session: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    mode: Option<Mode>,
    #[serde(default)]
    extra_rules: Option<Vec<RuleConfig>>,
}

async fn redact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RedactRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_auth(&headers, &state.token)?;
    let engine_handle = session_engine(&state, request.session.as_deref())?;
    let mut engine = engine_handle.lock().map_err(|_| ApiError::internal())?;
    let result = engine
        .redact(
            &request.text,
            request.path.as_deref(),
            request.mode,
            request.extra_rules,
            true,
        )
        .map_err(ApiError::bad_request)?;
    Ok(Json(json!({
        "text": result.text,
        "mode": result.mode.as_str(),
        "mapping_stored": result.mapping_stored,
        "findings": result.findings.iter().map(|finding| finding.to_json(false)).collect::<Vec<_>>(),
        "summary": result.summary(),
    })))
}

#[derive(Debug, Deserialize)]
struct RestoreRequest {
    text: String,
    #[serde(default)]
    session: Option<String>,
}

async fn restore(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RestoreRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_auth(&headers, &state.token)?;
    let engine_handle = session_engine(&state, request.session.as_deref())?;
    let engine = engine_handle.lock().map_err(|_| ApiError::internal())?;
    let (text, restored, unresolved) = engine.restore(&request.text);
    Ok(Json(json!({
        "text": text,
        "restored": restored,
        "unresolved": unresolved,
    })))
}

async fn delete_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_auth(&headers, &state.token)?;
    let key = session_key(&session);
    let mut removed = state
        .sessions
        .lock()
        .map_err(|_| ApiError::internal())?
        .remove(&key)
        .is_some();
    if let Some(directory) = &state.session_dir {
        let path = directory.join(format!("{key}.json"));
        if path.exists() {
            std::fs::remove_file(&path).map_err(ApiError::bad_request)?;
            removed = true;
        }
    }
    Ok(Json(json!({"deleted": removed})))
}

#[derive(Debug, Deserialize)]
struct ValidateRequest {
    #[serde(default)]
    rules: Option<Vec<RuleConfig>>,
}

async fn validate_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ValidateRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_auth(&headers, &state.token)?;
    let rules = request.rules.unwrap_or_default();
    match compile_rule_configs(rules, "api") {
        Ok(compiled) => {
            let metadata = compiled
                .iter()
                .map(|rule| serde_json::to_value(rule.metadata()).unwrap_or_default())
                .collect::<Vec<_>>();
            Ok(Json(json!({
                "valid": true,
                "errors": [],
                "count": compiled.len(),
                "rules": metadata,
            })))
        }
        Err(error) => Ok(Json(json!({
            "valid": false,
            "errors": [format!("{error:#}")],
            "count": 0,
        }))),
    }
}

async fn reload_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_auth(&headers, &state.token)?;
    let config = load_config(
        state.config_path.as_deref(),
        &state.extra_rule_files,
        Some(&state.root),
    )
    .map_err(ApiError::bad_request)?;
    let count = config.rules.len();
    *state.config.lock().map_err(|_| ApiError::internal())? = config.clone();
    let mut engine = state.engine.lock().map_err(|_| ApiError::internal())?;
    engine.reload(config.clone());
    drop(engine);
    let sessions = state.sessions.lock().map_err(|_| ApiError::internal())?;
    for session in sessions.values() {
        if let Ok(mut engine) = session.lock() {
            engine.reload(config.clone());
        }
    }
    Ok(Json(json!({"reloaded": true, "count": count})))
}

fn session_key(session: &str) -> String {
    hex::encode(Sha256::digest(session.as_bytes()))
}

fn session_engine(state: &AppState, session: Option<&str>) -> Result<Arc<Mutex<Engine>>, ApiError> {
    let Some(session) = session else {
        return Ok(state.engine.clone());
    };
    let key = session_key(session);
    let mut sessions = state.sessions.lock().map_err(|_| ApiError::internal())?;
    if let Some(engine) = sessions.get(&key) {
        return Ok(engine.clone());
    }
    let config = state
        .config
        .lock()
        .map_err(|_| ApiError::internal())?
        .clone();
    let mapping_path = state
        .session_dir
        .as_ref()
        .map(|directory| directory.join(format!("{key}.json")));
    let mapping = MappingStore::new(mapping_path).map_err(ApiError::bad_request)?;
    let engine = Arc::new(Mutex::new(Engine::new(config, mapping, None)));
    sessions.insert(key, engine.clone());
    Ok(engine)
}

fn check_auth(headers: &HeaderMap, token: &Option<String>) -> Result<(), ApiError> {
    let Some(token) = token else {
        return Ok(());
    };
    if token.is_empty() {
        return Ok(());
    }
    let mut supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .unwrap_or("")
        .trim();
    if supplied.is_empty() {
        supplied = headers
            .get("x-rredact-token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .trim();
    }
    if supplied == token {
        Ok(())
    } else {
        Err(ApiError {
            status: StatusCode::UNAUTHORIZED,
            message: "unauthorized".into(),
        })
    }
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal error".into(),
        }
    }

    fn bad_request(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: format!("{error:#}"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": self.message}))).into_response()
    }
}
