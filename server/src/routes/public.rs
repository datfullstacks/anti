use axum::{Router, routing::get, Json};
use serde_json::{json, Value};
use std::sync::Arc;
use crate::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/binary/latest", get(binary_latest))
}

async fn health() -> Json<Value> {
    Json(json!({ "ok": true }))
}

async fn binary_latest(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Result<Json<Value>, crate::error::AppError> {
    let row = sqlx::query!(
        r#"
        SELECT version, linux_url, linux_sha256, windows_url, windows_sha256, release_notes
        FROM binary_versions WHERE is_latest = TRUE LIMIT 1
        "#
    )
    .fetch_optional(&state.db)
    .await?;

    match row {
        Some(r) => Ok(Json(json!({
            "version": r.version,
            "linux": { "url": r.linux_url, "sha256": r.linux_sha256 },
            "windows": { "url": r.windows_url, "sha256": r.windows_sha256 },
            "release_notes": r.release_notes,
        }))),
        None => Ok(Json(json!({ "version": null }))),
    }
}
