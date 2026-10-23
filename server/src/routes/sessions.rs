use axum::{
    Router, routing::{get, put},
    extract::{State, Path, Extension},
    Json,
};
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::{AppState, error::{AppError, Result}, middleware::auth::AuthUser};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions", get(list))
        .route("/sessions/:id/status", put(update_status))
}

#[derive(Serialize)]
struct SessionRow {
    id: Uuid,
    profile_id: Uuid,
    profile_name: String,
    status: String,
    client_hostname: Option<String>,
    started_at: time::OffsetDateTime,
    ended_at: Option<time::OffsetDateTime>,
    duration_secs: Option<i32>,
}

async fn list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<Vec<SessionRow>>> {
    let rows = sqlx::query_as!(
        SessionRow,
        r#"
        SELECT s.id, s.profile_id, p.name as profile_name,
               s.status as "status: String", s.client_hostname,
               s.started_at, s.ended_at, s.duration_secs
        FROM sessions s
        JOIN profiles p ON p.id = s.profile_id
        WHERE s.org_id = $1
        ORDER BY s.started_at DESC
        LIMIT 200
        "#,
        auth.org_id
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows))
}

async fn update_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>> {
    let status = body["status"].as_str()
        .ok_or_else(|| AppError::BadRequest("status required".into()))?;

    let valid = ["launching", "running", "closed", "crashed"];
    if !valid.contains(&status) {
        return Err(AppError::BadRequest("invalid status".into()));
    }

    let ended_at = if matches!(status, "closed" | "crashed") {
        Some(time::OffsetDateTime::now_utc())
    } else {
        None
    };

    sqlx::query!(
        r#"
        UPDATE sessions SET
            status = $1::session_status,
            ended_at = COALESCE($2, ended_at),
            client_hostname = COALESCE($3, client_hostname)
        WHERE id = $4 AND org_id = $5
        "#,
        status, ended_at,
        body["client_hostname"].as_str(),
        id, auth.org_id
    )
    .execute(&state.db)
    .await?;

    Ok(Json(serde_json::json!({ "ok": true })))
}
