use axum::{
    Router, routing::{get, post, delete},
    extract::{State, Path, Extension},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::{AppState, error::{AppError, Result}, middleware::auth::AuthUser};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/proxies", get(list).post(create))
        .route("/proxies/:id", delete(delete_one))
}

#[derive(Serialize)]
struct ProxyRow {
    id: Uuid,
    name: String,
    protocol: String,
    host: String,
    port: i32,
    username: Option<String>,
    country_code: Option<String>,
    is_active: bool,
}

#[derive(Deserialize)]
pub struct CreateProxy {
    pub name: String,
    pub protocol: String,
    pub host: String,
    pub port: i32,
    pub username: Option<String>,
    pub password: Option<String>,
    pub country_code: Option<String>,
}

async fn list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<Vec<ProxyRow>>> {
    let rows = sqlx::query_as!(
        ProxyRow,
        r#"
        SELECT id, name, protocol as "protocol: String", host, port,
               username, country_code, is_active
        FROM proxies WHERE org_id = $1 ORDER BY name
        "#,
        auth.org_id
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows))
}

async fn create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<CreateProxy>,
) -> Result<Json<serde_json::Value>> {
    let valid_protocols = ["http", "https", "socks5"];
    if !valid_protocols.contains(&body.protocol.as_str()) {
        return Err(AppError::BadRequest("invalid protocol".into()));
    }

    let row = sqlx::query!(
        r#"
        INSERT INTO proxies (org_id, name, protocol, host, port, username, password, country_code)
        VALUES ($1, $2, $3::proxy_protocol, $4, $5, $6, $7, $8)
        RETURNING id
        "#,
        auth.org_id, body.name, body.protocol, body.host, body.port,
        body.username, body.password, body.country_code
    )
    .fetch_one(&state.db)
    .await?;

    Ok(Json(serde_json::json!({ "id": row.id })))
}

async fn delete_one(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let res = sqlx::query!(
        "DELETE FROM proxies WHERE id = $1 AND org_id = $2",
        id, auth.org_id
    )
    .execute(&state.db)
    .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}
