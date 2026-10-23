use axum::{
    Router, routing::{get, post, delete},
    extract::{State, Path, Extension},
    Json,
};
use bcrypt::hash;
use rand::{Rng, distributions::Alphanumeric};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::sync::Arc;
use uuid::Uuid;

use crate::{AppState, error::{AppError, Result}, middleware::auth::AuthUser};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/users/me", get(me))
        .route("/users/invite", post(invite))
        .route("/users/:id", delete(remove_member))
        .route("/api-keys", get(list_keys).post(create_key))
        .route("/api-keys/:id", delete(revoke_key))
}

#[derive(Serialize)]
struct UserInfo {
    id: Uuid,
    email: String,
    role: String,
    org_id: Uuid,
    org_name: String,
    plan_tier: String,
    subscription_status: String,
}

async fn me(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<UserInfo>> {
    let row = sqlx::query!(
        r#"
        SELECT u.id, u.email, u.role as "role: String",
               o.id as org_id, o.name as org_name,
               o.subscription_status,
               p.tier as "plan_tier: String"
        FROM users u
        JOIN orgs o ON o.id = u.org_id
        JOIN plans p ON p.id = o.plan_id
        WHERE u.id = $1
        "#,
        auth.user_id
    )
    .fetch_one(&state.db)
    .await?;

    Ok(Json(UserInfo {
        id: row.id,
        email: row.email,
        role: row.role,
        org_id: row.org_id,
        org_name: row.org_name,
        plan_tier: row.plan_tier,
        subscription_status: row.subscription_status,
    }))
}

#[derive(Deserialize)]
pub struct InviteRequest {
    pub email: String,
    pub role: String,
}

async fn invite(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<InviteRequest>,
) -> Result<Json<serde_json::Value>> {
    if auth.role == "member" {
        return Err(AppError::Forbidden("only admin or owner can invite".into()));
    }

    let valid_roles = ["admin", "member"];
    if !valid_roles.contains(&body.role.as_str()) {
        return Err(AppError::BadRequest("invalid role".into()));
    }

    // Check seat quota
    let plan_row = sqlx::query!(
        r#"
        SELECT p.max_seats, COUNT(u.id) as current
        FROM orgs o
        JOIN plans p ON p.id = o.plan_id
        LEFT JOIN users u ON u.org_id = o.id AND u.is_active = TRUE
        WHERE o.id = $1
        GROUP BY p.max_seats
        "#,
        auth.org_id
    )
    .fetch_one(&state.db)
    .await?;

    if plan_row.max_seats != -1 && plan_row.current.unwrap_or(0) >= plan_row.max_seats as i64 {
        return Err(AppError::QuotaExceeded("seat limit reached".into()));
    }

    // Generate temp password — in production send invite email instead
    let temp_pass: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    let hash = hash(&temp_pass, bcrypt::DEFAULT_COST)
        .map_err(|e| AppError::Internal(e.into()))?;

    let user = sqlx::query!(
        "INSERT INTO users (org_id, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id",
        auth.org_id, body.email.to_lowercase(), hash, body.role
    )
    .fetch_one(&state.db)
    .await?;

    // TODO: send invite email with temp_pass
    Ok(Json(serde_json::json!({
        "user_id": user.id,
        "temp_password": temp_pass,  // remove when email is wired up
    })))
}

async fn remove_member(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    if auth.role == "member" {
        return Err(AppError::Forbidden("insufficient permissions".into()));
    }
    if id == auth.user_id {
        return Err(AppError::BadRequest("cannot remove yourself".into()));
    }

    sqlx::query!(
        "UPDATE users SET is_active = FALSE WHERE id = $1 AND org_id = $2 AND role != 'owner'",
        id, auth.org_id
    )
    .execute(&state.db)
    .await?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
    pub scopes: Option<Vec<String>>,
    pub expires_days: Option<i64>,
}

async fn list_keys(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<serde_json::Value>> {
    let rows = sqlx::query!(
        r#"
        SELECT id, name, key_prefix, scopes, last_used_at, expires_at, created_at
        FROM api_keys WHERE org_id = $1 ORDER BY created_at DESC
        "#,
        auth.org_id
    )
    .fetch_all(&state.db)
    .await?;

    let keys: Vec<_> = rows.iter().map(|r| serde_json::json!({
        "id": r.id,
        "name": r.name,
        "key_prefix": r.key_prefix,
        "scopes": r.scopes,
        "last_used_at": r.last_used_at,
        "expires_at": r.expires_at,
        "created_at": r.created_at,
    })).collect();

    Ok(Json(serde_json::json!(keys)))
}

async fn create_key(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<CreateKeyRequest>,
) -> Result<Json<serde_json::Value>> {
    let raw_key: String = format!("ak_{}", rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(40)
        .map(char::from)
        .collect::<String>());

    let prefix = &raw_key[..8];
    let hash = format!("{:x}", Sha256::digest(raw_key.as_bytes()));

    let expires_at = body.expires_days.map(|d|
        time::OffsetDateTime::now_utc() + time::Duration::days(d)
    );

    let row = sqlx::query!(
        r#"
        INSERT INTO api_keys (org_id, user_id, name, key_hash, key_prefix, scopes, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
        "#,
        auth.org_id, auth.user_id, body.name, hash, prefix,
        &body.scopes.unwrap_or_default(),
        expires_at
    )
    .fetch_one(&state.db)
    .await?;

    // Return raw key ONCE — never stored
    Ok(Json(serde_json::json!({ "id": row.id, "key": raw_key })))
}

async fn revoke_key(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    sqlx::query!(
        "DELETE FROM api_keys WHERE id = $1 AND org_id = $2",
        id, auth.org_id
    )
    .execute(&state.db)
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
