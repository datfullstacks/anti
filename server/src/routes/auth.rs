use axum::{Router, routing::post, extract::State, Json};
use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::{AppState, error::{AppError, Result}, middleware::auth::make_jwt};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/auth/register", post(register))
        .route("/api/v1/auth/login", post(login))
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub org_name: String,
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user_id: Uuid,
    pub org_id: Uuid,
}

async fn register(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>> {
    if body.password.len() < 8 {
        return Err(AppError::BadRequest("password must be at least 8 characters".into()));
    }

    let password_hash = hash(&body.password, DEFAULT_COST)
        .map_err(|e| AppError::Internal(e.into()))?;

    let slug = body.org_name.to_lowercase().replace(' ', "-");

    let mut tx = state.db.begin().await?;

    // Check slug unique
    let existing = sqlx::query!("SELECT id FROM orgs WHERE slug = $1", slug)
        .fetch_optional(&mut *tx)
        .await?;
    if existing.is_some() {
        return Err(AppError::Conflict("org slug already taken".into()));
    }

    // Get starter plan
    let plan = sqlx::query!("SELECT id FROM plans WHERE tier = 'starter'")
        .fetch_one(&mut *tx)
        .await?;

    let trial_ends = time::OffsetDateTime::now_utc() + time::Duration::days(7);

    let org = sqlx::query!(
        "INSERT INTO orgs (name, slug, plan_id, trial_ends_at) VALUES ($1, $2, $3, $4) RETURNING id",
        body.org_name, slug, plan.id, trial_ends
    )
    .fetch_one(&mut *tx)
    .await?;

    let user = sqlx::query!(
        "INSERT INTO users (org_id, email, password_hash, role) VALUES ($1, $2, $3, 'owner') RETURNING id",
        org.id, body.email.to_lowercase(), password_hash
    )
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    let token = make_jwt(user.id, org.id, "owner", &state.jwt_secret)
        .map_err(|e| AppError::Internal(e))?;

    Ok(Json(AuthResponse { token, user_id: user.id, org_id: org.id }))
}

async fn login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<AuthResponse>> {
    let user = sqlx::query!(
        "SELECT id, org_id, password_hash, role as \"role: String\", is_active FROM users WHERE email = $1",
        body.email.to_lowercase()
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::Unauthorized)?;

    if !user.is_active {
        return Err(AppError::Forbidden("account disabled".into()));
    }

    let valid = verify(&body.password, &user.password_hash)
        .map_err(|e| AppError::Internal(e.into()))?;
    if !valid {
        return Err(AppError::Unauthorized);
    }

    sqlx::query!("UPDATE users SET last_login_at = NOW() WHERE id = $1", user.id)
        .execute(&state.db)
        .await?;

    let token = make_jwt(user.id, user.org_id, &user.role, &state.jwt_secret)
        .map_err(|e| AppError::Internal(e))?;

    Ok(Json(AuthResponse { token, user_id: user.id, org_id: user.org_id }))
}
