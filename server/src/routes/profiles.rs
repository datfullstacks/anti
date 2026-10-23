use axum::{
    Router, routing::{get, post, put, delete},
    extract::{State, Path, Extension},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    AppState,
    error::{AppError, Result},
    middleware::{auth::AuthUser, quota::QuotaChecker},
};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/profiles", get(list).post(create))
        .route("/profiles/:id", get(get_one).put(update).delete(delete_one))
        .route("/profiles/:id/launch", post(launch))
        .route("/profiles/:id/sync", post(sync_session))
}

#[derive(Serialize)]
struct ProfileRow {
    id: Uuid,
    name: String,
    proxy_id: Option<Uuid>,
    tags: Vec<String>,
    last_used_at: Option<time::OffsetDateTime>,
    created_at: time::OffsetDateTime,
}

#[derive(Deserialize)]
pub struct CreateProfile {
    pub name: String,
    pub proxy_id: Option<Uuid>,
    pub tags: Option<Vec<String>>,
    pub notes: Option<String>,
    // Fingerprint fields
    pub user_agent: String,
    pub platform: String,
    pub hardware_concurrency: i32,
    pub device_memory: i32,
    pub screen_width: i32,
    pub screen_height: i32,
    pub timezone: String,
    pub language: String,
    pub languages: Vec<String>,
    pub webgl_vendor: String,
    pub webgl_renderer: String,
    pub tcp_ttl: Option<i32>,
    pub tcp_window_size: Option<i32>,
    pub ja3_profile: Option<String>,
    pub http2_profile: Option<String>,
}

#[derive(Deserialize)]
pub struct SyncPayload {
    pub cookies_enc: Option<Vec<u8>>,
    pub local_storage_enc: Option<Vec<u8>>,
    pub binary_version: Option<String>,
}

async fn list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<Vec<ProfileRow>>> {
    let rows = sqlx::query_as!(
        ProfileRow,
        r#"
        SELECT id, name, proxy_id, tags, last_used_at, created_at
        FROM profiles WHERE org_id = $1
        ORDER BY created_at DESC
        "#,
        auth.org_id
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows))
}

async fn get_one(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let row = sqlx::query!(
        r#"
        SELECT p.id, p.name, p.proxy_id, p.tags, p.notes, p.last_used_at,
               p.last_binary_version,
               f.user_agent, f.platform, f.hardware_concurrency, f.device_memory,
               f.screen_width, f.screen_height, f.color_depth, f.pixel_ratio,
               f.timezone, f.language, f.languages,
               f.canvas_noise_seed, f.audio_noise_seed, f.font_noise_seed,
               f.webgl_vendor, f.webgl_renderer,
               f.tcp_ttl, f.tcp_window_size, f.ja3_profile, f.http2_profile,
               pr.protocol as proxy_protocol, pr.host as proxy_host,
               pr.port as proxy_port, pr.username as proxy_user, pr.password as proxy_pass
        FROM profiles p
        JOIN fingerprints f ON f.id = p.fingerprint_id
        LEFT JOIN proxies pr ON pr.id = p.proxy_id
        WHERE p.id = $1 AND p.org_id = $2
        "#,
        id, auth.org_id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;

    Ok(Json(serde_json::json!({
        "id": row.id,
        "name": row.name,
        "tags": row.tags,
        "notes": row.notes,
        "last_used_at": row.last_used_at,
        "last_binary_version": row.last_binary_version,
        "fingerprint": {
            "user_agent": row.user_agent,
            "platform": row.platform,
            "hardware_concurrency": row.hardware_concurrency,
            "device_memory": row.device_memory,
            "screen_width": row.screen_width,
            "screen_height": row.screen_height,
            "color_depth": row.color_depth,
            "pixel_ratio": row.pixel_ratio,
            "timezone": row.timezone,
            "language": row.language,
            "languages": row.languages,
            "canvas_noise_seed": row.canvas_noise_seed,
            "audio_noise_seed": row.audio_noise_seed,
            "font_noise_seed": row.font_noise_seed,
            "webgl_vendor": row.webgl_vendor,
            "webgl_renderer": row.webgl_renderer,
            "tcp_ttl": row.tcp_ttl,
            "tcp_window_size": row.tcp_window_size,
            "ja3_profile": row.ja3_profile,
            "http2_profile": row.http2_profile,
        },
        "proxy": row.proxy_host.map(|h| serde_json::json!({
            "protocol": row.proxy_protocol,
            "host": h,
            "port": row.proxy_port,
            "username": row.proxy_user,
            "password": row.proxy_pass,
        })),
    })))
}

async fn create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<CreateProfile>,
) -> Result<Json<serde_json::Value>> {
    let quota = QuotaChecker::new(&state.db, auth.org_id);
    quota.check_subscription_active().await?;
    quota.check_profile_limit().await?;

    let mut rng = rand::thread_rng();
    use rand::Rng;

    let mut tx = state.db.begin().await?;

    let fp = sqlx::query!(
        r#"
        INSERT INTO fingerprints (
            org_id, user_agent, platform, hardware_concurrency, device_memory,
            screen_width, screen_height, timezone, language, languages,
            canvas_noise_seed, audio_noise_seed, font_noise_seed,
            webgl_vendor, webgl_renderer,
            tcp_ttl, tcp_window_size, ja3_profile, http2_profile
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
        RETURNING id
        "#,
        auth.org_id,
        body.user_agent, body.platform,
        body.hardware_concurrency, body.device_memory,
        body.screen_width, body.screen_height,
        body.timezone, body.language, &body.languages,
        rng.gen::<i64>(), rng.gen::<i64>(), rng.gen::<i64>(),
        body.webgl_vendor, body.webgl_renderer,
        body.tcp_ttl.unwrap_or(64),
        body.tcp_window_size.unwrap_or(65535),
        body.ja3_profile.as_deref().unwrap_or("chrome_120"),
        body.http2_profile.as_deref().unwrap_or("chrome_120"),
    )
    .fetch_one(&mut *tx)
    .await?;

    let profile = sqlx::query!(
        r#"
        INSERT INTO profiles (org_id, created_by, name, fingerprint_id, proxy_id, tags, notes)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, created_at
        "#,
        auth.org_id, auth.user_id, body.name, fp.id,
        body.proxy_id,
        &body.tags.unwrap_or_default(),
        body.notes,
    )
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(serde_json::json!({ "id": profile.id, "created_at": profile.created_at })))
}

async fn update(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>> {
    // Only update mutable fields (name, proxy_id, tags, notes)
    sqlx::query!(
        r#"
        UPDATE profiles SET
            name = COALESCE($1, name),
            proxy_id = COALESCE($2, proxy_id),
            notes = COALESCE($3, notes),
            updated_at = NOW()
        WHERE id = $4 AND org_id = $5
        "#,
        body["name"].as_str(),
        body["proxy_id"].as_str().and_then(|s| Uuid::parse_str(s).ok()),
        body["notes"].as_str(),
        id, auth.org_id
    )
    .execute(&state.db)
    .await?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn delete_one(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let res = sqlx::query!(
        "DELETE FROM profiles WHERE id = $1 AND org_id = $2",
        id, auth.org_id
    )
    .execute(&state.db)
    .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn launch(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let quota = QuotaChecker::new(&state.db, auth.org_id);
    quota.check_subscription_active().await?;
    quota.check_concurrent_sessions().await?;

    // Verify profile belongs to org
    let exists = sqlx::query!("SELECT id FROM profiles WHERE id = $1 AND org_id = $2", id, auth.org_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    let session = sqlx::query!(
        "INSERT INTO sessions (org_id, profile_id, user_id, status) VALUES ($1, $2, $3, 'launching') RETURNING id",
        auth.org_id, id, auth.user_id
    )
    .fetch_one(&state.db)
    .await?;

    // Update last_used
    sqlx::query!("UPDATE profiles SET last_used_at = NOW() WHERE id = $1", id)
        .execute(&state.db)
        .await?;

    Ok(Json(serde_json::json!({ "session_id": session.id })))
}

async fn sync_session(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    Json(body): Json<SyncPayload>,
) -> Result<Json<serde_json::Value>> {
    sqlx::query!(
        r#"
        UPDATE profiles SET
            cookies_enc = COALESCE($1, cookies_enc),
            local_storage_enc = COALESCE($2, local_storage_enc),
            last_binary_version = COALESCE($3, last_binary_version),
            updated_at = NOW()
        WHERE id = $4 AND org_id = $5
        "#,
        body.cookies_enc.as_deref(),
        body.local_storage_enc.as_deref(),
        body.binary_version.as_deref(),
        id, auth.org_id
    )
    .execute(&state.db)
    .await?;

    Ok(Json(serde_json::json!({ "ok": true })))
}
