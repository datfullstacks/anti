use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use axum_extra::{headers::{Authorization, authorization::Bearer}, TypedHeader};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::sync::Arc;
use uuid::Uuid;

use crate::{AppState, error::{AppError, Result}};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,   // user_id
    pub org: Uuid,   // org_id
    pub role: String,
    pub exp: i64,
}

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub role: String,
}

pub async fn jwt_or_apikey(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> std::result::Result<Response, AppError> {
    let auth_header = req.headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok());

    let auth_user = if let Some(header) = auth_header {
        if let Some(token) = header.strip_prefix("Bearer ") {
            // Try JWT first
            if let Ok(user) = verify_jwt(token, &state.jwt_secret) {
                user
            } else {
                // Try API key
                verify_api_key(token, &state.db).await?
            }
        } else {
            return Err(AppError::Unauthorized);
        }
    } else {
        return Err(AppError::Unauthorized);
    };

    let mut req = req;
    req.extensions_mut().insert(auth_user);
    Ok(next.run(req).await)
}

fn verify_jwt(token: &str, secret: &str) -> std::result::Result<AuthUser, ()> {
    let key = DecodingKey::from_secret(secret.as_bytes());
    let data = decode::<Claims>(token, &key, &Validation::new(Algorithm::HS256))
        .map_err(|_| ())?;
    Ok(AuthUser {
        user_id: data.claims.sub,
        org_id: data.claims.org,
        role: data.claims.role,
    })
}

async fn verify_api_key(key: &str, db: &sqlx::PgPool) -> Result<AuthUser> {
    let hash = format!("{:x}", Sha256::digest(key.as_bytes()));

    let row = sqlx::query!(
        r#"
        SELECT ak.id, ak.org_id, ak.user_id, u.role as "role: String",
               ak.expires_at
        FROM api_keys ak
        JOIN users u ON u.id = ak.user_id
        WHERE ak.key_hash = $1 AND u.is_active = TRUE
        "#,
        hash
    )
    .fetch_optional(db)
    .await?
    .ok_or(AppError::Unauthorized)?;

    if let Some(exp) = row.expires_at {
        if exp < time::OffsetDateTime::now_utc() {
            return Err(AppError::Unauthorized);
        }
    }

    // Update last_used async — don't block the request
    let db = db.clone();
    let key_id = row.id;
    tokio::spawn(async move {
        let _ = sqlx::query!("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1", key_id)
            .execute(&db)
            .await;
    });

    Ok(AuthUser {
        user_id: row.user_id,
        org_id: row.org_id,
        role: row.role,
    })
}

pub fn make_jwt(user_id: Uuid, org_id: Uuid, role: &str, secret: &str) -> anyhow::Result<String> {
    use jsonwebtoken::{encode, EncodingKey, Header};
    let exp = (time::OffsetDateTime::now_utc() + time::Duration::days(30)).unix_timestamp();
    let claims = Claims { sub: user_id, org: org_id, role: role.to_string(), exp };
    Ok(encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))?)
}
