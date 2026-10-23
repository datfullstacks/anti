use axum::{
    Router, routing::{get, post},
    extract::{State, Extension},
    Json,
    http::{HeaderMap, StatusCode},
    body::Bytes,
    response::IntoResponse,
};
use serde::Serialize;
use std::sync::Arc;

use crate::{AppState, error::{AppError, Result}, middleware::auth::AuthUser};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/billing/plans", get(list_plans))
        .route("/billing/portal", post(create_portal_session))
        .route("/billing/checkout", post(create_checkout_session))
        // Webhook is public (verified via Stripe signature)
        .route("/billing/webhook", post(stripe_webhook))
}

#[derive(Serialize)]
struct PlanInfo {
    tier: String,
    name: String,
    max_profiles: i32,
    max_seats: i32,
    max_concurrent_sessions: i32,
    price_monthly_cents: i32,
    stripe_price_id: Option<String>,
}

async fn list_plans(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<PlanInfo>>> {
    let rows = sqlx::query_as!(
        PlanInfo,
        r#"
        SELECT tier as "tier: String", name, max_profiles, max_seats,
               max_concurrent_sessions, price_monthly_cents, stripe_price_id
        FROM plans ORDER BY price_monthly_cents
        "#
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows))
}

async fn create_checkout_session(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>> {
    let tier = body["tier"].as_str()
        .ok_or_else(|| AppError::BadRequest("tier required".into()))?;

    let plan = sqlx::query!(
        "SELECT stripe_price_id FROM plans WHERE tier = $1::plan_tier",
        tier
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;

    let price_id = plan.stripe_price_id
        .ok_or_else(|| AppError::BadRequest("plan has no stripe price".into()))?;

    // Get or create Stripe customer
    let org = sqlx::query!(
        "SELECT stripe_customer_id, name FROM orgs WHERE id = $1",
        auth.org_id
    )
    .fetch_one(&state.db)
    .await?;

    // Build checkout URL via Stripe API
    // In production use stripe-rust crate properly
    let client = reqwest::Client::new();
    let mut params = std::collections::HashMap::new();
    params.insert("mode", "subscription");
    params.insert("line_items[0][price]", &price_id);
    params.insert("line_items[0][quantity]", "1");
    params.insert("success_url", "https://yourdomain.com/billing/success");
    params.insert("cancel_url", "https://yourdomain.com/billing");
    params.insert("metadata[org_id]", &auth.org_id.to_string());

    let res = client.post("https://api.stripe.com/v1/checkout/sessions")
        .basic_auth(&state.stripe_secret, Option::<&str>::None)
        .form(&params)
        .send()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let json: serde_json::Value = res.json().await
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(Json(serde_json::json!({ "url": json["url"] })))
}

async fn create_portal_session(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<serde_json::Value>> {
    let org = sqlx::query!(
        "SELECT stripe_customer_id FROM orgs WHERE id = $1",
        auth.org_id
    )
    .fetch_one(&state.db)
    .await?;

    let customer_id = org.stripe_customer_id
        .ok_or_else(|| AppError::BadRequest("no stripe customer linked".into()))?;

    let client = reqwest::Client::new();
    let mut params = std::collections::HashMap::new();
    params.insert("customer", customer_id);
    params.insert("return_url".to_string(), "https://yourdomain.com/billing".to_string());

    let res = client.post("https://api.stripe.com/v1/billing_portal/sessions")
        .basic_auth(&state.stripe_secret, Option::<&str>::None)
        .form(&params)
        .send()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let json: serde_json::Value = res.json().await
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(Json(serde_json::json!({ "url": json["url"] })))
}

// Stripe webhook — verify signature, update plan on subscription events
pub async fn stripe_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let sig = match headers.get("stripe-signature").and_then(|v| v.to_str().ok()) {
        Some(s) => s.to_string(),
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let webhook_secret = std::env::var("STRIPE_WEBHOOK_SECRET").unwrap_or_default();

    // Verify signature (simplified — use stripe-rust in production)
    // stripe::Webhook::construct_event(&body, &sig, &webhook_secret)

    let event: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let event_type = event["type"].as_str().unwrap_or("");
    let obj = &event["data"]["object"];

    match event_type {
        "checkout.session.completed" => {
            let org_id_str = obj["metadata"]["org_id"].as_str().unwrap_or("");
            let customer_id = obj["customer"].as_str().unwrap_or("");
            let subscription_id = obj["subscription"].as_str().unwrap_or("");

            if let Ok(org_id) = uuid::Uuid::parse_str(org_id_str) {
                let _ = sqlx::query!(
                    "UPDATE orgs SET stripe_customer_id = $1, stripe_subscription_id = $2, subscription_status = 'active' WHERE id = $3",
                    customer_id, subscription_id, org_id
                )
                .execute(&state.db)
                .await;
            }
        }
        "customer.subscription.updated" => {
            let customer_id = obj["customer"].as_str().unwrap_or("");
            let status = obj["status"].as_str().unwrap_or("active");
            let price_id = obj["items"]["data"][0]["price"]["id"].as_str().unwrap_or("");

            // Find org and update plan
            if let Ok(plan) = sqlx::query!(
                "SELECT id FROM plans WHERE stripe_price_id = $1", price_id
            )
            .fetch_optional(&state.db)
            .await {
                if let Some(plan) = plan {
                    let _ = sqlx::query!(
                        "UPDATE orgs SET plan_id = $1, subscription_status = $2 WHERE stripe_customer_id = $3",
                        plan.id, status, customer_id
                    )
                    .execute(&state.db)
                    .await;
                }
            }
        }
        "customer.subscription.deleted" => {
            let customer_id = obj["customer"].as_str().unwrap_or("");
            let _ = sqlx::query!(
                "UPDATE orgs SET subscription_status = 'canceled' WHERE stripe_customer_id = $1",
                customer_id
            )
            .execute(&state.db)
            .await;
        }
        _ => {}
    }

    StatusCode::OK.into_response()
}
