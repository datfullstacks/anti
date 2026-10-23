use axum::{Router, middleware};
use sqlx::PgPool;
use std::sync::Arc;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod db;
mod error;
mod middleware as mw;
mod models;
mod routes;
mod stripe;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub jwt_secret: String,
    pub stripe_secret: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "anti_server=debug,tower_http=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL required");
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET required");
    let stripe_secret = std::env::var("STRIPE_SECRET_KEY").unwrap_or_default();

    let db = db::connect(&database_url).await?;
    db::migrate(&db).await?;

    let state = Arc::new(AppState { db, jwt_secret, stripe_secret });

    let app = Router::new()
        .merge(routes::public::router())
        .merge(routes::auth::router())
        .nest("/api/v1", routes::protected::router(state.clone()))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{port}");
    tracing::info!("listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
