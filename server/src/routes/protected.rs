use axum::{Router, middleware};
use std::sync::Arc;
use crate::{AppState, middleware::auth::jwt_or_apikey};

pub fn router(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .merge(super::profiles::router())
        .merge(super::proxies::router())
        .merge(super::sessions::router())
        .merge(super::users::router())
        .merge(super::billing::router())
        .route_layer(middleware::from_fn_with_state(state, jwt_or_apikey))
}
