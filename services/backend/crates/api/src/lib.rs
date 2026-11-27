//! Shedu HTTP API.

use axum::{
    Json, Router,
    http::{HeaderValue, header},
    middleware,
    response::Response,
    routing::get,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct Health {
    status: &'static str,
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

/// Her yanıta eklenen temel güvenlik başlıkları.
async fn security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

/// Uygulamanın bütün rotaları.
pub fn router() -> Router {
    Router::new()
        .route("/health", get(health))
        .layer(middleware::map_response(security_headers))
}
