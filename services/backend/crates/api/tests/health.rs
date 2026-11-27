use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use std::sync::Arc;

use http_body_util::BodyExt;
use shedu_api::{AppState, sms::RecordingSms};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

/// Veritabanına hiç bağlanmayan durum: sağlık kontrolü veritabanı gerektirmez.
fn state() -> AppState {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://localhost/kullanilmiyor")
        .expect("tembel havuz");
    AppState::new(
        pool,
        b"test-jwt-secret-0123456789abcdefghij",
        b"test-hmac-secret-0123456789abcdefgh",
        (b"test-data-key-0123456789abcdefghijkl", 1),
        Arc::new(RecordingSms::default()),
    )
    .expect("durum")
}

async fn get(path: &str) -> axum::response::Response {
    shedu_api::router(state())
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("istek kurulmalı"),
        )
        .await
        .expect("yanıt dönmeli")
}

#[tokio::test]
async fn health_returns_ok_with_security_headers() {
    let response = get("/health").await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::X_CONTENT_TYPE_OPTIONS],
        "nosniff"
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");

    let body = response
        .into_body()
        .collect()
        .await
        .expect("gövde okunmalı")
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON olmalı");
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn unknown_route_returns_404_and_still_has_security_headers() {
    let response = get("/does-not-exist").await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers()[header::X_CONTENT_TYPE_OPTIONS],
        "nosniff"
    );
}
