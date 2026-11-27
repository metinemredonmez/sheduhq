//! Shedu HTTP API.

pub mod audit;
pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod sms;

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    http::{HeaderValue, header},
    middleware,
    response::Response,
    routing::get,
};
use serde::Serialize;
use sqlx::PgPool;

use crate::{auth::tokens::TokenKeys, sms::SmsSender};

/// JSON gövdeleri için üst sınır; büyük gövdelerle kaynak tüketilmesini önler (RES-01).
const MAX_BODY_BYTES: usize = 16 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub tokens: Arc<TokenKeys>,
    pub hmac_secret: Arc<[u8]>,
    pub sms: Arc<dyn SmsSender>,
    /// Bilinmeyen kullanıcıyla girişte doğrulanan sahte hash; yanıt süresi hesabın varlığını
    /// belli etmez.
    pub dummy_hash: Arc<str>,
}

#[derive(Debug)]
pub struct StateError;

impl AppState {
    pub fn new(
        db: PgPool,
        jwt_secret: &[u8],
        hmac_secret: &[u8],
        sms: Arc<dyn SmsSender>,
    ) -> Result<Self, StateError> {
        let tokens = TokenKeys::new(jwt_secret).map_err(|_| StateError)?;
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|_| StateError)?;
        let dummy_password: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let dummy_hash = auth::password::hash(&dummy_password).map_err(|_| StateError)?;
        Ok(Self {
            db,
            tokens: Arc::new(tokens),
            hmac_secret: Arc::from(hmac_secret),
            sms,
            dummy_hash: Arc::from(dummy_hash),
        })
    }
}

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
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .nest("/v1", auth::routes())
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::map_response(security_headers))
}
