//! Shedu HTTP API.

pub mod admin;
pub mod app_version;
pub mod audit;
pub mod auth;
pub mod authz;
pub mod commands;
pub mod config;
pub mod crypto;
pub mod db;
pub mod devices;
pub mod error;
pub mod events;
pub mod features;
pub mod grants;
pub mod history;
pub mod invitations;
pub mod members;
pub mod notifications;
pub mod panels;
pub mod privacy;
pub mod push;
pub mod simulator;
pub mod sms;

use std::{sync::Arc, time::Duration};

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

use tokio::sync::broadcast;

use crate::{auth::tokens::TokenKeys, events::OrgEvent, push::PushSender, sms::SmsSender};

/// JSON gövdeleri için üst sınır; büyük gövdelerle kaynak tüketilmesini önler (RES-01).
const MAX_BODY_BYTES: usize = 16 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub tokens: Arc<TokenKeys>,
    pub hmac_secret: Arc<[u8]>,
    /// TOTP sırlarını şifreleyen anahtar (KEY-04).
    pub totp_key: Arc<crypto::DataKey>,
    pub sms: Arc<dyn SmsSender>,
    /// Bilinmeyen kullanıcıyla girişte doğrulanan sahte hash; yanıt süresi hesabın varlığını
    /// belli etmez.
    pub dummy_hash: Arc<str>,
    /// Veritabanı bildirimlerinden gelen olayların yayın kanalı (WebSocket istemcilerine).
    pub events: broadcast::Sender<OrgEvent>,
    /// Sanal panelde komutun tamamlanma gecikmesi.
    pub simulator_delay: Duration,
    /// WebSocket için izinli tarayıcı origin'leri. Boşsa Origin başlığı taşıyan her bağlantı
    /// reddedilir (tarayıcı istemcileri BFF üzerinden bağlanır).
    pub allowed_origins: Arc<[String]>,
    /// Push sağlayıcısı. Varsayılan: devre dışı (her gönderim başarısız sayılır).
    pub push: Arc<dyn PushSender>,
    /// Uygulama sürüm politikası önbelleği (varsayılan 60 saniye).
    pub versions: Arc<app_version::VersionCache>,
}

#[derive(Debug)]
pub struct StateError;

impl AppState {
    pub fn new(
        db: PgPool,
        jwt_secret: &[u8],
        hmac_secret: &[u8],
        data_key: (&[u8], i16),
        sms: Arc<dyn SmsSender>,
    ) -> Result<Self, StateError> {
        let tokens = TokenKeys::new(jwt_secret).map_err(|_| StateError)?;
        let totp_key = crypto::DataKey::derive(data_key.0, data_key.1, "totp-secret")
            .map_err(|_| StateError)?;
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|_| StateError)?;
        let dummy_password: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let dummy_hash = auth::password::hash(&dummy_password).map_err(|_| StateError)?;
        Ok(Self {
            db,
            tokens: Arc::new(tokens),
            hmac_secret: Arc::from(hmac_secret),
            totp_key: Arc::new(totp_key),
            sms,
            dummy_hash: Arc::from(dummy_hash),
            events: events::channel(),
            simulator_delay: Duration::from_millis(800),
            allowed_origins: Arc::from(Vec::new()),
            push: Arc::new(push::DisabledPush),
            versions: Arc::new(app_version::VersionCache::new(Duration::from_secs(60))),
        })
    }

    /// Veritabanı olay dinleyicisini başlatır (WebSocket akışı için).
    pub fn start_event_listener(&self) -> tokio::task::JoinHandle<()> {
        events::start_listener(self)
    }

    /// Süresi dolan hesap silme taleplerini saatte bir uygular.
    pub fn start_erasure_job(&self) -> tokio::task::JoinHandle<()> {
        privacy::start_erasure_job(self)
    }

    /// Push dağıtıcısını ve kaçırılan olay taramasını başlatır.
    pub fn start_push_dispatcher(&self) -> tokio::task::JoinHandle<()> {
        push::start_dispatcher(self)
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
        .nest(
            "/v1",
            auth::routes()
                .merge(panels::routes())
                .merge(commands::routes())
                .merge(history::routes())
                .merge(devices::routes())
                .merge(events::routes())
                .merge(members::routes())
                .merge(invitations::routes())
                .merge(grants::routes())
                .merge(privacy::routes())
                .merge(notifications::routes())
                .merge(features::routes())
                // Desteklenmeyen sürümdeki istemci reddedilir; sürüm kontrol ucu bunun dışındadır.
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    app_version::enforce,
                ))
                .merge(app_version::routes()),
        )
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::map_response(security_headers))
}
