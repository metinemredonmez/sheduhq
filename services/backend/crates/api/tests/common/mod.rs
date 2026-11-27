//! Entegrasyon testleri için ortak yardımcılar.
#![allow(dead_code)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::connect_info::MockConnectInfo,
    http::{Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use shedu_api::{AppState, auth::totp, db, push::RecordingPush, sms::RecordingSms};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use tower::ServiceExt;

pub const PHONE: &str = "+905551112233";
pub const PASSWORD: &str = "mavi bisiklet dag yolunda";
pub const NEW_PASSWORD: &str = "sari tramvay sahil boyunca";

pub struct TestApp {
    pub router: Router,
    pub state: AppState,
    pub sms: RecordingSms,
    pub push: RecordingPush,
    /// Uygulama rolüyle (RLS uygulanır).
    pub pool: PgPool,
    /// Süper kullanıcıyla; yalnızca test kurulumu ve doğrulamaları için.
    pub admin: PgPool,
}

pub async fn app(connect: PgConnectOptions) -> TestApp {
    app_with(connect, Duration::from_millis(50)).await
}

/// `simulator_delay`: sanal panelde komutun tamamlanma gecikmesi.
pub async fn app_with(connect: PgConnectOptions, simulator_delay: Duration) -> TestApp {
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(connect.clone())
        .await
        .expect("yönetici bağlantısı");
    let pool = db::pool_options(Some("shedu_app".into()))
        .max_connections(8)
        .connect_with(connect)
        .await
        .expect("bağlantı");
    let sms = RecordingSms::default();
    let mut state = AppState::new(
        pool.clone(),
        b"test-jwt-secret-0123456789abcdefghij",
        b"test-hmac-secret-0123456789abcdefgh",
        (b"test-data-key-0123456789abcdefghijkl", 1),
        Arc::new(sms.clone()),
    )
    .expect("durum");
    state.simulator_delay = simulator_delay;
    let push = RecordingPush::default();
    state.push = Arc::new(push.clone());
    let router = shedu_api::router(state.clone())
        .layer(MockConnectInfo(SocketAddr::from(([203, 0, 113, 7], 4000))));
    TestApp {
        router,
        state,
        sms,
        push,
        pool,
        admin,
    }
}

impl TestApp {
    /// Olay dinleyicisini ve push dağıtıcısını başlatır.
    pub async fn start_background(&self) {
        self.state.start_event_listener();
        self.state.start_push_dispatcher();
        // Dinleyicinin LISTEN komutunu vermesi için kısa bir süre.
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    pub async fn delete(&self, path: &str, bearer: &str) -> (StatusCode, Value) {
        self.call(Method::DELETE, path, None, Some(bearer)).await
    }

    pub async fn patch(&self, path: &str, body: Value, bearer: &str) -> (StatusCode, Value) {
        self.call(Method::PATCH, path, Some(body), Some(bearer))
            .await
    }

    pub async fn put(&self, path: &str, body: Value, bearer: &str) -> (StatusCode, Value) {
        self.call(Method::PUT, path, Some(body), Some(bearer)).await
    }

    pub async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        bearer: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(token) = bearer {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = match body {
            Some(json) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json.to_string())),
            None => request.body(Body::empty()),
        }
        .expect("istek");
        let response = self.router.clone().oneshot(request).await.expect("yanıt");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("gövde")
            .to_bytes();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    pub async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        self.call(Method::POST, path, Some(body), None).await
    }

    pub async fn get(&self, path: &str, bearer: &str) -> (StatusCode, Value) {
        self.call(Method::GET, path, None, Some(bearer)).await
    }

    pub async fn post_auth(&self, path: &str, body: Value, bearer: &str) -> (StatusCode, Value) {
        self.call(Method::POST, path, Some(body), Some(bearer))
            .await
    }

    /// Arka planda gönderilen son SMS kodunu bekler. Kod taşımayan mesajlar (ör. arka planda geç
    /// ulaşan davet SMS'i) atlanır.
    /// Yüklü makinede (CI) arka plan görevi gecikebilir; en fazla 5 saniye beklenir.
    pub async fn last_code(&self, phone: &str, previous: usize) -> String {
        for _ in 0..500 {
            let messages = self.sms.messages_to(phone);
            let code = messages
                .iter()
                .skip(previous)
                .rev()
                .map(|text| {
                    text.chars()
                        .filter(char::is_ascii_digit)
                        .take(6)
                        .collect::<String>()
                })
                .find(|code| code.len() == 6);
            if let Some(code) = code {
                return code;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("SMS gelmedi");
    }

    pub async fn register(&self, phone: &str) -> Value {
        let before = self.sms.messages_to(phone).len();
        let (status, _) = self
            .post("/v1/auth/register/start", json!({ "phone": phone }))
            .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let code = self.last_code(phone, before).await;
        let (status, body) = self
            .post(
                "/v1/auth/register/complete",
                json!({
                    "phone": phone, "code": code, "display_name": "Ayşe",
                    "password": PASSWORD, "device": { "platform": "ios", "name": "iPhone" }
                }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body
    }

    pub async fn login(&self, identifier: &str, password: &str) -> (StatusCode, Value) {
        self.post(
            "/v1/auth/login",
            json!({ "identifier": identifier, "password": password, "device": { "platform": "android" } }),
        )
        .await
    }

    /// Kayıt olur; (access token, kullanıcı kimliği, ev organizasyonu kimliği) döner.
    pub async fn user(&self, phone: &str) -> (String, String, String) {
        let tokens = self.register(phone).await;
        let access = s(&tokens, "access_token");
        let (_, me) = self.get("/v1/me", &access).await;
        (
            access,
            s(&me, "id"),
            me["organizations"][0]["id"]
                .as_str()
                .expect("org")
                .to_owned(),
        )
    }
}

/// Şu anki adıma göre `offset` adım ilerideki TOTP kodu.
pub fn totp_code(secret: &[u8], offset: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    totp::code_at(secret, totp::step_at(now) + offset)
}

impl TestApp {
    /// İkinci faktörü açar (bu oturum doğrulanmış sayılır); TOTP sırrını döner.
    pub async fn enable_mfa(&self, access: &str) -> Vec<u8> {
        let (status, setup) = self
            .post_auth(
                "/v1/auth/mfa/totp/setup",
                json!({ "password": PASSWORD }),
                access,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{setup}");
        let secret = totp::base32_decode(&s(&setup, "secret")).expect("sır");
        let (status, body) = self
            .post_auth(
                "/v1/auth/mfa/totp/confirm",
                json!({ "code": totp_code(&secret, 0) }),
                access,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        secret
    }
}

pub fn s(value: &Value, key: &str) -> String {
    value[key].as_str().expect(key).to_owned()
}
