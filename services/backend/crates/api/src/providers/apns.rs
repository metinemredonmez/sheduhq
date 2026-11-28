//! Apple Push Notification service (APNs) bağdaştırıcısı.
//!
//! - **Kimlik doğrulama:** token tabanlı (`.p8` anahtarıyla ES256 imzalı JWT). Sağlayıcı token'ı 40
//!   dakikada bir yenilenir (Apple en az 20, en çok 60 dakika ister). Apple token'ı reddederse yenisi
//!   ancak eldeki token 20 dakikadan eskiyse üretilir: art arda retler (ör. yanlış anahtar kimliği)
//!   Apple'ın sık yenileme sınırını (`TooManyProviderTokenUpdates`) tetiklemez.
//! - **Token silme:** cihaz token'ı yalnızca Apple "bu cihaz artık kayıtlı değil" dediğinde (410)
//!   silinir. `BadDeviceToken` ve `DeviceTokenNotForTopic` yanlış ortam (`production` / `sandbox`)
//!   veya yanlış konu (paket kimliği) ayarında bütün token'lar için döner; bunlar kalıcı hata
//!   olarak loglanır, token silinmez.
//! - **Bağlantı:** yalnızca HTTP/2 ve TLS; adres sabittir (üretim veya sandbox).
//! - **Tekilleştirme:** `apns-collapse-id` olay başına sabittir; aynı bildirim iki kez giderse
//!   cihazda tek görünür (BUS-02).
//! - **Süre:** `apns-expiration` olayın alınmasından en fazla bir saat sonrasıdır; Apple cihaza o
//!   zamana kadar ulaşamazsa bildirimi atar.
//! - **Kritik uyarı:** sessiz modu aşan "critical alert" Apple'ın ayrı iznini (entitlement) ister.
//!   İzin alınana kadar `SHEDU_APNS_CRITICAL_ALERTS` kapalı tutulur; alarm o zaman
//!   "time-sensitive" gider (odak modunu aşar, sessiz modu aşmaz).
//! - **Cihaz token'ı** onaltılık olmalıdır; değilse istek gönderilmez ve token geçersiz sayılır
//!   (token istek yoluna girer, EXT-01).

use std::{fmt, sync::Mutex};

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
};
use serde::Deserialize;
use serde_json::json;

use super::{
    ProviderError, http_client, jwt_signing_input, jwt_with_signature, pkcs8_from_pem, read_body,
    unix_now,
};
use crate::{
    config::ApnsSettings,
    push::{PushError, PushMessage, PushPriority},
};

const PRODUCTION_URL: &str = "https://api.push.apple.com";
const SANDBOX_URL: &str = "https://api.sandbox.push.apple.com";
/// Sağlayıcı token'ının yenilenme aralığı (saniye).
const PROVIDER_TOKEN_TTL: u64 = 40 * 60;
/// Apple'ın kuralı: sağlayıcı token'ı 20 dakikadan sık yenilenmez.
const MIN_RENEW_INTERVAL: u64 = 20 * 60;

pub struct Apns {
    http: reqwest::Client,
    base_url: String,
    key: EcdsaKeyPair,
    rng: SystemRandom,
    key_id: String,
    team_id: String,
    topic: String,
    critical_alerts: bool,
    /// Önbellekteki sağlayıcı token'ı ve üretildiği an.
    provider_token: Mutex<Option<(String, u64)>>,
}

impl fmt::Debug for Apns {
    // Anahtar ve token hiçbir zaman log'a düşmez (LOG-02).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Apns")
            .field("base_url", &self.base_url)
            .field("topic", &self.topic)
            .field("critical_alerts", &self.critical_alerts)
            .finish_non_exhaustive()
    }
}

/// Sağlayıcının yanıtına göre yapılacak iş.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Sent,
    InvalidToken,
    /// Sağlayıcı token'ı reddedildi: yenisi üretilir ve yeniden denenir.
    RenewProviderToken,
    Retry,
    Reject,
}

#[derive(Deserialize)]
struct ErrorBody {
    reason: Option<String>,
}

fn classify(status: u16, reason: Option<&str>) -> Outcome {
    match (status, reason) {
        (200, _) => Outcome::Sent,
        (410, _) => Outcome::InvalidToken,
        (403, Some("ExpiredProviderToken" | "InvalidProviderToken" | "MissingProviderToken")) => {
            Outcome::RenewProviderToken
        }
        (429, _) | (500..=599, _) => Outcome::Retry,
        _ => Outcome::Reject,
    }
}

/// APNs cihaz token'ı onaltılık bir dizidir (bugün 64 karakter).
pub(crate) fn valid_device_token(token: &str) -> bool {
    (32..=200).contains(&token.len())
        && token.len().is_multiple_of(2)
        && token.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Apns {
    /// Açılışta anahtar dosyasını okur ve doğrular.
    pub fn new(settings: &ApnsSettings) -> Result<Self, ProviderError> {
        let pem = std::fs::read_to_string(&settings.key_file)
            .map_err(|_| ProviderError::Key("SHEDU_APNS_KEY_FILE"))?;
        let base_url = if settings.sandbox {
            SANDBOX_URL
        } else {
            PRODUCTION_URL
        };
        Self::build(&pem, settings, base_url, true)
    }

    fn build(
        pem: &str,
        settings: &ApnsSettings,
        base_url: &str,
        https_only: bool,
    ) -> Result<Self, ProviderError> {
        let rng = SystemRandom::new();
        let der = pkcs8_from_pem(pem).ok_or(ProviderError::Key("SHEDU_APNS_KEY_FILE"))?;
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng)
            .map_err(|_| ProviderError::Key("SHEDU_APNS_KEY_FILE"))?;
        Ok(Self {
            http: http_client(https_only)?,
            base_url: base_url.to_owned(),
            key,
            rng,
            key_id: settings.key_id.clone(),
            team_id: settings.team_id.clone(),
            topic: settings.topic.clone(),
            critical_alerts: settings.critical_alerts,
            provider_token: Mutex::new(None),
        })
    }

    /// Önbellekteki sağlayıcı token'ını verir; yoksa veya süresi geçtiyse yenisini imzalar.
    fn provider_token(&self) -> Option<String> {
        let now = unix_now();
        let mut cached = self.provider_token.lock().ok()?;
        if let Some((token, issued_at)) = cached.as_ref()
            && now.saturating_sub(*issued_at) < PROVIDER_TOKEN_TTL
        {
            return Some(token.clone());
        }
        let input = jwt_signing_input(
            &json!({ "alg": "ES256", "kid": self.key_id }),
            &json!({ "iss": self.team_id, "iat": now }),
        );
        let signature = self.key.sign(&self.rng, input.as_bytes()).ok()?;
        let token = jwt_with_signature(&input, signature.as_ref());
        *cached = Some((token.clone(), now));
        Some(token)
    }

    /// Reddedilen token'ı bırakır; yalnızca 20 dakikadan eskiyse (Apple'ın yenileme sınırı).
    fn forget_provider_token(&self) {
        let now = unix_now();
        if let Ok(mut cached) = self.provider_token.lock()
            && cached
                .as_ref()
                .is_some_and(|(_, issued_at)| now.saturating_sub(*issued_at) >= MIN_RENEW_INTERVAL)
        {
            *cached = None;
        }
    }

    fn payload(&self, message: &PushMessage) -> serde_json::Value {
        let (sound, level) = match message.priority {
            PushPriority::Critical if self.critical_alerts => (
                json!({ "critical": 1, "name": "default", "volume": 1.0 }),
                "critical",
            ),
            PushPriority::Critical | PushPriority::Warning => (json!("default"), "time-sensitive"),
            PushPriority::Info => (json!("default"), "active"),
        };
        json!({
            "aps": {
                "alert": { "title": message.title, "body": message.body },
                "sound": sound,
                "interruption-level": level,
                "thread-id": message.panel_id.to_string(),
            },
            "shedu": message_data(message),
        })
    }

    pub(crate) async fn send(&self, message: &PushMessage) -> Result<(), PushError> {
        if !valid_device_token(&message.token) {
            return Err(PushError::InvalidToken);
        }
        let Some(provider_token) = self.provider_token() else {
            tracing::error!("APNs sağlayıcı token'ı imzalanamadı");
            return Err(PushError::Transient);
        };
        let mut authorization = HeaderValue::from_str(&format!("bearer {provider_token}"))
            .map_err(|_| PushError::Transient)?;
        authorization.set_sensitive(true);
        let priority = match message.priority {
            PushPriority::Critical | PushPriority::Warning => "10",
            PushPriority::Info => "5",
        };
        let sent = self
            .http
            .post(format!("{}/3/device/{}", self.base_url, message.token))
            .header(AUTHORIZATION, authorization)
            .header(CONTENT_TYPE, "application/json")
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", priority)
            .header("apns-expiration", message.expires_at.to_string())
            .header("apns-collapse-id", &message.collapse_key)
            .body(self.payload(message).to_string())
            .send()
            .await;
        let response = match sent {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(
                    timeout = error.is_timeout(),
                    connect = error.is_connect(),
                    "APNs'e ulaşılamadı"
                );
                return Err(PushError::Transient);
            }
        };
        let status = response.status().as_u16();
        let body = read_body(response).await.unwrap_or_default();
        let reason = serde_json::from_slice::<ErrorBody>(&body)
            .ok()
            .and_then(|error| error.reason);
        match classify(status, reason.as_deref()) {
            Outcome::Sent => Ok(()),
            Outcome::InvalidToken => Err(PushError::InvalidToken),
            Outcome::RenewProviderToken => {
                self.forget_provider_token();
                tracing::error!(status, reason, "APNs sağlayıcı token'ını reddetti");
                Err(PushError::Transient)
            }
            Outcome::Retry => {
                tracing::warn!(status, reason, "APNs geçici hata verdi");
                Err(PushError::Transient)
            }
            Outcome::Reject => {
                tracing::error!(status, reason, "APNs bildirimi reddetti");
                Err(PushError::Rejected)
            }
        }
    }
}

/// Bildirimle giden veri: yalnızca uygulamanın ayrıntıyı açması için gereken kimlikler. Kişi
/// kimliği, telefon veya ad gitmez (AI-02 ile aynı veri azaltma ilkesi, DAT-02).
pub(crate) fn message_data(message: &PushMessage) -> serde_json::Value {
    json!({
        "organization_id": message.organization_id.to_string(),
        "panel_id": message.panel_id.to_string(),
        "event_id": message.event_id.to_string(),
        "kind": message.kind,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use axum::http::StatusCode;
    use base64::{
        Engine,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    use ring::signature::{ECDSA_P256_SHA256_FIXED, KeyPair, UnparsedPublicKey};
    use uuid::Uuid;

    use super::*;
    use crate::providers::testing::{pem, requests, serve};

    const TOKEN: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

    /// Her test çalışmasında yeni üretilen P-256 anahtarı (depoda anahtar tutulmaz).
    fn test_key() -> (String, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("anahtar üretilemedi");
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .expect("anahtar okunamadı");
        (
            pem(&STANDARD.encode(pkcs8.as_ref())),
            pair.public_key().as_ref().to_vec(),
        )
    }

    fn settings(critical_alerts: bool) -> ApnsSettings {
        ApnsSettings {
            key_file: PathBuf::new(),
            key_id: "ABC123DEFG".into(),
            team_id: "TEAM123456".into(),
            topic: "app.shedu.ios".into(),
            sandbox: false,
            critical_alerts,
        }
    }

    fn message(priority: PushPriority) -> PushMessage {
        PushMessage {
            token: TOKEN.into(),
            platform: "ios".into(),
            user_id: Uuid::new_v4(),
            priority,
            title: "Shedu".into(),
            body: "Yangın alarmı".into(),
            organization_id: Uuid::new_v4(),
            panel_id: Uuid::new_v4(),
            event_id: 42,
            kind: "alarm".into(),
            collapse_key: "shedu-event-42".into(),
            expires_at: 1_900_000_000,
        }
    }

    #[test]
    fn responses_are_classified() {
        assert_eq!(classify(200, None), Outcome::Sent);
        assert_eq!(classify(410, Some("Unregistered")), Outcome::InvalidToken);
        // Yanlış ortam veya konu ayarında her cihaz için döner: token silinmez.
        assert_eq!(classify(400, Some("BadDeviceToken")), Outcome::Reject);
        assert_eq!(
            classify(400, Some("DeviceTokenNotForTopic")),
            Outcome::Reject
        );
        assert_eq!(
            classify(403, Some("ExpiredProviderToken")),
            Outcome::RenewProviderToken
        );
        assert_eq!(classify(429, Some("TooManyRequests")), Outcome::Retry);
        assert_eq!(classify(503, Some("ServiceUnavailable")), Outcome::Retry);
        // Yük hatası veya yanlış konu token'ı silmez, yeniden de denenmez.
        assert_eq!(classify(400, Some("BadTopic")), Outcome::Reject);
        assert_eq!(classify(413, Some("PayloadTooLarge")), Outcome::Reject);
        assert_eq!(classify(403, Some("TopicDisallowed")), Outcome::Reject);
    }

    #[test]
    fn invalid_or_foreign_keys_are_rejected_at_startup() {
        assert_eq!(
            Apns::build("anahtar değil", &settings(false), "http://x", false).err(),
            Some(ProviderError::Key("SHEDU_APNS_KEY_FILE"))
        );
        let not_ec = pem("AAECAwQ=");
        assert!(Apns::build(&not_ec, &settings(false), "http://x", false).is_err());
    }

    #[tokio::test]
    async fn alarm_is_sent_with_signed_token_and_collapse_id() {
        let (pem, public_key) = test_key();
        let (url, seen) = serve(|_| (StatusCode::OK, String::new())).await;
        let apns = Apns::build(&pem, &settings(false), &url, false).expect("apns");
        let message = message(PushPriority::Critical);
        assert_eq!(apns.send(&message).await, Ok(()));
        assert_eq!(apns.send(&message).await, Ok(()));

        let all = requests(&seen);
        assert_eq!(all.len(), 2);
        let request = &all[0];
        assert_eq!(request.path, format!("/3/device/{TOKEN}"));
        let header = |name: &str| {
            request
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned()
        };
        assert_eq!(header("apns-topic"), "app.shedu.ios");
        assert_eq!(header("apns-push-type"), "alert");
        assert_eq!(header("apns-priority"), "10");
        assert_eq!(header("apns-collapse-id"), "shedu-event-42");
        assert_eq!(header("apns-expiration"), "1900000000");

        // Sağlayıcı token'ı ES256 ile imzalı, doğru anahtar kimliği ve ekiple; önbellekten gelir.
        let bearer = header("authorization");
        let jwt = bearer.strip_prefix("bearer ").expect("bearer");
        assert_eq!(
            all[1]
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok()),
            Some(bearer.as_str())
        );
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let signed = format!("{}.{}", parts[0], parts[1]);
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).expect("imza");
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &public_key)
            .verify(signed.as_bytes(), &signature)
            .expect("imza doğrulanmalı");
        let jwt_header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).expect("başlık"))
                .expect("json");
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).expect("iddia"))
                .expect("json");
        assert_eq!(jwt_header["alg"], "ES256");
        assert_eq!(jwt_header["kid"], "ABC123DEFG");
        assert_eq!(claims["iss"], "TEAM123456");

        // Kritik uyarı izni yokken alarm "time-sensitive"; veri yalnızca kimlikler.
        let body: serde_json::Value = serde_json::from_str(&request.body).expect("json");
        assert_eq!(body["aps"]["interruption-level"], "time-sensitive");
        assert_eq!(body["aps"]["sound"], "default");
        assert_eq!(body["aps"]["alert"]["body"], "Yangın alarmı");
        assert_eq!(body["shedu"]["event_id"], "42");
        assert!(!request.body.contains(&message.user_id.to_string()));
        assert!(!request.body.contains(TOKEN));
    }

    #[tokio::test]
    async fn critical_alert_needs_the_setting() {
        let (pem, _) = test_key();
        let (url, seen) = serve(|_| (StatusCode::OK, String::new())).await;
        let apns = Apns::build(&pem, &settings(true), &url, false).expect("apns");
        assert_eq!(apns.send(&message(PushPriority::Critical)).await, Ok(()));
        assert_eq!(apns.send(&message(PushPriority::Info)).await, Ok(()));
        let all = requests(&seen);
        let critical: serde_json::Value = serde_json::from_str(&all[0].body).expect("json");
        assert_eq!(critical["aps"]["interruption-level"], "critical");
        assert_eq!(critical["aps"]["sound"]["critical"], 1);
        let info: serde_json::Value = serde_json::from_str(&all[1].body).expect("json");
        assert_eq!(info["aps"]["interruption-level"], "active");
        assert_eq!(
            all[1]
                .headers
                .get("apns-priority")
                .and_then(|v| v.to_str().ok()),
            Some("5")
        );
    }

    #[tokio::test]
    async fn errors_map_to_retry_reject_or_invalid_token() {
        let (pem, _) = test_key();
        let (url, seen) = serve(
            |request| match request.body.contains("\"kind\":\"armed\"") {
                true => (StatusCode::GONE, r#"{"reason":"Unregistered"}"#.to_owned()),
                false => (
                    StatusCode::FORBIDDEN,
                    r#"{"reason":"ExpiredProviderToken"}"#.to_owned(),
                ),
            },
        )
        .await;
        let apns = Apns::build(&pem, &settings(false), &url, false).expect("apns");

        // Reddedilen sağlayıcı token'ı: geçici hata. Token 20 dakikadan yeniyse korunur (art arda
        // retler Apple'ın yenileme sınırını tetiklemez); eskiyse sonraki denemede yenisi üretilir.
        let first = apns.provider_token().expect("token");
        assert_eq!(
            apns.send(&message(PushPriority::Critical)).await,
            Err(PushError::Transient)
        );
        assert_eq!(apns.provider_token(), Some(first.clone()));
        if let Ok(mut cached) = apns.provider_token.lock() {
            *cached = Some((first.clone(), unix_now() - MIN_RENEW_INTERVAL));
        }
        assert_eq!(
            apns.send(&message(PushPriority::Critical)).await,
            Err(PushError::Transient)
        );
        assert!(
            apns.provider_token
                .lock()
                .map(|t| t.is_none())
                .unwrap_or(false)
        );

        let unregistered = PushMessage {
            kind: "armed".into(),
            ..message(PushPriority::Info)
        };
        assert_eq!(apns.send(&unregistered).await, Err(PushError::InvalidToken));

        // Biçimi bozuk token (ör. yol karakteri) hiç gönderilmez.
        let count = requests(&seen).len();
        for token in ["../../3/device/x", "abc", &"g".repeat(64)] {
            let bad = PushMessage {
                token: token.to_owned(),
                ..message(PushPriority::Critical)
            };
            assert_eq!(apns.send(&bad).await, Err(PushError::InvalidToken));
        }
        assert_eq!(requests(&seen).len(), count);
    }

    #[test]
    fn debug_output_hides_key_and_token() {
        let (pem, _) = test_key();
        let apns = Apns::build(&pem, &settings(false), "http://x", false).expect("apns");
        let token = apns.provider_token().expect("token");
        let debug = format!("{apns:?}");
        assert!(!debug.contains(&token) && !debug.contains("PRIVATE"));
    }
}
