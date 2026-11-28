//! Firebase Cloud Messaging (FCM HTTP v1) bağdaştırıcısı (Android).
//!
//! - **Kimlik doğrulama:** Google hizmet hesabı. Hesabın anahtarıyla RS256 imzalı bir onay
//!   (JWT) Google'ın token adresine gönderilir ve yalnızca `firebase.messaging` kapsamlı erişim
//!   token'ı alınır. Token süresi dolmadan 5 dakika önce yenilenir; aynı anda tek yenileme yapılır.
//!   Google token'ı reddederse (401) bir sonraki denemede yenisi alınır.
//! - **Adresler sabittir:** token adresi `oauth2.googleapis.com`, gönderim `fcm.googleapis.com`.
//!   Hizmet hesabı dosyasındaki `token_uri` başka bir adres gösterirse açılış reddedilir: imzalı
//!   onay başka yere gönderilmez (EXT-01).
//! - **Tekilleştirme:** `collapse_key` ve bildirim `tag`'i olay başına sabittir (BUS-02).
//! - **Süre:** `ttl` olayın alınmasından en fazla bir saat sonrasına kadardır.
//! - **Kanallar:** Android'de bildirim kanalı uygulamada tanımlanır: `alarm` (sessiz modu aşan
//!   alarm kanalı), `warning`, `info`.

use std::{
    fmt,
    time::{Duration, Instant},
};

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use ring::{
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RsaKeyPair},
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;

use super::{
    ProviderError, apns::message_data, http_client, jwt_signing_input, jwt_with_signature,
    pkcs8_from_pem, read_body, unix_now,
};
use crate::{
    config::FcmSettings,
    push::{PushError, PushMessage, PushPriority},
};

const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const SEND_BASE_URL: &str = "https://fcm.googleapis.com";
const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
/// Erişim token'ı süresi dolmadan bu kadar önce yenilenir.
const RENEW_BEFORE: Duration = Duration::from_secs(5 * 60);

/// Hizmet hesabı dosyasının kullanılan alanları.
#[derive(Deserialize)]
struct ServiceAccount {
    #[serde(rename = "type")]
    kind: String,
    project_id: String,
    private_key_id: Option<String>,
    private_key: String,
    client_email: String,
    token_uri: Option<String>,
}

enum Signer {
    Rsa(Box<RsaKeyPair>, SystemRandom),
    /// Birim testleri: RSA anahtarı üretmek yerine sabit imza.
    #[cfg(test)]
    Fake,
}

impl Signer {
    fn sign(&self, input: &[u8]) -> Option<Vec<u8>> {
        match self {
            Self::Rsa(key, rng) => {
                let mut signature = vec![0; key.public().modulus_len()];
                key.sign(&RSA_PKCS1_SHA256, rng, input, &mut signature)
                    .ok()?;
                Some(signature)
            }
            #[cfg(test)]
            Self::Fake => Some(b"imza".to_vec()),
        }
    }
}

pub struct Fcm {
    http: reqwest::Client,
    token_url: String,
    send_url: String,
    client_email: String,
    private_key_id: Option<String>,
    signer: Signer,
    /// Önbellekteki erişim token'ı ve geçerlilik sonu. Kilit yenileme boyunca tutulur: aynı anda
    /// tek yenileme yapılır.
    access: Mutex<Option<(String, Instant)>>,
}

impl fmt::Debug for Fcm {
    // Anahtar ve erişim token'ı hiçbir zaman log'a düşmez (LOG-02).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fcm")
            .field("send_url", &self.send_url)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Sent,
    InvalidToken,
    /// Erişim token'ı reddedildi: yenisi alınır ve yeniden denenir.
    RenewAccessToken,
    Retry,
    Reject,
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: Option<ErrorBody>,
}

#[derive(Deserialize)]
struct ErrorBody {
    status: Option<String>,
    #[serde(default)]
    details: Vec<ErrorDetail>,
}

#[derive(Deserialize)]
struct ErrorDetail {
    #[serde(rename = "errorCode")]
    error_code: Option<String>,
}

#[derive(Deserialize)]
struct AccessToken {
    access_token: String,
    expires_in: u64,
}

fn classify(status: u16, code: Option<&str>) -> Outcome {
    match (status, code) {
        (200, _) => Outcome::Sent,
        (404, _) | (_, Some("UNREGISTERED" | "SENDER_ID_MISMATCH")) => Outcome::InvalidToken,
        (401, _) => Outcome::RenewAccessToken,
        (429, _) | (500..=599, _) => Outcome::Retry,
        // INVALID_ARGUMENT bozuk yük de olabilir: token silinmez, yeniden de denenmez.
        _ => Outcome::Reject,
    }
}

/// FCM kayıt token'ı: harf, rakam ve `:_-.` karakterleri.
fn valid_device_token(token: &str) -> bool {
    (20..=4096).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'-' | b'.'))
}

fn valid_project_id(id: &str) -> bool {
    (4..=40).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl Fcm {
    /// Açılışta hizmet hesabı dosyasını okur ve doğrular.
    pub fn new(settings: &FcmSettings) -> Result<Self, ProviderError> {
        let json = std::fs::read_to_string(&settings.service_account_file)
            .map_err(|_| ProviderError::Key("SHEDU_FCM_SERVICE_ACCOUNT_FILE"))?;
        let account = parse_account(&json)?;
        let der = pkcs8_from_pem(&account.private_key)
            .ok_or(ProviderError::Key("SHEDU_FCM_SERVICE_ACCOUNT_FILE"))?;
        let key = RsaKeyPair::from_pkcs8(&der)
            .map_err(|_| ProviderError::Key("SHEDU_FCM_SERVICE_ACCOUNT_FILE"))?;
        Self::build(
            account,
            Signer::Rsa(Box::new(key), SystemRandom::new()),
            TOKEN_URL,
            SEND_BASE_URL,
            true,
        )
    }

    fn build(
        account: ServiceAccount,
        signer: Signer,
        token_url: &str,
        send_base_url: &str,
        https_only: bool,
    ) -> Result<Self, ProviderError> {
        Ok(Self {
            http: http_client(https_only)?,
            token_url: token_url.to_owned(),
            send_url: format!(
                "{send_base_url}/v1/projects/{}/messages:send",
                account.project_id
            ),
            client_email: account.client_email,
            private_key_id: account.private_key_id,
            signer,
            access: Mutex::new(None),
        })
    }

    /// Geçerli erişim token'ını verir; yoksa veya süresi dolmak üzereyse Google'dan yenisini alır.
    async fn access_token(&self) -> Option<String> {
        let mut cached = self.access.lock().await;
        if let Some((token, valid_until)) = cached.as_ref()
            && Instant::now() < *valid_until
        {
            return Some(token.clone());
        }
        let now = unix_now();
        let mut header = json!({ "alg": "RS256", "typ": "JWT" });
        if let Some(kid) = &self.private_key_id {
            header["kid"] = json!(kid);
        }
        let input = jwt_signing_input(
            &header,
            &json!({
                "iss": self.client_email,
                "scope": SCOPE,
                "aud": TOKEN_URL,
                "iat": now,
                "exp": now + 3600,
            }),
        );
        let assertion = jwt_with_signature(&input, &self.signer.sign(input.as_bytes())?);
        let sent = self
            .http
            .post(&self.token_url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={assertion}"
            ))
            .send()
            .await;
        let response = match sent {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(
                    timeout = error.is_timeout(),
                    connect = error.is_connect(),
                    "Google token adresine ulaşılamadı"
                );
                return None;
            }
        };
        let status = response.status().as_u16();
        let body = read_body(response).await?;
        let Some(token) = serde_json::from_slice::<AccessToken>(&body)
            .ok()
            .filter(|_| status == 200)
            .filter(|token| !token.access_token.is_empty())
        else {
            tracing::error!(status, "FCM erişim token'ı alınamadı");
            return None;
        };
        let lifetime = Duration::from_secs(token.expires_in)
            .saturating_sub(RENEW_BEFORE)
            .max(Duration::from_secs(60));
        *cached = Some((token.access_token.clone(), Instant::now() + lifetime));
        Some(token.access_token)
    }

    async fn forget_access_token(&self) {
        *self.access.lock().await = None;
    }

    fn payload(message: &PushMessage) -> serde_json::Value {
        let (priority, channel, notification_priority) = match message.priority {
            PushPriority::Critical => ("HIGH", "alarm", "PRIORITY_MAX"),
            PushPriority::Warning => ("HIGH", "warning", "PRIORITY_HIGH"),
            PushPriority::Info => ("NORMAL", "info", "PRIORITY_DEFAULT"),
        };
        let ttl = message.expires_at.saturating_sub(unix_now());
        json!({
            "message": {
                "token": message.token,
                "notification": { "title": message.title, "body": message.body },
                "data": message_data(message),
                "android": {
                    "priority": priority,
                    "ttl": format!("{ttl}s"),
                    "collapse_key": message.collapse_key,
                    "notification": {
                        "channel_id": channel,
                        "tag": message.collapse_key,
                        "notification_priority": notification_priority,
                        "default_sound": true,
                    },
                },
            }
        })
    }

    pub(crate) async fn send(&self, message: &PushMessage) -> Result<(), PushError> {
        if !valid_device_token(&message.token) {
            return Err(PushError::InvalidToken);
        }
        let Some(access_token) = self.access_token().await else {
            return Err(PushError::Transient);
        };
        let mut authorization = HeaderValue::from_str(&format!("Bearer {access_token}"))
            .map_err(|_| PushError::Transient)?;
        authorization.set_sensitive(true);
        let sent = self
            .http
            .post(&self.send_url)
            .header(AUTHORIZATION, authorization)
            .header(CONTENT_TYPE, "application/json")
            .body(Self::payload(message).to_string())
            .send()
            .await;
        let response = match sent {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(
                    timeout = error.is_timeout(),
                    connect = error.is_connect(),
                    "FCM'e ulaşılamadı"
                );
                return Err(PushError::Transient);
            }
        };
        let status = response.status().as_u16();
        let body = read_body(response).await.unwrap_or_default();
        let error = serde_json::from_slice::<ErrorEnvelope>(&body)
            .ok()
            .and_then(|envelope| envelope.error);
        let code = error.as_ref().and_then(|error| {
            error
                .details
                .iter()
                .find_map(|detail| detail.error_code.clone())
                .or_else(|| error.status.clone())
        });
        match classify(status, code.as_deref()) {
            Outcome::Sent => Ok(()),
            Outcome::InvalidToken => Err(PushError::InvalidToken),
            Outcome::RenewAccessToken => {
                self.forget_access_token().await;
                tracing::error!(status, code, "FCM erişim token'ını reddetti");
                Err(PushError::Transient)
            }
            Outcome::Retry => {
                tracing::warn!(status, code, "FCM geçici hata verdi");
                Err(PushError::Transient)
            }
            Outcome::Reject => {
                tracing::error!(status, code, "FCM bildirimi reddetti");
                Err(PushError::Rejected)
            }
        }
    }
}

fn parse_account(json: &str) -> Result<ServiceAccount, ProviderError> {
    let invalid = ProviderError::Key("SHEDU_FCM_SERVICE_ACCOUNT_FILE");
    let account: ServiceAccount = serde_json::from_str(json).map_err(|_| invalid.clone())?;
    let email_ok = account.client_email.contains('@')
        && account.client_email.len() <= 320
        && !account.client_email.chars().any(char::is_whitespace);
    let token_uri_ok = account
        .token_uri
        .as_deref()
        .is_none_or(|uri| uri == TOKEN_URL);
    if account.kind != "service_account"
        || !valid_project_id(&account.project_id)
        || !email_ok
        || !token_uri_ok
    {
        return Err(invalid);
    }
    Ok(account)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use axum::http::StatusCode;
    use uuid::Uuid;

    use super::*;
    use crate::providers::testing::{requests, serve};

    const DEVICE: &str = "cihaz:deneme_deneme_deneme";

    fn account() -> ServiceAccount {
        parse_account(
            &json!({
                "type": "service_account",
                "project_id": "shedu-test",
                "private_key_id": "k1",
                "private_key": crate::providers::testing::pem("AAEC"),
                "client_email": "push@shedu-test.iam.gserviceaccount.com",
                "token_uri": TOKEN_URL,
            })
            .to_string(),
        )
        .expect("hesap")
    }

    fn message(priority: PushPriority) -> PushMessage {
        PushMessage {
            token: DEVICE.into(),
            platform: "android".into(),
            user_id: Uuid::new_v4(),
            priority,
            title: "Shedu".into(),
            body: "Yangın alarmı".into(),
            organization_id: Uuid::new_v4(),
            panel_id: Uuid::new_v4(),
            event_id: 7,
            kind: "alarm".into(),
            collapse_key: "shedu-event-7".into(),
            expires_at: unix_now() + 1800,
        }
    }

    #[test]
    fn responses_are_classified() {
        assert_eq!(classify(200, None), Outcome::Sent);
        assert_eq!(classify(404, Some("UNREGISTERED")), Outcome::InvalidToken);
        assert_eq!(
            classify(403, Some("SENDER_ID_MISMATCH")),
            Outcome::InvalidToken
        );
        assert_eq!(
            classify(401, Some("UNAUTHENTICATED")),
            Outcome::RenewAccessToken
        );
        assert_eq!(classify(429, Some("QUOTA_EXCEEDED")), Outcome::Retry);
        assert_eq!(classify(503, Some("UNAVAILABLE")), Outcome::Retry);
        assert_eq!(classify(400, Some("INVALID_ARGUMENT")), Outcome::Reject);
        assert_eq!(classify(403, Some("PERMISSION_DENIED")), Outcome::Reject);
    }

    #[test]
    fn service_account_file_is_validated() {
        let base = json!({
            "type": "service_account",
            "project_id": "shedu-test",
            "private_key": "x",
            "client_email": "push@shedu-test.iam.gserviceaccount.com",
        });
        assert!(parse_account(&base.to_string()).is_ok());
        let with = |key: &str, value: serde_json::Value| {
            let mut changed = base.clone();
            changed[key] = value;
            parse_account(&changed.to_string()).is_err()
        };
        // İmzalı onay yalnızca Google'ın token adresine gider.
        assert!(with("token_uri", json!("https://evil.example/token")));
        assert!(with("type", json!("authorized_user")));
        assert!(with("project_id", json!("../../x")));
        assert!(with("client_email", json!("yok")));
        assert!(parse_account("{}").is_err());

        // RSA olmayan veya bozuk anahtar açılışta reddedilir.
        let dir = std::env::temp_dir().join(format!("shedu-fcm-{}.json", Uuid::new_v4()));
        std::fs::write(&dir, base.to_string()).expect("dosya");
        let result = Fcm::new(&FcmSettings {
            service_account_file: dir.clone(),
        });
        let _ = std::fs::remove_file(&dir);
        assert_eq!(
            result.err(),
            Some(ProviderError::Key("SHEDU_FCM_SERVICE_ACCOUNT_FILE"))
        );
    }

    #[tokio::test]
    async fn token_is_fetched_once_and_message_sent() {
        let token_calls = Arc::new(AtomicUsize::new(0));
        let calls = token_calls.clone();
        let (url, seen) = serve(move |request| {
            if request.path == "/token" {
                calls.fetch_add(1, Ordering::SeqCst);
                (
                    StatusCode::OK,
                    r#"{"access_token":"erisim-1","expires_in":3599,"token_type":"Bearer"}"#
                        .to_owned(),
                )
            } else {
                (
                    StatusCode::OK,
                    r#"{"name":"projects/x/messages/1"}"#.to_owned(),
                )
            }
        })
        .await;
        let fcm = Fcm::build(
            account(),
            Signer::Fake,
            &format!("{url}/token"),
            &url,
            false,
        )
        .expect("fcm");
        assert_eq!(fcm.send(&message(PushPriority::Critical)).await, Ok(()));
        assert_eq!(fcm.send(&message(PushPriority::Info)).await, Ok(()));
        assert_eq!(token_calls.load(Ordering::SeqCst), 1, "token önbellekten");

        let all = requests(&seen);
        let token_request = &all[0];
        assert!(token_request.body.starts_with(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="
        ));
        let send = &all[1];
        assert_eq!(send.path, "/v1/projects/shedu-test/messages:send");
        assert_eq!(
            send.headers
                .get("authorization")
                .and_then(|v| v.to_str().ok()),
            Some("Bearer erisim-1")
        );
        let body: serde_json::Value = serde_json::from_str(&send.body).expect("json");
        let android = &body["message"]["android"];
        assert_eq!(android["priority"], "HIGH");
        assert_eq!(android["collapse_key"], "shedu-event-7");
        assert_eq!(android["notification"]["channel_id"], "alarm");
        assert_eq!(android["notification"]["tag"], "shedu-event-7");
        let ttl: u64 = android["ttl"]
            .as_str()
            .and_then(|t| t.trim_end_matches('s').parse().ok())
            .expect("ttl");
        assert!((1700..=1800).contains(&ttl));
        assert_eq!(body["message"]["data"]["event_id"], "7");
        let info: serde_json::Value = serde_json::from_str(&all[2].body).expect("json");
        assert_eq!(info["message"]["android"]["priority"], "NORMAL");
        assert_eq!(
            info["message"]["android"]["notification"]["channel_id"],
            "info"
        );
    }

    #[tokio::test]
    async fn errors_map_to_retry_reject_or_invalid_token() {
        let token_calls = Arc::new(AtomicUsize::new(0));
        let calls = token_calls.clone();
        let (url, seen) = serve(move |request| {
            if request.path == "/token" {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                return (
                    StatusCode::OK,
                    format!(r#"{{"access_token":"erisim-{n}","expires_in":3599}}"#),
                );
            }
            let error = |status: StatusCode, code: &str| {
                (
                    status,
                    format!(
                        r#"{{"error":{{"code":{},"status":"X","details":[{{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"{code}"}}]}}}}"#,
                        status.as_u16()
                    ),
                )
            };
            match () {
                () if request.body.contains("shedu-event-1\"") => {
                    error(StatusCode::NOT_FOUND, "UNREGISTERED")
                }
                () if request.body.contains("shedu-event-2\"") => {
                    error(StatusCode::UNAUTHORIZED, "THIRD_PARTY_AUTH_ERROR")
                }
                () if request.body.contains("shedu-event-3\"") => {
                    error(StatusCode::SERVICE_UNAVAILABLE, "UNAVAILABLE")
                }
                () => error(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT"),
            }
        })
        .await;
        let fcm = Fcm::build(
            account(),
            Signer::Fake,
            &format!("{url}/token"),
            &url,
            false,
        )
        .expect("fcm");
        let with_key = |n: i64| PushMessage {
            collapse_key: format!("shedu-event-{n}"),
            ..message(PushPriority::Critical)
        };
        assert_eq!(fcm.send(&with_key(1)).await, Err(PushError::InvalidToken));
        assert_eq!(fcm.send(&with_key(2)).await, Err(PushError::Transient));
        // Reddedilen erişim token'ından sonra yenisi alınır.
        assert_eq!(fcm.send(&with_key(3)).await, Err(PushError::Transient));
        assert_eq!(token_calls.load(Ordering::SeqCst), 2);
        assert_eq!(fcm.send(&with_key(4)).await, Err(PushError::Rejected));

        // Biçimi bozuk token gönderilmez.
        let count = requests(&seen).len();
        let bad = PushMessage {
            token: "boşluklu token \"}".into(),
            ..message(PushPriority::Critical)
        };
        assert_eq!(fcm.send(&bad).await, Err(PushError::InvalidToken));
        assert_eq!(requests(&seen).len(), count);
    }

    #[tokio::test]
    async fn failed_token_exchange_is_transient() {
        let (url, _) = serve(|_| {
            (
                StatusCode::BAD_REQUEST,
                r#"{"error":"invalid_grant"}"#.to_owned(),
            )
        })
        .await;
        let fcm = Fcm::build(
            account(),
            Signer::Fake,
            &format!("{url}/token"),
            &url,
            false,
        )
        .expect("fcm");
        assert_eq!(
            fcm.send(&message(PushPriority::Critical)).await,
            Err(PushError::Transient)
        );
        assert!(!format!("{fcm:?}").contains("erisim"));
    }
}
