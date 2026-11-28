//! İleti Merkezi SMS bağdaştırıcısı (`POST /v1/send-sms/json`).
//!
//! - **Kimlik:** panelden alınan API anahtarı ve hash istek gövdesinde gider; log'a ve `Debug`
//!   çıktısına yazılmaz (KEY-02, LOG-02).
//! - **Başlık:** gönderici adı panelde onaylı olmalıdır (en çok 11 karakter, Türkçe karakter yok).
//! - **İYS:** bütün Shedu SMS'leri işlem amaçlıdır (doğrulama kodu, davet, güvenlik bildirimi);
//!   ticari ileti değildir, bu yüzden `iys` her zaman `"0"`dır. Pazarlama SMS'i bu bağdaştırıcıyla
//!   gönderilmez.
//! - **Yeniden deneme:** ağ hatası, zaman aşımı ve sağlayıcının 5xx yanıtı en fazla iki kez daha
//!   denenir. Sağlayıcı aynı başlık, alıcı ve metni kısa süre içinde ikinci kez almayı reddeder
//!   (451): ilk deneme kabul edilmiş demektir, gönderildi sayılır. Korumanın süresi belgelenmemiştir;
//!   ilk deneme kabul edilmiş ve koruma bitmişse yeniden deneme mesajı ikinci kez gönderebilir.
//!   "Gönderildi" sağlayıcının kabulüdür, alıcıya teslim değildir. Diğer hatalar (kimlik, bakiye,
//!   onaysız başlık, hatalı numara) denenmez, hata koduyla loglanır; numara log'a yazılmaz.

use std::{fmt, time::Duration};

use reqwest::header::CONTENT_TYPE;
use serde::Deserialize;
use serde_json::json;

use super::{ProviderError, http_client, read_body};
use crate::{
    config::IletiMerkeziSettings,
    sms::{SmsError, SmsFuture, SmsSender},
};

const SEND_URL: &str = "https://api.iletimerkezi.com/v1/send-sms/json";

pub struct IletiMerkezi {
    http: reqwest::Client,
    url: String,
    key: String,
    hash: String,
    sender: String,
    retry_delays: Vec<Duration>,
}

impl fmt::Debug for IletiMerkezi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IletiMerkezi")
            .field("sender", &self.sender)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Sent,
    Retry,
    Fail,
}

#[derive(Deserialize)]
struct Envelope {
    response: Option<Response>,
}

#[derive(Deserialize)]
struct Response {
    status: Option<Status>,
}

#[derive(Deserialize)]
struct Status {
    code: Option<u16>,
}

fn classify(http_status: u16, code: Option<u16>) -> Outcome {
    match code.unwrap_or(http_status) {
        // 451: aynı sipariş kısa süre önce alındı (önceki deneme kabul edilmiş).
        200 | 451 => Outcome::Sent,
        500..=599 => Outcome::Retry,
        _ => Outcome::Fail,
    }
}

impl IletiMerkezi {
    pub fn new(settings: &IletiMerkeziSettings) -> Result<Self, ProviderError> {
        Self::build(
            settings,
            SEND_URL,
            true,
            vec![Duration::from_secs(1), Duration::from_secs(3)],
        )
    }

    fn build(
        settings: &IletiMerkeziSettings,
        url: &str,
        https_only: bool,
        retry_delays: Vec<Duration>,
    ) -> Result<Self, ProviderError> {
        Ok(Self {
            http: http_client(https_only)?,
            url: url.to_owned(),
            key: settings.key.clone(),
            hash: settings.hash.clone(),
            sender: settings.sender.clone(),
            retry_delays,
        })
    }

    async fn attempt(&self, body: &str) -> (Outcome, Option<u16>) {
        let sent = self
            .http
            .post(&self.url)
            .header(CONTENT_TYPE, "application/json")
            .body(body.to_owned())
            .send()
            .await;
        let response = match sent {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(
                    timeout = error.is_timeout(),
                    connect = error.is_connect(),
                    "SMS sağlayıcısına ulaşılamadı"
                );
                return (Outcome::Retry, None);
            }
        };
        let http_status = response.status().as_u16();
        let Some(body) = read_body(response).await else {
            return (Outcome::Retry, None);
        };
        let code = serde_json::from_slice::<Envelope>(&body)
            .ok()
            .and_then(|envelope| envelope.response?.status?.code);
        if code.is_none() && http_status == 200 {
            // Gövde beklenen biçimde değil ama istek kabul edilmiş görünüyor: yeniden denemek mesajı
            // çoğaltabilir, gönderildi sayılır ve iz bırakılır.
            tracing::warn!("SMS sağlayıcısının yanıtı okunamadı; gönderildi sayıldı");
        }
        (classify(http_status, code), code.or(Some(http_status)))
    }

    async fn deliver(&self, to: &str, text: &str) -> Result<(), SmsError> {
        let body = json!({
            "request": {
                "authentication": { "key": self.key, "hash": self.hash },
                "order": {
                    "sender": self.sender,
                    "iys": "0",
                    "message": {
                        "text": text,
                        // Alan adı sağlayıcının belgesindeki yazımla (`receipents`).
                        "receipents": { "number": [to] },
                    },
                },
            }
        })
        .to_string();
        let mut delays = self.retry_delays.iter();
        loop {
            let (outcome, code) = self.attempt(&body).await;
            match outcome {
                Outcome::Sent => {
                    if code == Some(451) {
                        tracing::info!(
                            "SMS sağlayıcısı tekrar eden siparişi bildirdi; ilk deneme kabul edilmiş"
                        );
                    }
                    return Ok(());
                }
                Outcome::Retry => match delays.next() {
                    Some(delay) => tokio::time::sleep(*delay).await,
                    None => {
                        tracing::error!(code, "SMS sağlayıcısı geçici hatada kaldı");
                        return Err(SmsError);
                    }
                },
                Outcome::Fail => {
                    tracing::error!(code, "SMS sağlayıcısı isteği reddetti");
                    return Err(SmsError);
                }
            }
        }
    }
}

impl SmsSender for IletiMerkezi {
    fn send<'a>(&'a self, to: &'a str, text: &'a str) -> SmsFuture<'a> {
        Box::pin(self.deliver(to, text))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use axum::http::StatusCode;

    use super::*;
    use crate::providers::testing::{requests, serve};

    const KEY: &str = "anahtar-0123456789abcdef";
    const HASH: &str = "hash-0123456789abcdef0123456789abcdef";

    fn settings() -> IletiMerkeziSettings {
        IletiMerkeziSettings {
            key: KEY.into(),
            hash: HASH.into(),
            sender: "SHEDU".into(),
        }
    }

    fn sms(url: &str) -> IletiMerkezi {
        IletiMerkezi::build(
            &settings(),
            url,
            false,
            vec![Duration::from_millis(5), Duration::from_millis(5)],
        )
        .expect("sms")
    }

    fn reply(code: u16) -> (StatusCode, String) {
        (
            StatusCode::from_u16(code).unwrap_or(StatusCode::OK),
            format!(r#"{{"response":{{"status":{{"code":{code},"message":"x"}}}}}}"#),
        )
    }

    #[test]
    fn responses_are_classified() {
        assert_eq!(classify(200, Some(200)), Outcome::Sent);
        assert_eq!(classify(200, Some(451)), Outcome::Sent);
        assert_eq!(classify(503, Some(503)), Outcome::Retry);
        assert_eq!(classify(502, None), Outcome::Retry);
        for code in [400, 401, 402, 450, 452, 466, 468] {
            assert_eq!(classify(code, Some(code)), Outcome::Fail, "{code}");
        }
    }

    #[tokio::test]
    async fn code_is_sent_as_transactional_with_approved_sender() {
        let (url, seen) = serve(|_| reply(200)).await;
        let sms = sms(&url);
        assert!(
            sms.send("+905551112233", "Shedu doğrulama kodunuz: 123456.")
                .await
                .is_ok()
        );
        let all = requests(&seen);
        assert_eq!(all.len(), 1);
        let body: serde_json::Value = serde_json::from_str(&all[0].body).expect("json");
        let request = &body["request"];
        assert_eq!(request["authentication"]["key"], KEY);
        assert_eq!(request["authentication"]["hash"], HASH);
        assert_eq!(request["order"]["sender"], "SHEDU");
        assert_eq!(request["order"]["iys"], "0");
        assert_eq!(
            request["order"]["message"]["receipents"]["number"][0],
            "+905551112233"
        );
        assert_eq!(
            request["order"]["message"]["text"],
            "Shedu doğrulama kodunuz: 123456."
        );
        let debug = format!("{sms:?}");
        assert!(!debug.contains(KEY) && !debug.contains(HASH));
    }

    #[tokio::test]
    async fn server_errors_are_retried_and_duplicates_count_as_sent() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        // İlk deneme 503, ikincisi "tekrar eden sipariş" (ilki aslında kabul edilmişti).
        let (url, _) = serve(move |_| match counter.fetch_add(1, Ordering::SeqCst) {
            0 => reply(503),
            _ => reply(451),
        })
        .await;
        assert!(sms(&url).send("+905551112233", "metin").await.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let (url, seen) = serve(|_| reply(503)).await;
        assert!(sms(&url).send("+905551112233", "metin").await.is_err());
        assert_eq!(requests(&seen).len(), 3, "ilk deneme ve iki yeniden deneme");
    }

    #[tokio::test]
    async fn client_errors_are_not_retried() {
        for code in [401, 402, 450, 466] {
            let (url, seen) = serve(move |_| reply(code)).await;
            assert!(sms(&url).send("+905551112233", "metin").await.is_err());
            assert_eq!(requests(&seen).len(), 1, "{code}");
        }
    }
}
