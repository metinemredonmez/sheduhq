//! Dış bildirim sağlayıcıları: APNs (iOS push), FCM (Android push) ve İleti Merkezi (SMS).
//!
//! Ortak kurallar:
//! - **Hedef sabittir (EXT-01):** sağlayıcı adresleri koddadır; yapılandırma yalnızca kimlik
//!   bilgisi verir. Kullanıcıdan gelen değer (cihaz token'ı) adrese ancak biçimi denetlendikten
//!   sonra girer.
//! - **Bağlantı (EXT-02, NET-01):** yalnızca HTTPS; sertifika ve ana makine adı doğrulanır,
//!   yönlendirme izlenmez, sistem vekil ayarı kullanılmaz.
//! - **Bütçe (EXT-03, RES-01):** bağlantı 5 sn, istek en fazla 15 sn; yanıt gövdesi en fazla 64 KiB
//!   okunur. Push çağrısının üst sınırı ayrıca `push::SEND_TIMEOUT`'tur.
//! - **Sır ve log (KEY-02, LOG-02):** anahtarlar, erişim token'ları, cihaz token'ları ve telefon
//!   numaraları log'a ve `Debug` çıktısına yazılmaz; hata log'unda yalnızca sağlayıcının hata kodu
//!   bulunur.

pub mod apns;
pub mod fcm;
pub mod iletimerkezi;

use std::{
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};

use crate::push::{PushError, PushFuture, PushMessage, PushSender};

/// Sağlayıcı yanıtının okunacak en büyük boyutu.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Tek bir HTTP isteğinin en uzun süresi.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Sağlayıcı kurulurken oluşan hata. Açılışta raporlanır; API başlamaz.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// Anahtar veya hizmet hesabı dosyası okunamadı ya da geçersiz.
    Key(&'static str),
    /// HTTP istemcisi kurulamadı.
    Client,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(what) => write!(f, "{what} okunamadı veya geçersiz"),
            Self::Client => write!(f, "sağlayıcı HTTP istemcisi kurulamadı"),
        }
    }
}

impl std::error::Error for ProviderError {}

/// Sağlayıcılar için ortak HTTP istemcisi. `https_only` yalnızca birim testlerinde (yerel sahte
/// sunucu) kapatılır.
pub(crate) fn http_client(https_only: bool) -> Result<reqwest::Client, ProviderError> {
    // reqwest yalnızca ring sağlayıcısıyla derlenir; süreç genelinde bir kez kurulur.
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .https_only(https_only)
        .build()
        .map_err(|_| ProviderError::Client)
}

/// Yanıt gövdesini en fazla 64 KiB okur. Daha büyük veya yarıda kesilen gövde `None` döner.
pub(crate) async fn read_body(mut response: reqwest::Response) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if body.len() + chunk.len() <= MAX_RESPONSE_BYTES => {
                body.extend_from_slice(&chunk);
            }
            Ok(Some(_)) | Err(_) => return None,
            Ok(None) => return Some(body),
        }
    }
}

/// PEM işaretleri parçalı yazılır: sır tarayıcısı (gitleaks) kodu anahtar sanmasın.
pub(crate) const PEM_BEGIN: &str = concat!("-----BEGIN ", "PRIVATE KEY-----");
pub(crate) const PEM_END: &str = concat!("-----END ", "PRIVATE KEY-----");

/// PEM metnindeki `PRIVATE KEY` (PKCS#8) bloğunu DER'e çevirir.
pub(crate) fn pkcs8_from_pem(pem: &str) -> Option<Vec<u8>> {
    let start = pem.find(PEM_BEGIN)? + PEM_BEGIN.len();
    let stop = start + pem[start..].find(PEM_END)?;
    let body: String = pem[start..stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    STANDARD.decode(body).ok().filter(|der| !der.is_empty())
}

/// İmzalanacak JWT gövdesi: `base64url(başlık).base64url(iddialar)`.
pub(crate) fn jwt_signing_input(header: &serde_json::Value, claims: &serde_json::Value) -> String {
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

/// İmzayı ekleyerek JWT'yi tamamlar.
pub(crate) fn jwt_with_signature(signing_input: &str, signature: &[u8]) -> String {
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// Push bildirimini cihazın platformuna göre sağlayıcıya yönlendirir: `ios` → APNs,
/// `android` → FCM. Sağlayıcısı olmayan platform (ör. `web`) kalıcı hata verir.
pub struct PlatformPush {
    pub apns: Option<apns::Apns>,
    pub fcm: Option<fcm::Fcm>,
}

impl PushSender for PlatformPush {
    fn send<'a>(&'a self, message: &'a PushMessage) -> PushFuture<'a> {
        Box::pin(async move {
            match (message.platform.as_str(), &self.apns, &self.fcm) {
                ("ios", Some(apns), _) => return apns.send(message).await,
                ("android", _, Some(fcm)) => return fcm.send(message).await,
                _ => {}
            }
            tracing::error!(
                platform = %message.platform,
                event_id = message.event_id,
                "bu platform için push sağlayıcısı yapılandırılmadı"
            );
            Err(PushError::Rejected)
        })
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! Sağlayıcı birim testleri için yerel sahte HTTP sunucusu.

    use std::{
        net::SocketAddr,
        sync::{Arc, Mutex},
    };

    use axum::{
        Router,
        body::Bytes,
        extract::State,
        http::{HeaderMap, StatusCode, Uri},
        response::IntoResponse,
        routing::any,
    };

    /// Sahte sunucunun gördüğü istek.
    #[derive(Debug, Clone)]
    pub struct Seen {
        pub path: String,
        pub headers: HeaderMap,
        pub body: String,
    }

    type Reply = Arc<dyn Fn(&Seen) -> (StatusCode, String) + Send + Sync>;

    #[derive(Clone)]
    struct Mock {
        seen: Arc<Mutex<Vec<Seen>>>,
        reply: Reply,
    }

    async fn handle(
        State(mock): State<Mock>,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> impl IntoResponse {
        let seen = Seen {
            path: uri.path().to_owned(),
            headers,
            body: String::from_utf8_lossy(&body).into_owned(),
        };
        let reply = (mock.reply)(&seen);
        if let Ok(mut all) = mock.seen.lock() {
            all.push(seen);
        }
        reply
    }

    /// Her isteğe `reply` ile yanıt veren sunucu başlatır; adresini ve görülen istekleri döner.
    pub async fn serve(
        reply: impl Fn(&Seen) -> (StatusCode, String) + Send + Sync + 'static,
    ) -> (String, Arc<Mutex<Vec<Seen>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mock = Mock {
            seen: seen.clone(),
            reply: Arc::new(reply),
        };
        let app = Router::new().fallback(any(handle)).with_state(mock);
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("sahte sunucu dinleyemedi");
        let addr = listener.local_addr().expect("adres");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), seen)
    }

    /// Base64 gövdeden test PEM'i kurar.
    pub fn pem(body: &str) -> String {
        format!("{}\n{body}\n{}\n", super::PEM_BEGIN, super::PEM_END)
    }

    pub fn requests(seen: &Arc<Mutex<Vec<Seen>>>) -> Vec<Seen> {
        seen.lock().map(|all| all.clone()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_body_is_decoded_and_garbage_rejected() {
        use testing::pem;
        assert_eq!(
            pkcs8_from_pem(&pem("AAEC\nAwQ=")),
            Some(vec![0, 1, 2, 3, 4])
        );
        assert_eq!(pkcs8_from_pem("anahtar yok"), None);
        assert_eq!(pkcs8_from_pem(&pem("%%%")), None);
        assert_eq!(pkcs8_from_pem(&pem("")), None);
    }

    #[tokio::test]
    async fn platform_without_provider_is_rejected_not_retried() {
        let push = PlatformPush {
            apns: None,
            fcm: None,
        };
        let message = PushMessage {
            token: "abcd".into(),
            platform: "web".into(),
            user_id: uuid::Uuid::new_v4(),
            priority: crate::push::PushPriority::Critical,
            title: "t".into(),
            body: "b".into(),
            organization_id: uuid::Uuid::new_v4(),
            panel_id: uuid::Uuid::new_v4(),
            event_id: 1,
            kind: "alarm".into(),
            collapse_key: "shedu-event-1".into(),
            expires_at: 0,
        };
        assert_eq!(push.send(&message).await, Err(PushError::Rejected));
        let ios = PushMessage {
            platform: "ios".into(),
            ..message
        };
        assert_eq!(push.send(&ios).await, Err(PushError::Rejected));
    }
}
