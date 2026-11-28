//! Ortam değişkenlerinden yapılandırma.
//!
//! Güvensiz ayarla başlamak yerine açılışta hata verir (KEY-01, OPS-01):
//! - sırlar en az 32 bayt olmalı ve birbirinden farklı olmalı (TOK-02, amaç ayrımı);
//! - üretimde veritabanı bağlantısı TLS zorunlu kılmalı (NET-01);
//! - üretimde SMS (İleti Merkezi) ve push (APNs, FCM) sağlayıcıları zorunludur; geliştirme
//!   göndericileri (konsola yazan) üretimde kullanılamaz (EXC-01).

use std::{fmt, net::SocketAddr, path::PathBuf};

use crate::push::PushContent;

/// Varsayılan olarak yalnızca yerel arayüzü dinler; dışarı açmak bilinçli bir ayar olmalıdır.
const DEFAULT_ADDR: &str = "127.0.0.1:8080";
const MIN_SECRET_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development,
    Production,
}

#[derive(Clone)]
pub struct Config {
    pub environment: Environment,
    pub addr: SocketAddr,
    pub database_url: String,
    /// Bağlantıdan sonra geçilecek rol (ör. `shedu_app`); RLS'nin uygulanmasını garanti eder.
    pub database_role: Option<String>,
    /// Access token imza anahtarı (HS256).
    pub jwt_secret: Vec<u8>,
    /// SMS kodları ve deneme sayacı anahtarları için HMAC anahtarı.
    pub hmac_secret: Vec<u8>,
    /// Veritabanındaki faktör sırlarını (TOTP) şifreleyen veri anahtarı (KEY-04).
    pub data_key: Vec<u8>,
    /// Veri anahtarının sürümü; şifreli kayıtla birlikte saklanır.
    pub data_key_version: i16,
    /// WebSocket için izinli tarayıcı origin'leri (virgülle ayrılmış, ör. `https://app.example`).
    pub allowed_origins: Vec<String>,
    /// İç AI servisinin adresi ve servis token'ı (ikisi birlikte; yoksa AI özellikleri kapalı).
    pub ai: Option<AiSettings>,
    /// SMS sağlayıcısı. Yoksa (yalnızca geliştirme) kodlar konsola yazılır.
    pub sms: Option<IletiMerkeziSettings>,
    /// iOS push sağlayıcısı.
    pub apns: Option<ApnsSettings>,
    /// Android push sağlayıcısı.
    pub fcm: Option<FcmSettings>,
    /// Push bildiriminde ne yazacağı (varsayılan: kısa, ad içermez).
    pub push_content: PushContent,
}

/// İleti Merkezi API kimliği ve onaylı gönderici adı (başlık).
#[derive(Clone)]
pub struct IletiMerkeziSettings {
    pub key: String,
    pub hash: String,
    pub sender: String,
}

impl fmt::Debug for IletiMerkeziSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IletiMerkeziSettings")
            .field("sender", &self.sender)
            .finish_non_exhaustive()
    }
}

/// APNs token tabanlı kimlik doğrulama: `.p8` anahtar dosyası, anahtar kimliği, ekip kimliği ve
/// uygulamanın paket kimliği (konu).
#[derive(Debug, Clone)]
pub struct ApnsSettings {
    pub key_file: PathBuf,
    pub key_id: String,
    pub team_id: String,
    pub topic: String,
    /// Geliştirme derlemeleri için Apple'ın sandbox ortamı.
    pub sandbox: bool,
    /// Sessiz modu aşan kritik uyarı; Apple'ın izni (entitlement) alınınca açılır.
    pub critical_alerts: bool,
}

/// FCM için Google hizmet hesabı dosyası.
#[derive(Debug, Clone)]
pub struct FcmSettings {
    pub service_account_file: PathBuf,
}

#[derive(Clone)]
pub struct AiSettings {
    pub url: String,
    pub token: String,
    /// Bütün sistemin son 24 saatteki AI harcama sınırı (ABD doları).
    pub daily_budget_usd: u32,
}

impl fmt::Debug for Config {
    // Sırlar ve bağlantı adresi (parola içerebilir) hiçbir zaman log'a düşmez (LOG-02).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("environment", &self.environment)
            .field("addr", &self.addr)
            .field("database_role", &self.database_role)
            .field("ai_configured", &self.ai.is_some())
            .field("sms", &self.sms)
            .field("apns", &self.apns)
            .field("fcm", &self.fcm)
            .field("push_content", &self.push_content)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    Missing(&'static str),
    Invalid(&'static str),
    SecretTooShort(&'static str),
    SecretsMustDiffer,
    DatabaseTlsRequired,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(name) => write!(f, "{name} tanımlı değil"),
            Self::Invalid(name) => write!(f, "{name} geçersiz"),
            Self::SecretTooShort(name) => write!(f, "{name} en az {MIN_SECRET_LEN} bayt olmalı"),
            Self::SecretsMustDiffer => write!(
                f,
                "SHEDU_JWT_SECRET, SHEDU_HMAC_SECRET ve SHEDU_DATA_KEY birbirinden farklı olmalı"
            ),
            Self::DatabaseTlsRequired => write!(
                f,
                "üretimde DATABASE_URL sslmode=verify-full olmalı (sunucu sertifikası ve ana makine adı doğrulanır)"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Testlerde ortam değişkenlerine dokunmadan yapılandırma kurmak için.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let environment = match get("SHEDU_ENV").as_deref() {
            None | Some("production") => Environment::Production,
            Some("development") => Environment::Development,
            Some(_) => return Err(ConfigError::Invalid("SHEDU_ENV")),
        };

        let addr = get("SHEDU_API_ADDR")
            .unwrap_or_else(|| DEFAULT_ADDR.to_owned())
            .parse()
            .map_err(|_| ConfigError::Invalid("SHEDU_API_ADDR"))?;

        let database_url = get("DATABASE_URL").ok_or(ConfigError::Missing("DATABASE_URL"))?;
        let options: sqlx::postgres::PgConnectOptions = database_url
            .parse()
            .map_err(|_| ConfigError::Invalid("DATABASE_URL"))?;
        if environment == Environment::Production && !crate::db::verifies_server_identity(&options)
        {
            return Err(ConfigError::DatabaseTlsRequired);
        }

        let database_role = get("SHEDU_DB_ROLE").filter(|role| !role.is_empty());
        // Üretimde uygulama her zaman RLS'ye tabi rolle çalışır; açılışta ayrıca doğrulanır.
        if environment == Environment::Production && database_role.is_none() {
            return Err(ConfigError::Missing("SHEDU_DB_ROLE"));
        }

        let jwt_secret = secret(&get, "SHEDU_JWT_SECRET")?;
        let hmac_secret = secret(&get, "SHEDU_HMAC_SECRET")?;
        let data_key = secret(&get, "SHEDU_DATA_KEY")?;
        if jwt_secret == hmac_secret || data_key == jwt_secret || data_key == hmac_secret {
            return Err(ConfigError::SecretsMustDiffer);
        }
        let data_key_version = match get("SHEDU_DATA_KEY_VERSION") {
            None => 1,
            Some(value) => value
                .parse::<i16>()
                .ok()
                .filter(|v| *v > 0)
                .ok_or(ConfigError::Invalid("SHEDU_DATA_KEY_VERSION"))?,
        };

        let allowed_origins = get("SHEDU_ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|origin| !origin.is_empty())
            .map(str::to_owned)
            .collect();

        let ai = match (
            get("SHEDU_AI_URL").filter(|v| !v.is_empty()),
            get("SHEDU_AI_TOKEN").filter(|v| !v.is_empty()),
        ) {
            (None, None) => None,
            (Some(_), None) => return Err(ConfigError::Missing("SHEDU_AI_TOKEN")),
            (None, Some(_)) => return Err(ConfigError::Missing("SHEDU_AI_URL")),
            (Some(url), Some(token)) => {
                crate::ai::validate_url(&url).map_err(|_| ConfigError::Invalid("SHEDU_AI_URL"))?;
                if token.len() < MIN_SECRET_LEN {
                    return Err(ConfigError::SecretTooShort("SHEDU_AI_TOKEN"));
                }
                let token_bytes = token.as_bytes();
                if [&jwt_secret, &hmac_secret, &data_key]
                    .iter()
                    .any(|s| s.as_slice() == token_bytes)
                {
                    return Err(ConfigError::SecretsMustDiffer);
                }
                let daily_budget_usd = match get("SHEDU_AI_DAILY_BUDGET_USD") {
                    None => crate::ai::DEFAULT_GLOBAL_DAILY_USD,
                    Some(value) => value
                        .parse::<u32>()
                        .ok()
                        .filter(|v| (1..=100_000).contains(v))
                        .ok_or(ConfigError::Invalid("SHEDU_AI_DAILY_BUDGET_USD"))?,
                };
                Some(AiSettings {
                    url,
                    token,
                    daily_budget_usd,
                })
            }
        };

        let sms = sms_settings(&get)?;
        let apns = apns_settings(&get)?;
        let fcm = get("SHEDU_FCM_SERVICE_ACCOUNT_FILE")
            .filter(|v| !v.is_empty())
            .map(|path| FcmSettings {
                service_account_file: PathBuf::from(path),
            });
        let push_content = match get("SHEDU_PUSH_CONTENT").as_deref() {
            None | Some("minimal") => PushContent::Minimal,
            Some("full") => PushContent::Full,
            Some(_) => return Err(ConfigError::Invalid("SHEDU_PUSH_CONTENT")),
        };
        // Alarm bildirimi veya giriş kodu gitmeyen bir sistemle başlamak yerine dur (EXC-01).
        if environment == Environment::Production {
            if sms.is_none() {
                return Err(ConfigError::Missing("SHEDU_ILETIMERKEZI_KEY"));
            }
            if apns.is_none() {
                return Err(ConfigError::Missing("SHEDU_APNS_KEY_FILE"));
            }
            if fcm.is_none() {
                return Err(ConfigError::Missing("SHEDU_FCM_SERVICE_ACCOUNT_FILE"));
            }
        }

        Ok(Self {
            environment,
            addr,
            database_url,
            database_role,
            jwt_secret,
            hmac_secret,
            data_key,
            data_key_version,
            allowed_origins,
            ai,
            sms,
            apns,
            fcm,
            push_content,
        })
    }
}

/// İleti Merkezi: anahtar, hash ve başlık birlikte verilir; hiçbiri yoksa sağlayıcı yok.
fn sms_settings(
    get: &impl Fn(&str) -> Option<String>,
) -> Result<Option<IletiMerkeziSettings>, ConfigError> {
    let value = |name| get(name).filter(|v: &String| !v.is_empty());
    let (key, hash, sender) = (
        value("SHEDU_ILETIMERKEZI_KEY"),
        value("SHEDU_ILETIMERKEZI_HASH"),
        value("SHEDU_SMS_SENDER"),
    );
    if key.is_none() && hash.is_none() && sender.is_none() {
        return Ok(None);
    }
    let key = key.ok_or(ConfigError::Missing("SHEDU_ILETIMERKEZI_KEY"))?;
    let hash = hash.ok_or(ConfigError::Missing("SHEDU_ILETIMERKEZI_HASH"))?;
    let sender = sender.ok_or(ConfigError::Missing("SHEDU_SMS_SENDER"))?;
    let credential = |v: &str| v.len() <= 256 && v.bytes().all(|b| b.is_ascii_graphic());
    if !credential(&key) {
        return Err(ConfigError::Invalid("SHEDU_ILETIMERKEZI_KEY"));
    }
    if !credential(&hash) {
        return Err(ConfigError::Invalid("SHEDU_ILETIMERKEZI_HASH"));
    }
    // Sağlayıcı kuralı: en çok 11 karakter, Türkçe karakter yok.
    if sender.len() > 11
        || !sender
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b' ')
    {
        return Err(ConfigError::Invalid("SHEDU_SMS_SENDER"));
    }
    Ok(Some(IletiMerkeziSettings { key, hash, sender }))
}

/// APNs: anahtar dosyası, anahtar kimliği, ekip kimliği ve konu birlikte verilir.
fn apns_settings(
    get: &impl Fn(&str) -> Option<String>,
) -> Result<Option<ApnsSettings>, ConfigError> {
    let value = |name| get(name).filter(|v: &String| !v.is_empty());
    let names = [
        "SHEDU_APNS_KEY_FILE",
        "SHEDU_APNS_KEY_ID",
        "SHEDU_APNS_TEAM_ID",
        "SHEDU_APNS_TOPIC",
    ];
    let values: Vec<Option<String>> = names.iter().map(|name| value(name)).collect();
    if values.iter().all(Option::is_none) {
        return Ok(None);
    }
    let mut present = Vec::with_capacity(names.len());
    for (name, v) in names.iter().zip(values) {
        present.push(v.ok_or(ConfigError::Missing(name))?);
    }
    let [key_file, key_id, team_id, topic]: [String; 4] = present
        .try_into()
        .map_err(|_| ConfigError::Missing("SHEDU_APNS_KEY_FILE"))?;
    // Apple'ın kimlikleri 10 karakterlik büyük harf ve rakamdır.
    let apple_id = |v: &str| {
        v.len() == 10
            && v.bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    };
    if !apple_id(&key_id) {
        return Err(ConfigError::Invalid("SHEDU_APNS_KEY_ID"));
    }
    if !apple_id(&team_id) {
        return Err(ConfigError::Invalid("SHEDU_APNS_TEAM_ID"));
    }
    // Paket kimliği (ör. `com.ornek.shedu`): başlığa girer, yalnızca güvenli karakterler.
    if topic.len() > 155
        || !topic.contains('.')
        || !topic
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err(ConfigError::Invalid("SHEDU_APNS_TOPIC"));
    }
    let sandbox = match get("SHEDU_APNS_ENVIRONMENT").as_deref() {
        None | Some("production") => false,
        Some("sandbox") => true,
        Some(_) => return Err(ConfigError::Invalid("SHEDU_APNS_ENVIRONMENT")),
    };
    let critical_alerts = match get("SHEDU_APNS_CRITICAL_ALERTS").as_deref() {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => return Err(ConfigError::Invalid("SHEDU_APNS_CRITICAL_ALERTS")),
    };
    Ok(Some(ApnsSettings {
        key_file: PathBuf::from(key_file),
        key_id,
        team_id,
        topic,
        sandbox,
        critical_alerts,
    }))
}

fn secret(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
) -> Result<Vec<u8>, ConfigError> {
    let value = get(name).ok_or(ConfigError::Missing(name))?;
    if value.len() < MIN_SECRET_LEN {
        return Err(ConfigError::SecretTooShort(name));
    }
    Ok(value.into_bytes())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    const JWT: &str = "jwt-secret-0123456789abcdefghijklmnop";
    const HMAC: &str = "hmac-secret-0123456789abcdefghijklmno";
    const DATA: &str = "data-key-0123456789abcdefghijklmnopqr";

    #[test]
    fn development_config_is_accepted() {
        let config = Config::from_lookup(lookup(&[
            ("SHEDU_ENV", "development"),
            ("DATABASE_URL", "postgres://localhost/shedu"),
            ("SHEDU_JWT_SECRET", JWT),
            ("SHEDU_HMAC_SECRET", HMAC),
            ("SHEDU_DATA_KEY", DATA),
        ]))
        .expect("geçerli yapılandırma");
        assert_eq!(config.environment, Environment::Development);
        assert_eq!(config.addr.to_string(), DEFAULT_ADDR);
    }

    #[test]
    fn missing_environment_means_production_and_requires_tls() {
        let result = Config::from_lookup(lookup(&[
            ("DATABASE_URL", "postgres://db/shedu"),
            ("SHEDU_JWT_SECRET", JWT),
            ("SHEDU_HMAC_SECRET", HMAC),
            ("SHEDU_DATA_KEY", DATA),
        ]));
        assert_eq!(result.err(), Some(ConfigError::DatabaseTlsRequired));
    }

    #[test]
    fn production_tls_check_reads_the_effective_mode_not_the_text() {
        for url in [
            // Sertifikayı doğrulamaz.
            "postgres://db/shedu?sslmode=require",
            // Metin başka parametrenin içinde; etkin mod `disable`.
            "postgres://db/shedu?sslmode=disable&application_name=sslmode%3Dverify-full",
            // Son değer geçerli.
            "postgres://db/shedu?sslmode=verify-full&sslmode=prefer",
        ] {
            let result = Config::from_lookup(lookup(&[
                ("DATABASE_URL", url),
                ("SHEDU_DB_ROLE", "shedu_app"),
                ("SHEDU_JWT_SECRET", JWT),
                ("SHEDU_HMAC_SECRET", HMAC),
                ("SHEDU_DATA_KEY", DATA),
            ]));
            assert_eq!(
                result.err(),
                Some(ConfigError::DatabaseTlsRequired),
                "{url}"
            );
        }
    }

    #[test]
    fn production_requires_an_application_role() {
        let result = Config::from_lookup(lookup(&[
            ("DATABASE_URL", "postgres://db/shedu?sslmode=verify-full"),
            ("SHEDU_JWT_SECRET", JWT),
            ("SHEDU_HMAC_SECRET", HMAC),
            ("SHEDU_DATA_KEY", DATA),
        ]));
        assert_eq!(result.err(), Some(ConfigError::Missing("SHEDU_DB_ROLE")));
        let mut pairs = vec![
            ("DATABASE_URL", "postgres://db/shedu?sslmode=verify-full"),
            ("SHEDU_DB_ROLE", "shedu_app"),
            ("SHEDU_JWT_SECRET", JWT),
            ("SHEDU_HMAC_SECRET", HMAC),
            ("SHEDU_DATA_KEY", DATA),
        ];
        pairs.extend_from_slice(PROVIDERS);
        assert!(Config::from_lookup(lookup(&pairs)).is_ok());
    }

    const PROVIDERS: &[(&str, &str)] = &[
        ("SHEDU_ILETIMERKEZI_KEY", "deneme-anahtar"),
        ("SHEDU_ILETIMERKEZI_HASH", "deneme-hash"),
        ("SHEDU_SMS_SENDER", "SHEDU"),
        ("SHEDU_APNS_KEY_FILE", "/run/secrets/apns.p8"),
        ("SHEDU_APNS_KEY_ID", "ABC123DEFG"),
        ("SHEDU_APNS_TEAM_ID", "TEAM123456"),
        ("SHEDU_APNS_TOPIC", "app.shedu.ios"),
        ("SHEDU_FCM_SERVICE_ACCOUNT_FILE", "/run/secrets/fcm.json"),
    ];

    #[test]
    fn production_requires_sms_and_push_providers() {
        let base = [
            ("DATABASE_URL", "postgres://db/shedu?sslmode=verify-full"),
            ("SHEDU_DB_ROLE", "shedu_app"),
            ("SHEDU_JWT_SECRET", JWT),
            ("SHEDU_HMAC_SECRET", HMAC),
            ("SHEDU_DATA_KEY", DATA),
        ];
        let without = |skip: &str| {
            let mut pairs = base.to_vec();
            pairs.extend(PROVIDERS.iter().filter(|(name, _)| !name.starts_with(skip)));
            Config::from_lookup(lookup(&pairs)).err()
        };
        assert_eq!(
            without("SHEDU_ILETIMERKEZI").or(without("SHEDU_SMS")),
            Some(ConfigError::Missing("SHEDU_ILETIMERKEZI_KEY"))
        );
        assert_eq!(
            without("SHEDU_APNS"),
            Some(ConfigError::Missing("SHEDU_APNS_KEY_FILE"))
        );
        assert_eq!(
            without("SHEDU_FCM"),
            Some(ConfigError::Missing("SHEDU_FCM_SERVICE_ACCOUNT_FILE"))
        );

        let mut pairs = base.to_vec();
        pairs.extend_from_slice(PROVIDERS);
        let config = Config::from_lookup(lookup(&pairs)).expect("üretim");
        assert_eq!(config.push_content, PushContent::Minimal);
        assert!(
            config
                .apns
                .as_ref()
                .is_some_and(|a| !a.sandbox && !a.critical_alerts)
        );
        let debug = format!("{config:?}");
        assert!(!debug.contains("deneme-anahtar") && !debug.contains("deneme-hash"));
    }

    #[test]
    fn provider_settings_are_validated() {
        let base = [
            ("SHEDU_ENV", "development"),
            ("DATABASE_URL", "postgres://localhost/shedu"),
            ("SHEDU_JWT_SECRET", JWT),
            ("SHEDU_HMAC_SECRET", HMAC),
            ("SHEDU_DATA_KEY", DATA),
        ];
        let with = |extra: &[(&'static str, &'static str)]| {
            let mut pairs = base.to_vec();
            pairs.extend_from_slice(extra);
            Config::from_lookup(lookup(&pairs)).err()
        };
        // Geliştirmede sağlayıcı isteğe bağlı; verilirse eksiksiz ve geçerli olmalı.
        assert_eq!(with(&[]), None);
        assert_eq!(
            with(&[("SHEDU_ILETIMERKEZI_KEY", "anahtar")]),
            Some(ConfigError::Missing("SHEDU_ILETIMERKEZI_HASH"))
        );
        assert_eq!(
            with(&[
                ("SHEDU_ILETIMERKEZI_KEY", "anahtar"),
                ("SHEDU_ILETIMERKEZI_HASH", "hash"),
                ("SHEDU_SMS_SENDER", "ŞEDU"),
            ]),
            Some(ConfigError::Invalid("SHEDU_SMS_SENDER"))
        );
        assert_eq!(
            with(&[
                ("SHEDU_ILETIMERKEZI_KEY", "anahtar"),
                ("SHEDU_ILETIMERKEZI_HASH", "hash"),
                ("SHEDU_SMS_SENDER", "COK UZUN BASLIK"),
            ]),
            Some(ConfigError::Invalid("SHEDU_SMS_SENDER"))
        );
        assert_eq!(
            with(&[("SHEDU_APNS_KEY_FILE", "/k.p8")]),
            Some(ConfigError::Missing("SHEDU_APNS_KEY_ID"))
        );
        let apns = [
            ("SHEDU_APNS_KEY_FILE", "/k.p8"),
            ("SHEDU_APNS_KEY_ID", "ABC123DEFG"),
            ("SHEDU_APNS_TEAM_ID", "TEAM123456"),
        ];
        let apns_with = |topic: &'static str, extra: &[(&'static str, &'static str)]| {
            let mut pairs = apns.to_vec();
            pairs.push(("SHEDU_APNS_TOPIC", topic));
            pairs.extend_from_slice(extra);
            with(&pairs)
        };
        assert_eq!(apns_with("app.shedu.ios", &[]), None);
        assert_eq!(
            apns_with("app.shedu.ios\r\nx: y", &[]),
            Some(ConfigError::Invalid("SHEDU_APNS_TOPIC"))
        );
        assert_eq!(
            apns_with("app.shedu.ios", &[("SHEDU_APNS_ENVIRONMENT", "test")]),
            Some(ConfigError::Invalid("SHEDU_APNS_ENVIRONMENT"))
        );
        assert_eq!(
            apns_with("app.shedu.ios", &[("SHEDU_APNS_CRITICAL_ALERTS", "evet")]),
            Some(ConfigError::Invalid("SHEDU_APNS_CRITICAL_ALERTS"))
        );
        assert_eq!(
            with(&[
                ("SHEDU_APNS_KEY_FILE", "/k.p8"),
                ("SHEDU_APNS_KEY_ID", "kisa"),
                ("SHEDU_APNS_TEAM_ID", "TEAM123456"),
                ("SHEDU_APNS_TOPIC", "app.shedu.ios"),
            ]),
            Some(ConfigError::Invalid("SHEDU_APNS_KEY_ID"))
        );
        assert_eq!(
            with(&[("SHEDU_PUSH_CONTENT", "hepsi")]),
            Some(ConfigError::Invalid("SHEDU_PUSH_CONTENT"))
        );
    }

    #[test]
    fn short_or_shared_secrets_are_rejected() {
        let short = Config::from_lookup(lookup(&[
            ("SHEDU_ENV", "development"),
            ("DATABASE_URL", "postgres://localhost/shedu"),
            ("SHEDU_JWT_SECRET", "kisa"),
            ("SHEDU_HMAC_SECRET", HMAC),
            ("SHEDU_DATA_KEY", DATA),
        ]));
        assert_eq!(
            short.err(),
            Some(ConfigError::SecretTooShort("SHEDU_JWT_SECRET"))
        );

        let shared = Config::from_lookup(lookup(&[
            ("SHEDU_ENV", "development"),
            ("DATABASE_URL", "postgres://localhost/shedu"),
            ("SHEDU_JWT_SECRET", JWT),
            ("SHEDU_HMAC_SECRET", JWT),
            ("SHEDU_DATA_KEY", DATA),
        ]));
        assert_eq!(shared.err(), Some(ConfigError::SecretsMustDiffer));

        let shared_data = Config::from_lookup(lookup(&[
            ("SHEDU_ENV", "development"),
            ("DATABASE_URL", "postgres://localhost/shedu"),
            ("SHEDU_JWT_SECRET", JWT),
            ("SHEDU_HMAC_SECRET", HMAC),
            ("SHEDU_DATA_KEY", HMAC),
        ]));
        assert_eq!(shared_data.err(), Some(ConfigError::SecretsMustDiffer));

        let missing = Config::from_lookup(lookup(&[
            ("SHEDU_ENV", "development"),
            ("DATABASE_URL", "postgres://localhost/shedu"),
            ("SHEDU_JWT_SECRET", JWT),
            ("SHEDU_HMAC_SECRET", HMAC),
        ]));
        assert_eq!(missing.err(), Some(ConfigError::Missing("SHEDU_DATA_KEY")));
    }

    #[test]
    fn ai_service_settings_are_validated() {
        let base = [
            ("SHEDU_ENV", "development"),
            ("DATABASE_URL", "postgres://localhost/shedu"),
            ("SHEDU_JWT_SECRET", JWT),
            ("SHEDU_HMAC_SECRET", HMAC),
            ("SHEDU_DATA_KEY", DATA),
        ];
        let with = |extra: &[(&'static str, &'static str)]| {
            let mut pairs = base.to_vec();
            pairs.extend_from_slice(extra);
            Config::from_lookup(lookup(&pairs))
        };
        const TOKEN: &str = "ai-token-0123456789abcdefghijklmnopq";
        assert!(with(&[]).expect("AI'sız").ai.is_none());
        let ok = with(&[
            ("SHEDU_AI_URL", "http://127.0.0.1:8000"),
            ("SHEDU_AI_TOKEN", TOKEN),
        ])
        .expect("AI'lı");
        assert_eq!(ok.ai.as_ref().map(|ai| ai.daily_budget_usd), Some(20));
        assert!(!format!("{ok:?}").contains(TOKEN));
        assert_eq!(
            with(&[
                ("SHEDU_AI_URL", "http://127.0.0.1:8000"),
                ("SHEDU_AI_TOKEN", TOKEN),
                ("SHEDU_AI_DAILY_BUDGET_USD", "0"),
            ])
            .err(),
            Some(ConfigError::Invalid("SHEDU_AI_DAILY_BUDGET_USD"))
        );
        assert_eq!(
            with(&[("SHEDU_AI_URL", "http://127.0.0.1:8000")]).err(),
            Some(ConfigError::Missing("SHEDU_AI_TOKEN"))
        );
        assert_eq!(
            with(&[
                ("SHEDU_AI_URL", "http://ai:8000"),
                ("SHEDU_AI_TOKEN", TOKEN)
            ])
            .err(),
            Some(ConfigError::Invalid("SHEDU_AI_URL"))
        );
        assert_eq!(
            with(&[("SHEDU_AI_URL", "https://ai"), ("SHEDU_AI_TOKEN", "kisa")]).err(),
            Some(ConfigError::SecretTooShort("SHEDU_AI_TOKEN"))
        );
        assert_eq!(
            with(&[("SHEDU_AI_URL", "https://ai"), ("SHEDU_AI_TOKEN", JWT)]).err(),
            Some(ConfigError::SecretsMustDiffer)
        );
    }

    #[test]
    fn debug_output_never_contains_secrets() {
        let config = Config::from_lookup(lookup(&[
            ("SHEDU_ENV", "development"),
            ("DATABASE_URL", "postgres://user:parola@localhost/shedu"),
            ("SHEDU_JWT_SECRET", JWT),
            ("SHEDU_HMAC_SECRET", HMAC),
            ("SHEDU_DATA_KEY", DATA),
        ]))
        .expect("geçerli yapılandırma");
        let debug = format!("{config:?}");
        assert!(
            !debug.contains(JWT)
                && !debug.contains(HMAC)
                && !debug.contains(DATA)
                && !debug.contains("parola")
        );
    }
}
