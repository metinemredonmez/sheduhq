//! Ortam değişkenlerinden yapılandırma.
//!
//! Güvensiz ayarla başlamak yerine açılışta hata verir (KEY-01, OPS-01):
//! - sırlar en az 32 bayt olmalı ve birbirinden farklı olmalı (TOK-02, amaç ayrımı);
//! - üretimde veritabanı bağlantısı TLS zorunlu kılmalı (NET-01);
//! - geliştirme SMS göndericisi üretimde kullanılamaz.

use std::{fmt, net::SocketAddr};

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
                "üretimde DATABASE_URL sslmode=verify-full (veya require) içermeli"
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
        if environment == Environment::Production
            && !(database_url.contains("sslmode=verify-full")
                || database_url.contains("sslmode=require"))
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
        })
    }
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
    fn production_requires_an_application_role() {
        let result = Config::from_lookup(lookup(&[
            ("DATABASE_URL", "postgres://db/shedu?sslmode=verify-full"),
            ("SHEDU_JWT_SECRET", JWT),
            ("SHEDU_HMAC_SECRET", HMAC),
            ("SHEDU_DATA_KEY", DATA),
        ]));
        assert_eq!(result.err(), Some(ConfigError::Missing("SHEDU_DB_ROLE")));
        let ok = Config::from_lookup(lookup(&[
            ("DATABASE_URL", "postgres://db/shedu?sslmode=verify-full"),
            ("SHEDU_DB_ROLE", "shedu_app"),
            ("SHEDU_JWT_SECRET", JWT),
            ("SHEDU_HMAC_SECRET", HMAC),
            ("SHEDU_DATA_KEY", DATA),
        ]));
        assert!(ok.is_ok());
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
