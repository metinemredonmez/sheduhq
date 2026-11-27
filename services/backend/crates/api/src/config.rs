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
}

impl fmt::Debug for Config {
    // Sırlar ve bağlantı adresi (parola içerebilir) hiçbir zaman log'a düşmez (LOG-02).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("environment", &self.environment)
            .field("addr", &self.addr)
            .field("database_role", &self.database_role)
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
            Self::SecretsMustDiffer => {
                write!(f, "SHEDU_JWT_SECRET ve SHEDU_HMAC_SECRET farklı olmalı")
            }
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

        let jwt_secret = secret(&get, "SHEDU_JWT_SECRET")?;
        let hmac_secret = secret(&get, "SHEDU_HMAC_SECRET")?;
        if jwt_secret == hmac_secret {
            return Err(ConfigError::SecretsMustDiffer);
        }

        Ok(Self {
            environment,
            addr,
            database_url,
            database_role,
            jwt_secret,
            hmac_secret,
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

    #[test]
    fn development_config_is_accepted() {
        let config = Config::from_lookup(lookup(&[
            ("SHEDU_ENV", "development"),
            ("DATABASE_URL", "postgres://localhost/shedu"),
            ("SHEDU_JWT_SECRET", JWT),
            ("SHEDU_HMAC_SECRET", HMAC),
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
        ]));
        assert_eq!(result.err(), Some(ConfigError::DatabaseTlsRequired));
    }

    #[test]
    fn short_or_shared_secrets_are_rejected() {
        let short = Config::from_lookup(lookup(&[
            ("SHEDU_ENV", "development"),
            ("DATABASE_URL", "postgres://localhost/shedu"),
            ("SHEDU_JWT_SECRET", "kisa"),
            ("SHEDU_HMAC_SECRET", HMAC),
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
        ]));
        assert_eq!(shared.err(), Some(ConfigError::SecretsMustDiffer));
    }

    #[test]
    fn debug_output_never_contains_secrets() {
        let config = Config::from_lookup(lookup(&[
            ("SHEDU_ENV", "development"),
            ("DATABASE_URL", "postgres://user:parola@localhost/shedu"),
            ("SHEDU_JWT_SECRET", JWT),
            ("SHEDU_HMAC_SECRET", HMAC),
        ]))
        .expect("geçerli yapılandırma");
        let debug = format!("{config:?}");
        assert!(!debug.contains(JWT) && !debug.contains(HMAC) && !debug.contains("parola"));
    }
}
