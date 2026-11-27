//! Access token (JWT) ve refresh token.
//!
//! Access token (TOK-01):
//! - Yalnızca HS256 kabul edilir; başlıktaki `alg` bundan farklıysa reddedilir.
//! - `iss`, `aud`, `exp`, `iat`, `sub` zorunludur; `typ` alanı "access" olmalıdır, başka amaçla
//!   üretilmiş bir token access token yerine geçemez.
//! - Ömür 10 dakika. `sid` oturum (refresh ailesi) kimliğidir; her istekte sunucuda oturumun iptal
//!   edilmediği kontrol edilir (SES-04).
//!
//! Refresh token: 32 rastgele bayt (base64url). Veritabanında yalnızca SHA-256 özeti tutulur.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const ISSUER: &str = "shedu";
pub const AUDIENCE: &str = "shedu-api";
const TOKEN_TYPE_ACCESS: &str = "access";
pub const ACCESS_TTL_SECS: i64 = 10 * 60;
pub const REFRESH_TTL_DAYS: i64 = 30;
/// Oturumun (refresh ailesi) mutlak ömrü: yenileme ile uzamaz; dolunca yeniden giriş gerekir
/// (SES-03).
pub const SESSION_MAX_DAYS: i32 = 90;
const LEEWAY_SECS: u64 = 5;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessClaims {
    pub iss: String,
    pub aud: String,
    /// Kullanıcı kimliği.
    pub sub: Uuid,
    /// Oturum (refresh ailesi) kimliği.
    pub sid: Uuid,
    pub iat: i64,
    pub exp: i64,
    pub jti: Uuid,
    pub typ: String,
}

#[derive(Clone)]
pub struct TokenKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
    validation: Validation,
}

#[derive(Debug)]
pub struct TokenError;

impl TokenKeys {
    pub fn new(secret: &[u8]) -> Result<Self, TokenError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.algorithms = vec![Algorithm::HS256];
        validation.set_issuer(&[ISSUER]);
        validation.set_audience(&[AUDIENCE]);
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);
        validation.leeway = LEEWAY_SECS;
        validation.validate_exp = true;
        Ok(Self {
            encoding: EncodingKey::from_secret(secret).map_err(|_| TokenError)?,
            decoding: DecodingKey::from_secret(secret).map_err(|_| TokenError)?,
            validation,
        })
    }

    /// Yeni access token üretir; token ve saniye cinsinden ömrünü döner.
    pub fn issue_access(&self, user_id: Uuid, session_id: Uuid) -> Result<String, TokenError> {
        let now = Utc::now().timestamp();
        let claims = AccessClaims {
            iss: ISSUER.to_owned(),
            aud: AUDIENCE.to_owned(),
            sub: user_id,
            sid: session_id,
            iat: now,
            exp: now + ACCESS_TTL_SECS,
            jti: Uuid::new_v4(),
            typ: TOKEN_TYPE_ACCESS.to_owned(),
        };
        self.encode(&claims)
    }

    fn encode(&self, claims: &AccessClaims) -> Result<String, TokenError> {
        jsonwebtoken::encode(&Header::new(Algorithm::HS256), claims, &self.encoding)
            .map_err(|_| TokenError)
    }

    /// Access token'ı doğrular. Her başarısızlık aynı hatayı döner.
    pub fn verify_access(&self, token: &str) -> Result<AccessClaims, TokenError> {
        let data = jsonwebtoken::decode::<AccessClaims>(token, &self.decoding, &self.validation)
            .map_err(|_| TokenError)?;
        if data.claims.typ != TOKEN_TYPE_ACCESS || data.header.alg != Algorithm::HS256 {
            return Err(TokenError);
        }
        Ok(data.claims)
    }
}

/// Yeni refresh token: (istemciye verilecek değer, veritabanında saklanacak SHA-256 özeti).
pub fn new_refresh_token() -> Result<(String, Vec<u8>), TokenError> {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(|_| TokenError)?;
    Ok((URL_SAFE_NO_PAD.encode(raw), Sha256::digest(raw).to_vec()))
}

/// İstemcinin gönderdiği refresh token'ın özeti. Biçim yanlışsa `None`.
pub fn refresh_token_hash(token: &str) -> Option<Vec<u8>> {
    let raw = URL_SAFE_NO_PAD.decode(token.as_bytes()).ok()?;
    (raw.len() == 32).then(|| Sha256::digest(&raw).to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-jwt-secret-0123456789abcdefghij";

    fn keys() -> TokenKeys {
        TokenKeys::new(SECRET).expect("anahtar")
    }

    fn valid_claims() -> AccessClaims {
        let now = Utc::now().timestamp();
        AccessClaims {
            iss: ISSUER.into(),
            aud: AUDIENCE.into(),
            sub: Uuid::new_v4(),
            sid: Uuid::new_v4(),
            iat: now,
            exp: now + 60,
            jti: Uuid::new_v4(),
            typ: TOKEN_TYPE_ACCESS.into(),
        }
    }

    #[test]
    fn issued_token_verifies() {
        let keys = keys();
        let (user, session) = (Uuid::new_v4(), Uuid::new_v4());
        let token = keys.issue_access(user, session).expect("token");
        let claims = keys.verify_access(&token).expect("geçerli");
        assert_eq!((claims.sub, claims.sid), (user, session));
        assert_eq!(claims.exp - claims.iat, ACCESS_TTL_SECS);
    }

    #[test]
    fn wrong_issuer_audience_type_or_expiry_is_rejected() {
        let keys = keys();
        let mutations: [fn(&mut AccessClaims); 4] = [
            |c| c.iss = "baskasi".into(),
            |c| c.aud = "baska-servis".into(),
            |c| c.typ = "refresh".into(),
            |c| {
                c.iat -= 3600;
                c.exp = Utc::now().timestamp() - 60;
            },
        ];
        for mutate in mutations {
            let mut claims = valid_claims();
            mutate(&mut claims);
            let token = keys.encode(&claims).expect("token");
            assert!(keys.verify_access(&token).is_err(), "{claims:?}");
        }
    }

    #[test]
    fn token_signed_with_another_key_is_rejected() {
        let other = TokenKeys::new(b"another-secret-0123456789abcdefghijk").expect("anahtar");
        let token = other.encode(&valid_claims()).expect("token");
        assert!(keys().verify_access(&token).is_err());
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let keys = keys();
        let token = keys.encode(&valid_claims()).expect("token");
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        let mut claims = valid_claims();
        claims.sub = Uuid::new_v4();
        parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("json"));
        assert!(keys.verify_access(&parts.join(".")).is_err());
    }

    #[test]
    fn alg_none_and_other_algorithms_are_rejected() {
        let keys = keys();
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&valid_claims()).expect("json"));
        for header in [
            r#"{"alg":"none","typ":"JWT"}"#,
            r#"{"alg":"HS512","typ":"JWT"}"#,
        ] {
            let token = format!("{}.{payload}.", URL_SAFE_NO_PAD.encode(header));
            assert!(keys.verify_access(&token).is_err(), "{header}");
        }
        let hs512 = jsonwebtoken::encode(
            &Header::new(Algorithm::HS512),
            &valid_claims(),
            &EncodingKey::from_secret(SECRET).expect("anahtar"),
        )
        .expect("token");
        assert!(keys.verify_access(&hs512).is_err());
    }

    #[test]
    fn refresh_token_hash_matches_and_rejects_garbage() {
        let (token, stored) = new_refresh_token().expect("token");
        assert_eq!(refresh_token_hash(&token), Some(stored));
        assert_eq!(refresh_token_hash("kisa"), None);
        assert_eq!(refresh_token_hash("!!!geçersiz!!!"), None);
    }
}
