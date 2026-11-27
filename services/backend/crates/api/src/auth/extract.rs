//! Kimliği doğrulanmış istek.
//!
//! Yalnızca `Authorization: Bearer <access token>` kabul edilir; token URL'de veya çerezde
//! aranmaz, böylece iki farklı kimlik taşıma biçimi çakışamaz (SES-01). Her istekte kullanıcının
//! hâlâ etkin olduğu ve oturumun iptal edilmediği veritabanından kontrol edilir: çıkış, oturum
//! kapatma ve parola sıfırlama, eski access token'ı da hemen geçersiz kılar (SES-04).

use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use uuid::Uuid;

use crate::{AppState, error::ApiError};

#[derive(Debug, Clone, Copy)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub session_id: Uuid,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized)?;

        let claims = state
            .tokens
            .verify_access(token)
            .map_err(|_| ApiError::Unauthorized)?;

        // Oturum kuralı bütün yüzeylerde aynı: `session_active` (aile, 90 gün, kullanıcı durumu).
        let (active,): (bool,) = sqlx::query_as("SELECT session_active($2, $1)")
            .bind(claims.sub)
            .bind(claims.sid)
            .fetch_one(&state.db)
            .await?;

        if !active {
            return Err(ApiError::Unauthorized);
        }
        Ok(Self {
            user_id: claims.sub,
            session_id: claims.sid,
        })
    }
}
