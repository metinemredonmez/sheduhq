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

        let active: Option<(i32,)> = sqlx::query_as(
            "SELECT 1 FROM users u
              WHERE u.id = $1 AND u.status = 'active'
                AND EXISTS (SELECT 1 FROM refresh_tokens r
                             WHERE r.family_id = $2 AND r.user_id = $1 AND r.revoked_at IS NULL)",
        )
        .bind(claims.sub)
        .bind(claims.sid)
        .fetch_optional(&state.db)
        .await?;

        if active.is_none() {
            return Err(ApiError::Unauthorized);
        }
        Ok(Self {
            user_id: claims.sub,
            session_id: claims.sid,
        })
    }
}
