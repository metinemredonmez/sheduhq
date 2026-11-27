//! API hataları.
//!
//! İstemciye yalnızca sabit bir hata kodu döner; iç ayrıntı (SQL, yığın izi, kullanıcı var mı
//! yok mu) asla sızmaz. İç hatalar sunucu log'una kişisel veri içermeden yazılır.

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Debug)]
pub enum ApiError {
    /// İstek biçimi veya alanları geçersiz.
    BadRequest(&'static str),
    /// Kimlik doğrulanamadı. Neden (yanlış parola, bilinmeyen kullanıcı, iptal edilmiş oturum)
    /// bilerek ayırt edilmez.
    Unauthorized,
    NotFound,
    Conflict(&'static str),
    /// Deneme sınırı aşıldı.
    TooManyRequests {
        retry_after_secs: u64,
    },
    /// Beklenmeyen hata. Ayrıntı yalnızca sunucu log'una gider.
    Internal,
}

#[derive(Serialize)]
struct Body {
    error: &'static str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::BadRequest(code) => (StatusCode::BAD_REQUEST, code),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict(code) => (StatusCode::CONFLICT, code),
            Self::TooManyRequests { retry_after_secs } => {
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(Body {
                        error: "too_many_requests",
                    }),
                )
                    .into_response();
                if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                    response.headers_mut().insert(header::RETRY_AFTER, value);
                }
                return response;
            }
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        (status, Json(Body { error: code })).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        // Hata mesajı kişisel veri içerebilir (ör. benzersizlik ihlalinde değer); yalnızca tür ve
        // kod yazılır.
        let code = error
            .as_database_error()
            .and_then(|db| db.code().map(|c| c.into_owned()));
        tracing::error!(kind = error_kind(&error), code = ?code, "veritabanı hatası");
        Self::Internal
    }
}

fn error_kind(error: &sqlx::Error) -> &'static str {
    match error {
        sqlx::Error::Database(_) => "database",
        sqlx::Error::PoolTimedOut => "pool_timed_out",
        sqlx::Error::Io(_) => "io",
        sqlx::Error::RowNotFound => "row_not_found",
        _ => "other",
    }
}

/// Benzersizlik ihlali mi (SQLSTATE 23505)?
pub fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|db| db.code())
        .is_some_and(|code| code == "23505")
}

pub type ApiResult<T> = Result<T, ApiError>;
