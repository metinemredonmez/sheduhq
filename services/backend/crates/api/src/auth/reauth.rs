//! Hassas işlemlerden önce parolayla yeniden doğrulama (ör. sahiplik devri, MFA ayarı).
//!
//! Kullanıcı başına ayrı bir sayaçla sınırlanır; ele geçirilmiş bir oturumla parola tahmin
//! edilemez (AUT-02). Parolası olmayan hesapta sahte bir hash doğrulanır ve sonuç her zaman
//! olumsuzdur.

use uuid::Uuid;

use super::{password, rate_limit};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};

pub async fn verify_password(
    state: &AppState,
    user_id: Uuid,
    candidate: String,
) -> ApiResult<bool> {
    let mut conn = state.db.acquire().await?;
    rate_limit::hit(
        &mut conn,
        &state.hmac_secret,
        rate_limit::REAUTH_PER_USER,
        &user_id.to_string(),
    )
    .await?;
    let stored: Option<(Option<String>,)> =
        sqlx::query_as("SELECT password_hash FROM users WHERE id = $1 AND status = 'active'")
            .bind(user_id)
            .fetch_optional(&mut *conn)
            .await?;
    drop(conn);
    let has_password = matches!(stored, Some((Some(_),)));
    let stored = stored
        .and_then(|(hash,)| hash)
        .unwrap_or_else(|| state.dummy_hash.to_string());
    if candidate.chars().count() > password::MAX_CHARS {
        return Ok(false);
    }
    let matched = tokio::task::spawn_blocking(move || password::verify(&candidate, &stored))
        .await
        .map_err(|_| ApiError::Internal)?;
    Ok(has_password && matched)
}
