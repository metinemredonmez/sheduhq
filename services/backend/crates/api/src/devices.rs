//! Bu oturumun cihazına push token'ı kaydetme ve silme.
//!
//! Aynı token başka bir hesaba kayıtlıysa oradan silinir: cihaz el değiştirdiğinde eski sahibinin
//! alarmları yeni kullanıcıya gitmez. Çıkışta ve oturum kapatılınca token da silinir.
//!
//! Token'ın biçimi cihazın platformuna göre kayıtta denetlenir (iOS: APNs onaltılık token,
//! Android: FCM kayıt token'ı). Hatalı kayıt ilk alarma kadar gizli kalmaz, istemci hemen
//! `400 invalid_push_token` alır. Push sağlayıcısı olmayan platform (`web`) `400
//! push_not_supported` alır.

use axum::{Json, Router, extract::State, http::StatusCode, routing::put};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult},
    providers::{apns, fcm},
};

pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/devices/current/push-token",
        put(set_push_token).delete(clear_push_token),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushTokenRequest {
    token: String,
}

async fn current_device(conn: &mut sqlx::PgConnection, user: AuthUser) -> ApiResult<Uuid> {
    let device: Option<(Option<Uuid>,)> = sqlx::query_as(
        "SELECT device_id FROM refresh_tokens WHERE family_id = $1 AND user_id = $2 LIMIT 1",
    )
    .bind(user.session_id)
    .bind(user.user_id)
    .fetch_optional(conn)
    .await?;
    device.and_then(|(id,)| id).ok_or(ApiError::NotFound)
}

pub async fn set_push_token(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<PushTokenRequest>,
) -> ApiResult<StatusCode> {
    let token = request.token.trim();
    if token.is_empty() || token.len() > 4096 || token.chars().any(char::is_whitespace) {
        return Err(ApiError::BadRequest("invalid_push_token"));
    }
    let mut tx = state.db.begin().await?;
    let device_id = current_device(&mut tx, user).await?;
    let (platform,): (String,) =
        sqlx::query_as("SELECT platform FROM user_devices WHERE id = $1 AND user_id = $2")
            .bind(device_id)
            .bind(user.user_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ApiError::NotFound)?;
    let valid = match platform.as_str() {
        "ios" => apns::valid_device_token(token),
        "android" => fcm::valid_device_token(token),
        _ => return Err(ApiError::BadRequest("push_not_supported")),
    };
    if !valid {
        return Err(ApiError::BadRequest("invalid_push_token"));
    }
    sqlx::query("UPDATE user_devices SET push_token = NULL WHERE push_token = $1 AND id <> $2")
        .bind(token)
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE user_devices SET push_token = $1, last_seen_at = now() WHERE id = $2 AND user_id = $3")
        .bind(token)
        .bind(device_id)
        .bind(user.user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn clear_push_token(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<StatusCode> {
    let mut tx = state.db.begin().await?;
    let device_id = current_device(&mut tx, user).await?;
    sqlx::query("UPDATE user_devices SET push_token = NULL WHERE id = $1 AND user_id = $2")
        .bind(device_id)
        .bind(user.user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
