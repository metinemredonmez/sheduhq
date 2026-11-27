//! Kişisel verinin düzeltilmesi (KVKK md. 11): görünen ad ve telefon numarası.
//!
//! Numara hesabın kimliğidir (giriş, parola sıfırlama, davet): değişim parolayla yeniden doğrulama,
//! faktör açıksa ikinci adımı tamamlanmış oturum ve yeni numaraya gönderilen SMS koduyla olur.
//! Yeni numara başka bir hesaba aitse kod gönderilmez ama yanıt aynıdır; numaranın kayıtlı olup
//! olmadığı belli olmaz. Değişiklik eski numaraya bildirilir. Denetim kaydına numara yazılmaz.

use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::json;

use super::{
    AuthUser,
    codes::Purpose,
    handlers::{consume_code, ip_of, issue_code, normalize_phone},
    mfa, rate_limit,
};
use crate::{
    AppState, audit,
    error::{ApiError, ApiResult, is_unique_violation},
};

const SMS_PHONE_CHANGED: &str = "Shedu: Hesabınızın telefon numarası değiştirildi. Bunu siz \
                                 yapmadıysanız hemen destek ile iletişime geçin.";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateRequest {
    display_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneStartRequest {
    new_phone: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneCompleteRequest {
    new_phone: String,
    code: String,
}

/// Görünen adı düzeltir.
pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<UpdateRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let display_name = request.display_name.trim().to_owned();
    if display_name.is_empty()
        || display_name.chars().count() > 100
        || display_name.chars().any(char::is_control)
    {
        return Err(ApiError::BadRequest("invalid_display_name"));
    }
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "UPDATE users SET display_name = $2, updated_at = now() WHERE id = $1 AND status = 'active'",
    )
    .bind(user.user_id)
    .bind(&display_name)
    .execute(&mut *tx)
    .await?;
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: None,
            actor_user_id: Some(user.user_id),
            action: "profile.updated",
            target_type: Some("user"),
            target_id: Some(&user.user_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({ "fields": ["display_name"] }),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({ "display_name": display_name })))
}

/// Numara değişimini başlatır: yeni numaraya kod gönderir. Her zaman 202.
pub async fn phone_start(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    user: AuthUser,
    Json(request): Json<PhoneStartRequest>,
) -> ApiResult<StatusCode> {
    let new_phone =
        normalize_phone(&request.new_phone).ok_or(ApiError::BadRequest("invalid_phone"))?;
    {
        let mut conn = state.db.acquire().await?;
        mfa::step_up(&mut conn, user).await?;
        let current = mfa::phone_of(&mut conn, user.user_id).await?;
        if current.as_deref() == Some(new_phone.as_str()) {
            return Err(ApiError::BadRequest("same_phone"));
        }
    }
    mfa::require_password(
        &state,
        user.user_id,
        request.password,
        "profile.phone_change",
    )
    .await?;

    let mut conn = state.db.acquire().await?;
    for (budget, value) in [
        (rate_limit::PHONE_CHANGE_PER_USER, user.user_id.to_string()),
        (rate_limit::SMS_PER_IP, ip_of(&addr)),
        (rate_limit::SMS_PER_PHONE, new_phone.clone()),
        (rate_limit::SMS_GLOBAL, "all".to_owned()),
    ] {
        rate_limit::hit(&mut conn, &state.hmac_secret, budget, &value).await?;
    }
    let taken: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM users WHERE phone = $1")
        .bind(&new_phone)
        .fetch_optional(&mut *conn)
        .await?;
    if taken.is_none() {
        issue_code(
            &state,
            &mut conn,
            Purpose::PhoneChange,
            &new_phone,
            Some(user.user_id),
        )
        .await?;
    }
    Ok(StatusCode::ACCEPTED)
}

/// Numara değişimini kodla tamamlar. Kod, değişimi başlatan kullanıcıya bağlıdır.
pub async fn phone_complete(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    user: AuthUser,
    Json(request): Json<PhoneCompleteRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let new_phone =
        normalize_phone(&request.new_phone).ok_or(ApiError::BadRequest("invalid_phone"))?;
    {
        let mut conn = state.db.acquire().await?;
        mfa::step_up(&mut conn, user).await?;
        rate_limit::hit(
            &mut conn,
            &state.hmac_secret,
            rate_limit::VERIFY_PER_IP,
            &ip_of(&addr),
        )
        .await?;
    }
    let bound = consume_code(&state, Purpose::PhoneChange, &new_phone, &request.code).await?;
    if bound != Some(user.user_id) {
        return Err(ApiError::BadRequest("invalid_code"));
    }

    let mut tx = state.db.begin().await?;
    let old_phone = mfa::phone_of(&mut tx, user.user_id).await?;
    let updated = sqlx::query(
        "UPDATE users SET phone = $2, updated_at = now() WHERE id = $1 AND status = 'active'",
    )
    .bind(user.user_id)
    .bind(&new_phone)
    .execute(&mut *tx)
    .await;
    match updated {
        Err(error) if is_unique_violation(&error) => {
            return Err(ApiError::Conflict("phone_in_use"));
        }
        other => {
            other?;
        }
    }
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: None,
            actor_user_id: Some(user.user_id),
            action: "profile.phone_changed",
            target_type: Some("user"),
            target_id: Some(&user.user_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({}),
        },
    )
    .await?;
    tx.commit().await?;
    mfa::notify(&state, old_phone, SMS_PHONE_CHANGED);
    Ok(Json(json!({ "phone": new_phone })))
}
