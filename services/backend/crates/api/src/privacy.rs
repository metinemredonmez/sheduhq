//! Kişisel veriler (KVKK md. 11): kişinin kendi verisini dışa aktarması ve hesabını silmesi.
//!
//! Her iki işlem de parolayla yeniden doğrulama ve faktör açıksa ikinci adımı tamamlanmış oturum
//! ister; ele geçirilmiş bir access token ile bütün kişisel veri tek seferde alınamaz, hesap
//! silinemez (AUT-04).
//!
//! Dışa aktarma (DAT-02, AZ-03): yalnızca kullanıcının kendi verisi. Başka kişilerin kimliği,
//! numarası veya olay ayrıntısı girmez; push token'ları ve faktör sırları girmez. Dosya sunucuda
//! saklanmaz, yanıt önbelleğe alınmaz (`no-store`). Kullanıcı başına günde 3 kez.
//!
//! Silme: veritabanındaki `erase_account()` tek işlemde yapar (bkz. migration 0008). Başka üyesi
//! olan organizasyonun sahibi önce sahipliği devretmelidir.

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    AppState, audit,
    auth::{AuthUser, mfa, rate_limit},
    db::set_context,
    error::{ApiError, ApiResult},
};

/// Dışa aktarılan komut ve güvenlik olayı sayısı üst sınırı (veritabanı da uygular).
const MAX_ROWS: i32 = 10_000;
const SMS_ERASED: &str = "Shedu: Hesabınız ve kişisel verileriniz silindi. Bunu siz yapmadıysanız \
                          hemen destek ile iletişime geçin.";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/me/data-export", post(export))
        .route("/me/delete", post(delete_account))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordRequest {
    password: String,
}

#[derive(Serialize, sqlx::FromRow)]
struct UserData {
    id: Uuid,
    display_name: String,
    phone: Option<String>,
    email: Option<String>,
    status: String,
    created_at: DateTime<Utc>,
}

#[derive(Serialize, sqlx::FromRow)]
struct OrganizationData {
    id: Uuid,
    name: String,
    kind: String,
    role: String,
    joined_at: DateTime<Utc>,
}

#[derive(Serialize, sqlx::FromRow)]
struct DeviceData {
    id: Uuid,
    platform: String,
    name: Option<String>,
    push_registered: bool,
    created_at: DateTime<Utc>,
    last_seen_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, sqlx::FromRow)]
struct SessionData {
    id: Uuid,
    device_id: Option<Uuid>,
    started_at: DateTime<Utc>,
    last_active_at: DateTime<Utc>,
    active: bool,
    second_factor: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
struct GrantData {
    id: Uuid,
    organization_id: Uuid,
    panel_id: Uuid,
    partition_id: Option<Uuid>,
    can_view_events: bool,
    can_arm: bool,
    can_disarm: bool,
    can_bypass: bool,
    always_open: bool,
    valid_from: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    #[sqlx(skip)]
    windows: Vec<WindowData>,
}

#[derive(Serialize, sqlx::FromRow)]
struct WindowData {
    #[serde(skip)]
    grant_id: Uuid,
    day: i16,
    start_minute: i16,
    end_minute: i16,
}

#[derive(Serialize, sqlx::FromRow)]
struct CommandData {
    id: Uuid,
    organization_id: Uuid,
    panel_id: Uuid,
    partition_id: Uuid,
    kind: String,
    zones: Option<Vec<i16>>,
    status: String,
    rejection_reason: Option<String>,
    requested_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, sqlx::FromRow)]
struct SecurityEvent {
    organization_id: Option<Uuid>,
    action: String,
    outcome: String,
    /// Olayı kişinin kendisi mi yaptı (yoksa kişiye yönelik mi)?
    by_me: bool,
    created_at: DateTime<Utc>,
}

/// Ortak ön koşul: faktör açıksa doğrulanmış oturum, sonra parola.
async fn reauthenticate(
    state: &AppState,
    user: AuthUser,
    password: String,
    action: &'static str,
) -> ApiResult<()> {
    {
        let mut conn = state.db.acquire().await?;
        mfa::step_up(&mut conn, user).await?;
    }
    mfa::require_password(state, user.user_id, password, action).await
}

pub async fn export(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<PasswordRequest>,
) -> ApiResult<Response> {
    reauthenticate(&state, user, request.password, "privacy.export").await?;
    {
        let mut conn = state.db.acquire().await?;
        rate_limit::hit(
            &mut conn,
            &state.hmac_secret,
            rate_limit::PRIVACY_EXPORT_PER_USER,
            &user.user_id.to_string(),
        )
        .await?;
    }

    let mut tx = state.db.begin().await?;
    set_context(&mut tx, Some(user.user_id), None).await?;
    let profile: UserData = sqlx::query_as(
        "SELECT id, display_name, phone, email, status, created_at FROM users WHERE id = $1",
    )
    .bind(user.user_id)
    .fetch_one(&mut *tx)
    .await?;
    let organizations: Vec<OrganizationData> = sqlx::query_as(
        "SELECT o.id, o.name, o.kind, m.role, m.created_at AS joined_at
           FROM memberships m JOIN organizations o ON o.id = m.organization_id
          WHERE m.user_id = $1 ORDER BY m.created_at",
    )
    .bind(user.user_id)
    .fetch_all(&mut *tx)
    .await?;
    let devices: Vec<DeviceData> = sqlx::query_as(
        "SELECT id, platform, name, push_token IS NOT NULL AS push_registered, created_at, last_seen_at
           FROM user_devices WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(user.user_id)
    .fetch_all(&mut *tx)
    .await?;
    let sessions: Vec<SessionData> = sqlx::query_as(
        "SELECT r.family_id AS id, min(r.device_id::text)::uuid AS device_id,
                min(r.created_at) AS started_at, max(r.created_at) AS last_active_at,
                bool_or(r.revoked_at IS NULL AND r.used_at IS NULL AND r.expires_at > now()) AS active,
                min(f.method) AS second_factor
           FROM refresh_tokens r LEFT JOIN session_factors f ON f.family_id = r.family_id
          WHERE r.user_id = $1
          GROUP BY r.family_id
          ORDER BY started_at",
    )
    .bind(user.user_id)
    .fetch_all(&mut *tx)
    .await?;
    let (totp, recovery_remaining): (Option<bool>, i64) = sqlx::query_as(
        "SELECT (SELECT confirmed_at IS NOT NULL FROM user_totp WHERE user_id = $1),
                (SELECT count(*) FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL)",
    )
    .bind(user.user_id)
    .fetch_one(&mut *tx)
    .await?;

    // Panel yetkileri kiracı tablolarında: her üyelik kendi kiracı bağlamıyla okunur.
    let mut grants: Vec<GrantData> = Vec::new();
    for organization in &organizations {
        set_context(&mut tx, Some(user.user_id), Some(organization.id)).await?;
        let mut rows: Vec<GrantData> = sqlx::query_as(
            "SELECT id, organization_id, panel_id, partition_id, can_view_events, can_arm,
                    can_disarm, can_bypass, always_open, valid_from, expires_at
               FROM access_grants WHERE user_id = $1 ORDER BY created_at",
        )
        .bind(user.user_id)
        .fetch_all(&mut *tx)
        .await?;
        let ids: Vec<Uuid> = rows.iter().map(|g| g.id).collect();
        let windows: Vec<WindowData> = sqlx::query_as(
            "SELECT grant_id, day, start_minute, end_minute FROM access_windows
              WHERE grant_id = ANY($1) ORDER BY day, start_minute",
        )
        .bind(&ids)
        .fetch_all(&mut *tx)
        .await?;
        for grant in &mut rows {
            grant.windows = windows
                .iter()
                .filter(|w| w.grant_id == grant.id)
                .map(|w| WindowData {
                    grant_id: w.grant_id,
                    day: w.day,
                    start_minute: w.start_minute,
                    end_minute: w.end_minute,
                })
                .collect();
        }
        grants.append(&mut rows);
    }

    set_context(&mut tx, Some(user.user_id), None).await?;
    let commands: Vec<CommandData> = sqlx::query_as("SELECT * FROM privacy_my_commands($1)")
        .bind(MAX_ROWS)
        .fetch_all(&mut *tx)
        .await?;
    let security_events: Vec<SecurityEvent> = sqlx::query_as("SELECT * FROM privacy_my_audit($1)")
        .bind(MAX_ROWS)
        .fetch_all(&mut *tx)
        .await?;
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: None,
            actor_user_id: Some(user.user_id),
            action: "privacy.exported",
            target_type: Some("user"),
            target_id: Some(&user.user_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({ "commands": commands.len(), "security_events": security_events.len() }),
        },
    )
    .await?;
    tx.commit().await?;

    let truncated =
        commands.len() >= MAX_ROWS as usize || security_events.len() >= MAX_ROWS as usize;
    let body = json!({
        "format": "shedu-personal-data/v1",
        "generated_at": Utc::now(),
        "user": profile,
        "organizations": organizations,
        "devices": devices,
        "sessions": sessions,
        "mfa": {
            "totp": match totp { None => "none", Some(false) => "pending", Some(true) => "enabled" },
            "recovery_codes_remaining": recovery_remaining,
        },
        "access_grants": grants,
        "commands": commands,
        "security_events": security_events,
        "truncated": truncated,
    });
    let mut response = Json(body).into_response();
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"shedu-kisisel-veriler.json\""),
    );
    Ok(response)
}

pub async fn delete_account(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<PasswordRequest>,
) -> ApiResult<Response> {
    reauthenticate(&state, user, request.password, "privacy.erase").await?;

    let mut tx = state.db.begin().await?;
    set_context(&mut tx, Some(user.user_id), None).await?;
    // Başka üyesi olan organizasyonların sahibi: hangi organizasyonlar olduğu söylenir.
    let shared: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT m.organization_id FROM memberships m
          WHERE m.user_id = $1 AND m.role = 'owner'
            AND EXISTS (SELECT 1 FROM memberships o
                         WHERE o.organization_id = m.organization_id AND o.user_id <> $1)
          ORDER BY m.organization_id",
    )
    .bind(user.user_id)
    .fetch_all(&mut *tx)
    .await?;
    if !shared.is_empty() {
        let organizations: Vec<Uuid> = shared.into_iter().map(|(id,)| id).collect();
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({ "error": "transfer_ownership_first", "organizations": organizations })),
        )
            .into_response());
    }

    let phone = mfa::phone_of(&mut tx, user.user_id).await?;
    let erased: Result<(serde_json::Value,), sqlx::Error> =
        sqlx::query_as("SELECT erase_account()")
            .fetch_one(&mut *tx)
            .await;
    let (summary,) = match erased {
        Ok(row) => row,
        // Arada biri organizasyona katıldıysa veritabanı reddeder.
        Err(error)
            if error
                .as_database_error()
                .and_then(|e| e.code())
                .is_some_and(|code| code == "23001") =>
        {
            return Err(ApiError::Conflict("transfer_ownership_first"));
        }
        Err(error) => return Err(error.into()),
    };
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: None,
            actor_user_id: Some(user.user_id),
            action: "privacy.account_erased",
            target_type: Some("user"),
            target_id: Some(&user.user_id.to_string()),
            outcome: audit::Outcome::Success,
            details: summary,
        },
    )
    .await?;
    tx.commit().await?;
    mfa::notify(&state, phone, SMS_ERASED);
    Ok(StatusCode::NO_CONTENT.into_response())
}
