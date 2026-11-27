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
//! Silme: talep hesabı hemen kapatır (oturumlar, push token'ları) ve silmeyi 30 gün sonraya
//! planlar; kişi bu sürede tam doğrulamayla giriş yaparsa talep iptal olur. Süre dolunca silme işi
//! veritabanındaki `erase_account()`'ı tek işlemde çalıştırır (bkz. migration 0008, 0009). Başka
//! üyesi olan organizasyonun sahibi önce sahipliği devretmelidir.
//!
//! Rıza defteri: amaç başına verme ve geri çekme kayıtları yalnızca eklenir; güncel durum son
//! kayıttır. Eski metin sürümüne verilen yanıt kabul edilmez.

use std::time::Duration;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{
    AppState, audit,
    auth::{AuthUser, handlers::revoke_user_sessions, mfa, rate_limit},
    db::set_context,
    error::{ApiError, ApiResult},
    invitations,
};

/// Dışa aktarılan komut ve güvenlik olayı sayısı üst sınırı (veritabanı da uygular).
const MAX_ROWS: i32 = 10_000;
/// Silme talebinden kalıcı silmeye kadar geçen süre.
pub const ERASURE_GRACE_DAYS: i32 = 30;
const SMS_SCHEDULED: &str = "Shedu: Hesabınız 30 gün sonra kalıcı olarak silinecek. Vazgeçerseniz \
                             bu süre içinde giriş yapmanız yeterli.";
pub(crate) const SMS_ERASURE_CANCELLED: &str = "Shedu: Hesap silme talebiniz girişinizle iptal \
                                                edildi. Bunu siz yapmadıysanız hemen parolanızı \
                                                değiştirin.";
const SMS_ERASED: &str = "Shedu: Hesabınız ve kişisel verileriniz silindi. Bunu siz yapmadıysanız \
                          hemen destek ile iletişime geçin.";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/me/data-export", post(export))
        .route("/me/delete", post(delete_account))
        .route("/me/consents", get(list_consents).post(record_consent))
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
struct ConsentRecord {
    purpose: String,
    version: String,
    granted: bool,
    platform: Option<String>,
    recorded_at: DateTime<Utc>,
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

/// Kurumsal personel (işletme veya izleme merkezinde sahip, yönetici, operatör) organizasyon
/// verisine yalnızca ikinci adımı tamamlanmış oturumla erişir (AUT-01; kural
/// `authz::mfa_required` ile aynı). Dışa aktarma bu organizasyonlardaki yetki ve komut
/// kayıtlarını da içerdiği için aynı kural burada da geçerlidir: faktörü henüz kurulmamış
/// personel önce faktörü kurar.
///
/// Denetim verinin okunduğu işlemde yapılır ve üyelikler işlem sonuna kadar paylaşımlı kilitlenir:
/// arada personel rolüne yükseltilen üyenin çıktısı da bu kurala tabidir (Y06). Çağıran işlem kişi
/// bağlamıyla açılmış olmalı.
async fn ensure_staff_factor(conn: &mut PgConnection, user: AuthUser) -> ApiResult<()> {
    let roles: Vec<(String, String)> = sqlx::query_as(
        "SELECT o.kind, m.role FROM memberships m JOIN organizations o ON o.id = m.organization_id
          WHERE m.user_id = $1
          ORDER BY m.organization_id
            FOR SHARE OF m",
    )
    .bind(user.user_id)
    .fetch_all(&mut *conn)
    .await?;
    let staff = roles.iter().any(|(kind, role)| {
        matches!(kind.as_str(), "business" | "monitoring_center")
            && matches!(role.as_str(), "owner" | "admin" | "operator")
    });
    if !staff {
        return Ok(());
    }
    let (verified,): (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM session_factors WHERE family_id = $2 AND user_id = $1)",
    )
    .bind(user.user_id)
    .bind(user.session_id)
    .fetch_one(&mut *conn)
    .await?;
    if !verified {
        return Err(ApiError::Forbidden("mfa_required"));
    }
    Ok(())
}

pub async fn export(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<PasswordRequest>,
) -> ApiResult<Response> {
    // Parola denemesinden önce erken red (personelin faktörü yoksa parola sorulmaz); kesin denetim
    // aşağıda, verinin okunduğu işlemde.
    {
        let mut tx = state.db.begin().await?;
        set_context(&mut tx, Some(user.user_id), None).await?;
        ensure_staff_factor(&mut tx, user).await?;
        tx.commit().await?;
    }
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
    ensure_staff_factor(&mut tx, user).await?;
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
    // Etkin oturum kuralı HTTP ve push ile aynı (`session_active`).
    let sessions: Vec<SessionData> = sqlx::query_as(
        "SELECT s.id, s.device_id, s.created_at AS started_at,
                coalesce((SELECT max(r.created_at) FROM refresh_tokens r WHERE r.family_id = s.id),
                         s.created_at) AS last_active_at,
                session_active(s.id, s.user_id) AS active,
                f.method AS second_factor
           FROM session_families s LEFT JOIN session_factors f ON f.family_id = s.id
          WHERE s.user_id = $1
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
               FROM access_grants WHERE user_id = $1 AND organization_id = $2 ORDER BY created_at",
        )
        .bind(user.user_id)
        .bind(organization.id)
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
    let consents: Vec<ConsentRecord> = sqlx::query_as(
        "SELECT purpose, version, granted, platform, recorded_at FROM consent_records
          WHERE user_id = $1 ORDER BY recorded_at, id",
    )
    .bind(user.user_id)
    .fetch_all(&mut *tx)
    .await?;
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
        "consents": consents,
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

/// Silme talebi: hesabı hemen kapatır ve kalıcı silmeyi 30 gün sonraya planlar.
pub async fn delete_account(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<PasswordRequest>,
) -> ApiResult<Response> {
    reauthenticate(&state, user, request.password, "privacy.erase").await?;

    let mut tx = state.db.begin().await?;
    set_context(&mut tx, Some(user.user_id), None).await?;
    // Hesap satırı önce kilitlenir. Bu kişinin davetinin kabulü ve bu kişiye sahiplik devri hesap
    // satırını paylaşımlı kilitler: ya talepten önce biter (aşağıdaki denetim yeni üyeyi veya
    // sahipliği görür) ya da talepten sonra sıralanır ve kapanmış hesabı görüp reddedilir (AZ-03).
    let active: Option<(i32,)> =
        sqlx::query_as("SELECT 1 FROM users WHERE id = $1 AND status = 'active' FOR NO KEY UPDATE")
            .bind(user.user_id)
            .fetch_optional(&mut *tx)
            .await?;
    if active.is_none() {
        return Err(ApiError::Unauthorized);
    }
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

    let scheduled: Option<(DateTime<Utc>,)> = sqlx::query_as(
        "UPDATE users
            SET status = 'pending_deletion', updated_at = now(),
                deletion_due_at = now() + make_interval(days => $2)
          WHERE id = $1 AND status = 'active'
          RETURNING deletion_due_at",
    )
    .bind(user.user_id)
    .bind(ERASURE_GRACE_DAYS)
    .fetch_optional(&mut *tx)
    .await?;
    let (due,) = scheduled.ok_or(ApiError::Unauthorized)?;
    // Hesap hemen kapanır: bütün oturumlar biter, cihazlara bildirim gitmez (SES-04).
    revoke_user_sessions(&mut tx, user.user_id, None).await?;
    // Gönderdiği açık davetler iptal edilir: kabul edilirse organizasyon tek üyeli olmaktan çıkar
    // ve kalıcı silme takılır. Davetler kiracı verisidir; her organizasyon kendi bağlamında.
    let organizations: Vec<(Uuid,)> =
        sqlx::query_as("SELECT organization_id FROM memberships WHERE user_id = $1")
            .bind(user.user_id)
            .fetch_all(&mut *tx)
            .await?;
    let mut revoked_invitations = 0;
    for (organization_id,) in organizations {
        set_context(&mut tx, Some(user.user_id), Some(organization_id)).await?;
        revoked_invitations +=
            invitations::revoke_sent_by(&mut tx, organization_id, user.user_id).await?;
    }
    set_context(&mut tx, Some(user.user_id), None).await?;
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: None,
            actor_user_id: Some(user.user_id),
            action: "privacy.erasure_scheduled",
            target_type: Some("user"),
            target_id: Some(&user.user_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({ "deletion_due_at": due, "invitations_revoked": revoked_invitations }),
        },
    )
    .await?;
    let phone = mfa::phone_of(&mut tx, user.user_id).await?;
    tx.commit().await?;
    mfa::notify(&state, phone, SMS_SCHEDULED);
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "deletion_due_at": due })),
    )
        .into_response())
}

/// Bekleyen silme talebini iptal eder (tam doğrulamalı girişte, oturum açılmadan önce çağrılır).
/// İptal edildiyse `true`. Talep yalnızca 30 günlük süre içinde geri alınabilir: süresi dolmuş
/// (silme işinin henüz işlemediği) hesapla giriş reddedilir. Silme işi hesap satırını kilitler;
/// iptal onunla sıralanır (DAT-05). Süre karar anına (`clock_timestamp()`) göre denetlenir, işlem
/// başına göre değil: kilidi beklerken süre dolduysa talep geri alınmaz (Y06).
pub(crate) async fn cancel_scheduled_erasure(
    conn: &mut PgConnection,
    user_id: Uuid,
) -> ApiResult<bool> {
    let cancelled = sqlx::query(
        "UPDATE users SET status = 'active', deletion_due_at = NULL, updated_at = now()
          WHERE id = $1 AND status = 'pending_deletion' AND deletion_due_at > clock_timestamp()",
    )
    .bind(user_id)
    .execute(&mut *conn)
    .await?
    .rows_affected()
        == 1;
    if !cancelled {
        let (active,): (bool,) = sqlx::query_as(
            "SELECT coalesce(bool_or(status = 'active'), false) FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;
        if !active {
            return Err(ApiError::Unauthorized);
        }
    }
    if cancelled {
        audit::record(
            conn,
            audit::Event {
                organization_id: None,
                actor_user_id: Some(user_id),
                action: "privacy.erasure_cancelled",
                target_type: Some("user"),
                target_id: Some(&user_id.to_string()),
                outcome: audit::Outcome::Success,
                details: json!({}),
            },
        )
        .await?;
    }
    Ok(cancelled)
}

/// Süresi dolan silme taleplerini uygular; silinen hesap sayısını döner. Birden fazla API kopyası
/// aynı anda çalışabilir: her hesap `SKIP LOCKED` ile tek kopya tarafından işlenir.
pub async fn erase_due_accounts(state: &AppState) -> ApiResult<usize> {
    let mut erased = 0;
    let mut failed: Vec<Uuid> = Vec::new();
    while erased + failed.len() < 500 {
        let mut tx = state.db.begin().await?;
        let due: Option<(Uuid, Option<String>)> = sqlx::query_as(
            "SELECT id, phone FROM users
              WHERE status = 'pending_deletion' AND deletion_due_at <= now() AND id <> ALL($1)
              ORDER BY deletion_due_at
              LIMIT 1
              FOR UPDATE SKIP LOCKED",
        )
        .bind(&failed)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((user_id, phone)) = due else { break };
        set_context(&mut tx, Some(user_id), None).await?;
        let summary: Result<(serde_json::Value,), sqlx::Error> =
            sqlx::query_as("SELECT erase_account()")
                .fetch_one(&mut *tx)
                .await;
        match summary {
            Ok((mut summary,)) => {
                summary["scheduled"] = json!(true);
                audit::record(
                    &mut tx,
                    audit::Event {
                        organization_id: None,
                        actor_user_id: Some(user_id),
                        action: "privacy.account_erased",
                        target_type: Some("user"),
                        target_id: Some(&user_id.to_string()),
                        outcome: audit::Outcome::Success,
                        details: summary,
                    },
                )
                .await?;
                tx.commit().await?;
                mfa::notify(state, phone, SMS_ERASED);
                erased += 1;
            }
            Err(error) => {
                // İşlem geri alınır; hesap bir sonraki turda yeniden denenir.
                tracing::error!(?error, "planlı hesap silme başarısız");
                failed.push(user_id);
            }
        }
    }
    Ok(erased)
}

/// Silme işini saatte bir çalıştırır.
pub fn start_erasure_job(state: &AppState) -> tokio::task::JoinHandle<()> {
    let state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
            match erase_due_accounts(&state).await {
                Ok(0) => {}
                Ok(count) => tracing::info!(count, "planlı hesap silmeleri uygulandı"),
                Err(error) => tracing::error!(?error, "planlı hesap silme işi çalışmadı"),
            }
        }
    })
}

// ---------------------------------------------------------------------------------------------
// Rıza defteri
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentRequest {
    purpose: String,
    /// Kişiye gösterilen metnin sürümü; güncel sürüm olmalı.
    version: String,
    granted: bool,
    platform: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
struct ConsentState {
    code: String,
    kind: String,
    description: String,
    current_version: String,
    granted: Option<bool>,
    version: Option<String>,
    recorded_at: Option<DateTime<Utc>>,
    /// Son yanıt güncel metin sürümüne mi verildi? Değilse istemci yeniden sormalı.
    up_to_date: bool,
}

pub async fn list_consents(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<serde_json::Value>> {
    let purposes: Vec<ConsentState> = sqlx::query_as(
        "SELECT p.code, p.kind, p.description, p.current_version, r.granted, r.version,
                r.recorded_at, coalesce(r.version = p.current_version, false) AS up_to_date
           FROM consent_purposes p
           LEFT JOIN LATERAL (
                SELECT granted, version, recorded_at FROM consent_records
                 WHERE user_id = $1 AND purpose = p.code
                 ORDER BY recorded_at DESC, id DESC
                 LIMIT 1) r ON true
          ORDER BY p.code",
    )
    .bind(user.user_id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({ "purposes": purposes })))
}

pub async fn record_consent(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<ConsentRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    if request
        .platform
        .as_deref()
        .is_some_and(|p| !matches!(p, "ios" | "android" | "web"))
    {
        return Err(ApiError::BadRequest("invalid_platform"));
    }
    let mut tx = state.db.begin().await?;
    rate_limit::hit(
        &mut tx,
        &state.hmac_secret,
        rate_limit::CONSENT_PER_USER,
        &user.user_id.to_string(),
    )
    .await?;
    let purpose: Option<(String, String)> =
        sqlx::query_as("SELECT kind, current_version FROM consent_purposes WHERE code = $1")
            .bind(&request.purpose)
            .fetch_optional(&mut *tx)
            .await?;
    let (kind, current_version) = purpose.ok_or(ApiError::Unprocessable("unknown_purpose"))?;
    if request.version != current_version {
        return Err(ApiError::Conflict("outdated_version"));
    }
    if kind == "notice_acknowledgement" && !request.granted {
        return Err(ApiError::BadRequest("notice_cannot_be_withdrawn"));
    }
    let (recorded_at,): (DateTime<Utc>,) = sqlx::query_as(
        "INSERT INTO consent_records (user_id, purpose, version, granted, platform)
         VALUES ($1, $2, $3, $4, $5) RETURNING recorded_at",
    )
    .bind(user.user_id)
    .bind(&request.purpose)
    .bind(&request.version)
    .bind(request.granted)
    .bind(&request.platform)
    .fetch_one(&mut *tx)
    .await?;
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: None,
            actor_user_id: Some(user.user_id),
            action: "privacy.consent_recorded",
            target_type: Some("user"),
            target_id: Some(&user.user_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({
                "purpose": request.purpose, "version": request.version, "granted": request.granted,
            }),
        },
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "purpose": request.purpose,
            "version": request.version,
            "granted": request.granted,
            "recorded_at": recorded_at,
        })),
    ))
}
