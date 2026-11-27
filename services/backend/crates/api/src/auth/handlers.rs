//! Giriş ve oturum uç noktaları.
//!
//! Hesabın var olup olmadığı hiçbir yanıtta belli olmaz (AUT-02, AUT-03): kayıt ve sıfırlama
//! başlatma her zaman 202 döner; yanlış parola ile bilinmeyen kullanıcı aynı yanıtı ve benzer
//! süreyi alır (bilinmeyen kullanıcıda sahte bir hash doğrulanır).

use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Acquire, PgConnection};
use uuid::Uuid;

use super::{
    AuthUser,
    codes::{self, Purpose},
    mfa, password,
    rate_limit::{self, Budget},
    tokens::{self, ACCESS_TTL_SECS, REFRESH_TTL_DAYS},
};
use crate::{
    AppState, audit,
    db::set_context,
    error::{ApiError, ApiResult, is_unique_violation},
    privacy,
    sms::mask_phone,
};

// ---------------------------------------------------------------------------------------------
// İstek ve yanıt gövdeleri. Bilinmeyen alanlar reddedilir (API-02).
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartRequest {
    phone: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceInfo {
    pub(super) platform: String,
    pub(super) name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    phone: String,
    code: String,
    display_name: String,
    password: String,
    device: DeviceInfo,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    /// Telefon (+90…) veya e-posta.
    identifier: String,
    password: String,
    device: DeviceInfo,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshRequest {
    refresh_token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetRequest {
    phone: String,
    code: String,
    new_password: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    refresh_token: String,
    session_id: Uuid,
}

/// Giriş yanıtı: ya oturum ya da ikinci adım bileti.
#[derive(Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    Tokens(TokenResponse),
    MfaRequired(mfa::Challenge),
}

#[derive(Serialize)]
pub struct MeResponse {
    id: Uuid,
    display_name: String,
    phone: Option<String>,
    email: Option<String>,
    organizations: Vec<OrganizationSummary>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct OrganizationSummary {
    id: Uuid,
    name: String,
    kind: String,
    role: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct SessionSummary {
    id: Uuid,
    platform: Option<String>,
    name: Option<String>,
    started_at: DateTime<Utc>,
    last_active_at: DateTime<Utc>,
    #[sqlx(skip)]
    current: bool,
}

// ---------------------------------------------------------------------------------------------
// Doğrulama yardımcıları
// ---------------------------------------------------------------------------------------------

/// E.164: `+` ve 8–15 rakam, ilk rakam 0 olamaz.
pub(crate) fn normalize_phone(raw: &str) -> Option<String> {
    let value = raw.trim();
    let digits = value.strip_prefix('+')?;
    let valid = (8..=15).contains(&digits.len())
        && digits.chars().all(|c| c.is_ascii_digit())
        && !digits.starts_with('0');
    valid.then(|| value.to_owned())
}

fn normalize_email(raw: &str) -> Option<String> {
    let value = raw.trim().to_lowercase();
    let (local, domain) = value.split_once('@')?;
    let valid = !local.is_empty()
        && domain.contains('.')
        && value.len() <= 254
        && !value.chars().any(char::is_whitespace);
    valid.then_some(value)
}

pub(super) fn validate_device(device: &DeviceInfo) -> ApiResult<()> {
    if !matches!(device.platform.as_str(), "ios" | "android" | "web") {
        return Err(ApiError::BadRequest("invalid_device"));
    }
    if device
        .name
        .as_ref()
        .is_some_and(|name| name.chars().count() > 100)
    {
        return Err(ApiError::BadRequest("invalid_device"));
    }
    Ok(())
}

pub(super) fn ip_of(addr: &SocketAddr) -> String {
    // Ters vekil arkasında çalışırken güvenilir vekil yapılandırılana kadar X-Forwarded-For
    // dikkate alınmaz (NET-03).
    addr.ip().to_string()
}

async fn limit(
    state: &AppState,
    conn: &mut PgConnection,
    budget: Budget,
    value: &str,
) -> ApiResult<()> {
    rate_limit::hit(conn, &state.hmac_secret, budget, value).await
}

// ---------------------------------------------------------------------------------------------
// Doğrulama kodları
// ---------------------------------------------------------------------------------------------

/// Yeni kod üretir, aynı telefon ve amaç için önceki kodları geçersiz kılar ve SMS'i arka planda
/// gönderir (yanıt süresi kodun gönderilip gönderilmediğini belli etmez).
pub(super) async fn issue_code(
    state: &AppState,
    conn: &mut PgConnection,
    purpose: Purpose,
    phone: &str,
    user_id: Option<Uuid>,
) -> ApiResult<()> {
    let code = codes::generate().map_err(|_| ApiError::Internal)?;
    let mac = codes::code_mac(&state.hmac_secret, purpose, phone, &code);

    let mut tx = conn.begin().await?;
    sqlx::query(
        "UPDATE verification_codes SET consumed_at = now()
          WHERE phone = $1 AND purpose = $2 AND consumed_at IS NULL",
    )
    .bind(phone)
    .bind(purpose.as_str())
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO verification_codes (purpose, phone, user_id, code_hash, expires_at)
         VALUES ($1, $2, $3, $4, now() + make_interval(mins => $5))",
    )
    .bind(purpose.as_str())
    .bind(phone)
    .bind(user_id)
    .bind(mac)
    .bind(i32::try_from(codes::CODE_TTL_MINUTES).unwrap_or(10))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let sms = state.sms.clone();
    let phone = phone.to_owned();
    let text = format!("Shedu doğrulama kodunuz: {code}. Bu kodu kimseyle paylaşmayın.");
    tokio::spawn(async move {
        if sms.send(&phone, &text).await.is_err() {
            tracing::error!(phone = %mask_phone(&phone), "SMS gönderilemedi");
        }
    });
    Ok(())
}

/// Kodu doğrular ve tüketir. Ayrı ve hemen kalıcı hale gelen bir işlemde çalışır: yanlış
/// denemeler sonraki adımlar başarısız olsa bile sayılır. Kod tek kullanımlıktır, en fazla
/// 5 deneme hakkı vardır (AUT-03). Başarılıysa koda bağlı kullanıcı kimliğini döner.
pub(super) async fn consume_code(
    state: &AppState,
    purpose: Purpose,
    phone: &str,
    code: &str,
) -> ApiResult<Option<Uuid>> {
    let invalid = ApiError::BadRequest("invalid_code");
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return Err(invalid);
    }

    let mut tx = state.db.begin().await?;
    let row: Option<(Uuid, Vec<u8>, i16, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, code_hash, attempts, user_id FROM verification_codes
          WHERE phone = $1 AND purpose = $2 AND consumed_at IS NULL AND expires_at > now()
          ORDER BY created_at DESC
          LIMIT 1
          FOR UPDATE",
    )
    .bind(phone)
    .bind(purpose.as_str())
    .fetch_optional(&mut *tx)
    .await?;

    let Some((id, stored, attempts, user_id)) = row else {
        tx.commit().await?;
        return Err(invalid);
    };

    if attempts < codes::MAX_ATTEMPTS
        && codes::code_matches(&state.hmac_secret, purpose, phone, code, &stored)
    {
        sqlx::query("UPDATE verification_codes SET consumed_at = now() WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(user_id);
    }

    sqlx::query(
        "UPDATE verification_codes
            SET attempts = attempts + 1,
                consumed_at = CASE WHEN attempts + 1 >= $2 THEN now() ELSE NULL END
          WHERE id = $1",
    )
    .bind(id)
    .bind(codes::MAX_ATTEMPTS)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Err(invalid)
}

// ---------------------------------------------------------------------------------------------
// Oturumlar
// ---------------------------------------------------------------------------------------------

/// Yeni oturum: yeni cihaz kaydı ve yeni bir refresh ailesi. Girişte her zaman yeni aile
/// oluşturulur; eski oturum kimliği yeni yetkiyle birleşmez (SES-02).
pub(super) async fn create_session(
    conn: &mut PgConnection,
    user_id: Uuid,
    device: &DeviceInfo,
) -> ApiResult<(Uuid, String)> {
    let (device_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO user_devices (user_id, platform, name, last_seen_at)
         VALUES ($1, $2, $3, now()) RETURNING id",
    )
    .bind(user_id)
    .bind(&device.platform)
    .bind(&device.name)
    .fetch_one(&mut *conn)
    .await?;

    let family_id = Uuid::new_v4();
    let refresh = insert_refresh(conn, user_id, Some(device_id), family_id).await?;
    Ok((family_id, refresh))
}

async fn insert_refresh(
    conn: &mut PgConnection,
    user_id: Uuid,
    device_id: Option<Uuid>,
    family_id: Uuid,
) -> ApiResult<String> {
    let (token, hash) = tokens::new_refresh_token().map_err(|_| ApiError::Internal)?;
    sqlx::query(
        "INSERT INTO refresh_tokens (user_id, device_id, family_id, token_hash, expires_at)
         VALUES ($1, $2, $3, $4, now() + make_interval(days => $5))",
    )
    .bind(user_id)
    .bind(device_id)
    .bind(family_id)
    .bind(hash)
    .bind(i32::try_from(REFRESH_TTL_DAYS).unwrap_or(30))
    .execute(conn)
    .await?;
    Ok(token)
}

pub(super) fn token_response(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
    refresh_token: String,
) -> ApiResult<TokenResponse> {
    let access_token = state
        .tokens
        .issue_access(user_id, session_id)
        .map_err(|_| ApiError::Internal)?;
    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ACCESS_TTL_SECS,
        refresh_token,
        session_id,
    })
}

/// Oturum ailesini iptal eder ve o cihazın push token'ını siler: çıkış yapılmış cihaza alarm
/// bildirimi gitmez.
async fn revoke_family(
    conn: &mut PgConnection,
    family_id: Uuid,
    user_id: Uuid,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = now()
          WHERE family_id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(family_id)
    .bind(user_id)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE user_devices SET push_token = NULL
          WHERE user_id = $2 AND id IN (SELECT device_id FROM refresh_tokens WHERE family_id = $1)",
    )
    .bind(family_id)
    .bind(user_id)
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}

async fn hash_password(password: String) -> ApiResult<String> {
    tokio::task::spawn_blocking(move || password::hash(&password))
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(|_| ApiError::Internal)
}

// ---------------------------------------------------------------------------------------------
// Kayıt
// ---------------------------------------------------------------------------------------------

pub async fn register_start(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<StartRequest>,
) -> ApiResult<StatusCode> {
    let phone = normalize_phone(&request.phone).ok_or(ApiError::BadRequest("invalid_phone"))?;
    let mut conn = state.db.acquire().await?;
    limit(&state, &mut conn, rate_limit::SMS_PER_IP, &ip_of(&addr)).await?;
    limit(&state, &mut conn, rate_limit::SMS_PER_PHONE, &phone).await?;
    limit(&state, &mut conn, rate_limit::SMS_GLOBAL, "all").await?;

    let existing: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE phone = $1")
        .bind(&phone)
        .fetch_optional(&mut *conn)
        .await?;
    if existing.is_none() {
        issue_code(&state, &mut conn, Purpose::Register, &phone, None).await?;
    }
    Ok(StatusCode::ACCEPTED)
}

pub async fn register_complete(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<RegisterRequest>,
) -> ApiResult<(StatusCode, Json<TokenResponse>)> {
    let phone = normalize_phone(&request.phone).ok_or(ApiError::BadRequest("invalid_phone"))?;
    let display_name = request.display_name.trim().to_owned();
    if display_name.is_empty() || display_name.chars().count() > 100 {
        return Err(ApiError::BadRequest("invalid_display_name"));
    }
    validate_device(&request.device)?;
    password::validate_new(&request.password, &[&phone, &display_name])
        .map_err(|rejection| ApiError::BadRequest(rejection.code()))?;

    {
        let mut conn = state.db.acquire().await?;
        limit(&state, &mut conn, rate_limit::VERIFY_PER_IP, &ip_of(&addr)).await?;
    }
    consume_code(&state, Purpose::Register, &phone, &request.code).await?;
    let password_hash = hash_password(request.password).await?;

    let user_id = Uuid::new_v4();
    let organization_id = Uuid::new_v4();
    let mut tx = state.db.begin().await?;
    set_context(&mut tx, Some(user_id), Some(organization_id)).await?;

    let inserted = sqlx::query(
        "INSERT INTO users (id, phone, display_name, password_hash) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(&phone)
    .bind(&display_name)
    .bind(&password_hash)
    .execute(&mut *tx)
    .await;
    match inserted {
        Err(error) if is_unique_violation(&error) => {
            return Err(ApiError::Conflict("already_registered"));
        }
        other => {
            other?;
        }
    }

    sqlx::query("INSERT INTO organizations (id, name, kind) VALUES ($1, $2, 'home')")
        .bind(organization_id)
        .bind(&display_name)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO memberships (user_id, organization_id, role) VALUES ($1, $2, 'owner')",
    )
    .bind(user_id)
    .bind(organization_id)
    .execute(&mut *tx)
    .await?;

    let (session_id, refresh_token) = create_session(&mut tx, user_id, &request.device).await?;
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: Some(organization_id),
            actor_user_id: Some(user_id),
            action: "auth.register",
            target_type: Some("user"),
            target_id: Some(&user_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({ "platform": request.device.platform }),
        },
    )
    .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(token_response(&state, user_id, session_id, refresh_token)?),
    ))
}

// ---------------------------------------------------------------------------------------------
// Giriş, yenileme, çıkış
// ---------------------------------------------------------------------------------------------

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    validate_device(&request.device)?;
    let identifier = if request.identifier.trim_start().starts_with('+') {
        normalize_phone(&request.identifier)
    } else {
        normalize_email(&request.identifier)
    }
    .ok_or(ApiError::Unauthorized)?;

    let mut conn = state.db.acquire().await?;
    limit(&state, &mut conn, rate_limit::LOGIN_PER_IP, &ip_of(&addr)).await?;
    limit(
        &state,
        &mut conn,
        rate_limit::LOGIN_PER_ACCOUNT,
        &identifier,
    )
    .await?;
    limit(&state, &mut conn, rate_limit::LOGIN_GLOBAL, "all").await?;

    let user: Option<(Uuid, Option<String>, String)> = sqlx::query_as(
        "SELECT id, password_hash, status FROM users WHERE phone = $1 OR email = $1",
    )
    .bind(&identifier)
    .fetch_optional(&mut *conn)
    .await?;

    // Bilinmeyen kullanıcıda da bir hash doğrulanır; yanıt süresi hesabın varlığını belli etmez.
    let stored_hash = user
        .as_ref()
        .and_then(|(_, hash, _)| hash.clone())
        .unwrap_or_else(|| state.dummy_hash.to_string());
    let candidate = request.password;
    let password_ok = candidate.chars().count() <= password::MAX_CHARS
        && tokio::task::spawn_blocking(move || password::verify(&candidate, &stored_hash))
            .await
            .map_err(|_| ApiError::Internal)?;

    let user_id = match user {
        // Silme bekleyen hesap tam doğrulamayla giriş yaparsa talep iptal olur (aşağıda; MFA
        // açıksa ikinci adımdan sonra).
        Some((id, Some(_), status))
            if password_ok && (status == "active" || status == "pending_deletion") =>
        {
            id
        }
        other => {
            let target = other.map(|(id, _, _)| id.to_string());
            audit::record(
                &mut conn,
                audit::Event {
                    organization_id: None,
                    actor_user_id: None,
                    action: "auth.login_failed",
                    target_type: target.as_ref().map(|_| "user"),
                    target_id: target.as_deref(),
                    outcome: audit::Outcome::Failure,
                    details: json!({}),
                },
            )
            .await?;
            return Err(ApiError::Unauthorized);
        }
    };

    // İkinci faktör açıksa oturum açılmaz; kısa ömürlü bir biletle ikinci adım istenir (AUT-01).
    if let Some(challenge) = mfa::start_challenge(&mut conn, user_id, &request.device).await? {
        return Ok(Json(LoginResponse::MfaRequired(challenge)));
    }

    let mut tx = conn.begin().await?;
    let cancelled = privacy::cancel_scheduled_erasure(&mut tx, user_id).await?;
    let (session_id, refresh_token) = create_session(&mut tx, user_id, &request.device).await?;
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: None,
            actor_user_id: Some(user_id),
            action: "auth.login",
            target_type: Some("session"),
            target_id: Some(&session_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({ "platform": request.device.platform }),
        },
    )
    .await?;
    let phone = if cancelled {
        mfa::phone_of(&mut tx, user_id).await?
    } else {
        None
    };
    tx.commit().await?;
    if cancelled {
        mfa::notify(&state, phone, privacy::SMS_ERASURE_CANCELLED);
    }

    Ok(Json(LoginResponse::Tokens(token_response(
        &state,
        user_id,
        session_id,
        refresh_token,
    )?)))
}

/// Refresh token'ı tek kullanımlık olarak değiştirir. Daha önce kullanılmış bir token yeniden
/// gelirse çalınmış sayılır: bütün aile iptal edilir ve denetim kaydına yazılır (SES-05).
/// Aynı oturumun eşzamanlı yenilemesini istemci tek uçuşla (single-flight) koordine eder.
pub async fn refresh(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<RefreshRequest>,
) -> ApiResult<Json<TokenResponse>> {
    let mut conn = state.db.acquire().await?;
    limit(&state, &mut conn, rate_limit::REFRESH_PER_IP, &ip_of(&addr)).await?;
    let hash = tokens::refresh_token_hash(&request.refresh_token).ok_or(ApiError::Unauthorized)?;

    let mut tx = conn.begin().await?;
    let rotated: Option<(Uuid, Uuid, Option<Uuid>)> = sqlx::query_as(
        "UPDATE refresh_tokens r SET used_at = now()
           FROM users u
          WHERE r.token_hash = $1 AND r.used_at IS NULL AND r.revoked_at IS NULL
            AND r.expires_at > now() AND u.id = r.user_id AND u.status = 'active'
          RETURNING r.user_id, r.family_id, r.device_id",
    )
    .bind(&hash)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some((user_id, family_id, device_id)) = rotated {
        let refresh_token = insert_refresh(&mut tx, user_id, device_id, family_id).await?;
        if let Some(device_id) = device_id {
            sqlx::query("UPDATE user_devices SET last_seen_at = now() WHERE id = $1")
                .bind(device_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        return Ok(Json(token_response(
            &state,
            user_id,
            family_id,
            refresh_token,
        )?));
    }

    let reused: Option<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT user_id, family_id FROM refresh_tokens WHERE token_hash = $1 AND used_at IS NOT NULL",
    )
    .bind(&hash)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((user_id, family_id)) = reused {
        let revoked = revoke_family(&mut tx, family_id, user_id).await?;
        tracing::warn!(
            revoked,
            "kullanılmış refresh token yeniden geldi; aile iptal edildi"
        );
        audit::record(
            &mut tx,
            audit::Event {
                organization_id: None,
                actor_user_id: Some(user_id),
                action: "auth.refresh_reuse_detected",
                target_type: Some("session"),
                target_id: Some(&family_id.to_string()),
                outcome: audit::Outcome::Denied,
                details: json!({ "revoked_tokens": revoked }),
            },
        )
        .await?;
    }
    tx.commit().await?;
    Err(ApiError::Unauthorized)
}

pub async fn logout(State(state): State<AppState>, user: AuthUser) -> ApiResult<StatusCode> {
    let mut tx = state.db.begin().await?;
    revoke_family(&mut tx, user.session_id, user.user_id).await?;
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: None,
            actor_user_id: Some(user.user_id),
            action: "auth.logout",
            target_type: Some("session"),
            target_id: Some(&user.session_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({}),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------------
// Profil ve oturumlar
// ---------------------------------------------------------------------------------------------

pub async fn me(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<MeResponse>> {
    let mut tx = state.db.begin().await?;
    set_context(&mut tx, Some(user.user_id), None).await?;

    let (id, display_name, phone, email): (Uuid, String, Option<String>, Option<String>) =
        sqlx::query_as("SELECT id, display_name, phone, email FROM users WHERE id = $1")
            .bind(user.user_id)
            .fetch_one(&mut *tx)
            .await?;
    // organizations RLS: yalnızca üyesi olunan organizasyonlar görünür (member_read).
    let organizations: Vec<OrganizationSummary> = sqlx::query_as(
        "SELECT o.id, o.name, o.kind, m.role
           FROM memberships m JOIN organizations o ON o.id = m.organization_id
          WHERE m.user_id = $1
          ORDER BY o.name",
    )
    .bind(user.user_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(Json(MeResponse {
        id,
        display_name,
        phone,
        email,
        organizations,
    }))
}

pub async fn list_sessions(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Vec<SessionSummary>>> {
    let mut sessions: Vec<SessionSummary> = sqlx::query_as(
        "SELECT r.family_id AS id, d.platform, d.name,
                min(r.created_at) AS started_at, max(r.created_at) AS last_active_at
           FROM refresh_tokens r LEFT JOIN user_devices d ON d.id = r.device_id
          WHERE r.user_id = $1
          GROUP BY r.family_id, d.platform, d.name
         HAVING bool_or(r.revoked_at IS NULL AND r.used_at IS NULL AND r.expires_at > now())
          ORDER BY last_active_at DESC",
    )
    .bind(user.user_id)
    .fetch_all(&state.db)
    .await?;
    for session in &mut sessions {
        session.current = session.id == user.session_id;
    }
    Ok(Json(sessions))
}

/// Kullanıcı kendi oturumlarından birini kapatır. Başkasının oturum kimliği verilirse,
/// var olsa bile 404 döner (AZ-01).
pub async fn revoke_session(
    State(state): State<AppState>,
    user: AuthUser,
    Path(session_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let mut tx = state.db.begin().await?;
    if revoke_family(&mut tx, session_id, user.user_id).await? == 0 {
        return Err(ApiError::NotFound);
    }
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: None,
            actor_user_id: Some(user.user_id),
            action: "auth.session_revoked",
            target_type: Some("session"),
            target_id: Some(&session_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({}),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------------
// Parola sıfırlama
// ---------------------------------------------------------------------------------------------

pub async fn reset_start(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<StartRequest>,
) -> ApiResult<StatusCode> {
    let phone = normalize_phone(&request.phone).ok_or(ApiError::BadRequest("invalid_phone"))?;
    let mut conn = state.db.acquire().await?;
    limit(&state, &mut conn, rate_limit::SMS_PER_IP, &ip_of(&addr)).await?;
    limit(&state, &mut conn, rate_limit::SMS_PER_PHONE, &phone).await?;
    limit(&state, &mut conn, rate_limit::SMS_GLOBAL, "all").await?;

    let user: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM users WHERE phone = $1 AND status IN ('active', 'pending_deletion')",
    )
    .bind(&phone)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some((user_id,)) = user {
        issue_code(
            &state,
            &mut conn,
            Purpose::PasswordReset,
            &phone,
            Some(user_id),
        )
        .await?;
    }
    Ok(StatusCode::ACCEPTED)
}

/// Parolayı değiştirir ve kullanıcının bütün oturumlarını kapatır (SES-04).
pub async fn reset_complete(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<ResetRequest>,
) -> ApiResult<StatusCode> {
    let phone = normalize_phone(&request.phone).ok_or(ApiError::BadRequest("invalid_phone"))?;
    {
        let mut conn = state.db.acquire().await?;
        limit(&state, &mut conn, rate_limit::VERIFY_PER_IP, &ip_of(&addr)).await?;
    }

    let profile: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT display_name, email FROM users WHERE phone = $1")
            .bind(&phone)
            .fetch_optional(&state.db)
            .await?;
    let (display_name, email) = profile.unwrap_or_default();
    let mut personal = vec![phone.as_str(), display_name.as_str()];
    if let Some(email) = email.as_deref() {
        personal.push(email);
    }
    password::validate_new(&request.new_password, &personal)
        .map_err(|rejection| ApiError::BadRequest(rejection.code()))?;

    let user_id = consume_code(&state, Purpose::PasswordReset, &phone, &request.code)
        .await?
        .ok_or(ApiError::BadRequest("invalid_code"))?;
    let password_hash = hash_password(request.new_password).await?;

    let mut tx = state.db.begin().await?;
    sqlx::query(
        "UPDATE users SET password_hash = $1, updated_at = now()
          WHERE id = $2 AND status IN ('active', 'pending_deletion')",
    )
    .bind(&password_hash)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE user_devices SET push_token = NULL WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    let revoked = sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: None,
            actor_user_id: Some(user_id),
            action: "auth.password_reset",
            target_type: Some("user"),
            target_id: Some(&user_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({ "revoked_tokens": revoked }),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phone_normalization() {
        assert_eq!(
            normalize_phone(" +905551112233 "),
            Some("+905551112233".into())
        );
        for bad in [
            "905551112233",
            "+0555111",
            "+90 555 111",
            "+1234567",
            "+1234567890123456",
        ] {
            assert_eq!(normalize_phone(bad), None, "{bad}");
        }
    }

    #[test]
    fn email_normalization() {
        assert_eq!(
            normalize_email(" Ali@Example.COM "),
            Some("ali@example.com".into())
        );
        for bad in ["ali", "@example.com", "ali@localhost", "a li@example.com"] {
            assert_eq!(normalize_email(bad), None, "{bad}");
        }
    }
}
