//! İki adımlı doğrulama: TOTP ve tek kullanımlık kurtarma kodları (AUT-01, AUT-04, KEY-04).
//!
//! - Kurulum ve kaldırma parolayla yeniden doğrulama ister; kaldırma ayrıca geçerli bir TOTP veya
//!   kurtarma kodu ister. Açma, kapatma ve kurtarma koduyla giriş kullanıcıya SMS ile bildirilir.
//! - TOTP sırrı şifreli saklanır; aynı kod iki kez kabul edilmez. Kurtarma kodlarının yalnızca
//!   HMAC özeti saklanır.
//! - Faktörü açık kullanıcı girişte parolayı doğrulayınca oturum almaz; kısa ömürlü, tek
//!   kullanımlık, 5 denemelik bir biletle ikinci adımı tamamlar. İkinci adımı tamamlanan oturum
//!   kaydedilir; ayrıcalıklı organizasyon erişimi yalnızca bu oturumlara açılır (`authz`).

use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::StatusCode,
};
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use sqlx::PgConnection;
use uuid::Uuid;

use super::{
    AuthUser,
    handlers::{self, DeviceInfo, TokenResponse, create_session, ip_of, token_response},
    rate_limit, reauth, tokens, totp,
};
use crate::{
    AppState, audit,
    error::{ApiError, ApiResult},
    sms::mask_phone,
};

const CHALLENGE_TTL_SECS: i64 = 300;
const CHALLENGE_MAX_ATTEMPTS: i16 = 5;
const RECOVERY_CODE_COUNT: usize = 10;
const RECOVERY_CODE_LEN: usize = 10;
/// Karıştırılabilecek karakterler (0/o, 1/l/i) yok: 31 karakter, kod başına ~49 bit.
const RECOVERY_ALPHABET: &[u8; 31] = b"abcdefghjkmnpqrstuvwxyz23456789";

const SMS_ENABLED: &str = "Shedu: Hesabınızda iki adımlı doğrulama açıldı. Bunu siz yapmadıysanız \
                           hemen parolanızı değiştirin.";
const SMS_DISABLED: &str = "Shedu: Hesabınızda iki adımlı doğrulama kapatıldı. Bunu siz \
                            yapmadıysanız hemen parolanızı değiştirin.";
const SMS_RECOVERY_USED: &str = "Shedu: Hesabınıza bir kurtarma koduyla giriş yapıldı. Bunu siz \
                                 yapmadıysanız hemen parolanızı değiştirin.";

/// Şifreli TOTP kaydı: anahtar sürümü, nonce, şifreli sır, son kabul edilen adım.
type StoredTotp = (i16, Vec<u8>, Vec<u8>, Option<i64>);

#[derive(Clone, Copy)]
enum Method {
    Totp,
    RecoveryCode,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::RecoveryCode => "recovery_code",
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Gövdeler
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordRequest {
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeRequest {
    code: String,
}

/// Parola ve ikinci faktör: TOTP kodu veya kurtarma kodundan tam olarak biri.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactorRequest {
    password: String,
    code: Option<String>,
    recovery_code: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    mfa_token: String,
    code: Option<String>,
    recovery_code: Option<String>,
}

#[derive(Serialize)]
pub struct Challenge {
    mfa_required: bool,
    mfa_token: String,
    expires_in: i64,
}

#[derive(Serialize)]
pub struct Status {
    /// `none`, `pending` (kurulum onaylanmadı) veya `enabled`.
    totp: &'static str,
    recovery_codes_remaining: i64,
    /// Bu oturumda ikinci adım tamamlandı mı?
    session_verified: bool,
}

// ---------------------------------------------------------------------------------------------
// Yardımcılar
// ---------------------------------------------------------------------------------------------

pub(crate) fn notify(state: &AppState, phone: Option<String>, text: &'static str) {
    let Some(phone) = phone else { return };
    let sms = state.sms.clone();
    tokio::spawn(async move {
        if sms.send(&phone, text).await.is_err() {
            tracing::error!(phone = %mask_phone(&phone), "güvenlik bildirimi gönderilemedi");
        }
    });
}

pub(crate) async fn phone_of(conn: &mut PgConnection, user_id: Uuid) -> ApiResult<Option<String>> {
    let row: Option<(Option<String>,)> = sqlx::query_as("SELECT phone FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(conn)
        .await?;
    Ok(row.and_then(|(phone,)| phone))
}

async fn record(
    conn: &mut PgConnection,
    user_id: Uuid,
    action: &'static str,
    outcome: audit::Outcome,
    details: serde_json::Value,
) -> ApiResult<()> {
    audit::record(
        conn,
        audit::Event {
            organization_id: None,
            actor_user_id: Some(user_id),
            action,
            target_type: Some("user"),
            target_id: Some(&user_id.to_string()),
            outcome,
            details,
        },
    )
    .await?;
    Ok(())
}

/// Parolayla yeniden doğrulama; başarısız deneme `action` adıyla denetim kaydına yazılır.
pub(crate) async fn require_password(
    state: &AppState,
    user_id: Uuid,
    password: String,
    action: &'static str,
) -> ApiResult<()> {
    if reauth::verify_password(state, user_id, password).await? {
        return Ok(());
    }
    let mut conn = state.db.acquire().await?;
    record(
        &mut conn,
        user_id,
        action,
        audit::Outcome::Failure,
        json!({}),
    )
    .await?;
    Err(ApiError::Forbidden("reauth_failed"))
}

/// TOTP kodunu doğrular ve adımı tüketir. Satır kilitlenir; eşzamanlı iki doğrulamadan yalnızca
/// biri aynı adımı kullanabilir (BUS-02). `confirmed`: onaylanmış faktör mü, kurulumdaki mi.
async fn check_totp(
    state: &AppState,
    conn: &mut PgConnection,
    user_id: Uuid,
    code: &str,
    confirmed: bool,
) -> ApiResult<bool> {
    let row: Option<StoredTotp> = sqlx::query_as(
        "SELECT key_version, nonce, secret_ct, last_step FROM user_totp
          WHERE user_id = $1 AND (confirmed_at IS NOT NULL) = $2
          FOR UPDATE",
    )
    .bind(user_id)
    .bind(confirmed)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((version, nonce, ciphertext, last_step)) = row else {
        return Ok(false);
    };
    let secret = state
        .totp_key
        .open(version, user_id.as_bytes(), &nonce, &ciphertext)
        .map_err(|_| {
            tracing::error!("TOTP sırrı çözülemedi (anahtar veya veri bozuk)");
            ApiError::Internal
        })?;
    let now_step = totp::step_at(Utc::now().timestamp());
    let Some(step) = totp::matching_step(&secret, code.trim(), now_step) else {
        return Ok(false);
    };
    if last_step.is_some_and(|last| step <= last) {
        return Ok(false);
    }
    let updated = sqlx::query(
        "UPDATE user_totp SET last_step = $2
          WHERE user_id = $1 AND (last_step IS NULL OR last_step < $2)",
    )
    .bind(user_id)
    .bind(step)
    .execute(conn)
    .await?;
    Ok(updated.rows_affected() == 1)
}

fn recovery_hash(state: &AppState, user_id: Uuid, code: &str) -> ApiResult<Vec<u8>> {
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(&state.hmac_secret).map_err(|_| ApiError::Internal)?;
    mac.update(b"recovery-code\0");
    mac.update(user_id.as_bytes());
    mac.update(code.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Küçük harfe çevirir, tire ve boşlukları atar; biçim yanlışsa `None`.
fn normalize_recovery(input: &str) -> Option<String> {
    let code: String = input
        .chars()
        .filter(|c| *c != '-' && !c.is_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    (code.len() == RECOVERY_CODE_LEN && code.bytes().all(|b| RECOVERY_ALPHABET.contains(&b)))
        .then_some(code)
}

fn generate_recovery_code() -> ApiResult<String> {
    let mut code = String::with_capacity(RECOVERY_CODE_LEN);
    let mut buffer = [0u8; 32];
    while code.len() < RECOVERY_CODE_LEN {
        getrandom::fill(&mut buffer).map_err(|_| ApiError::Internal)?;
        // Reddederek örnekleme: 248 = 8 × 31, kalan değerler eşit olasılıklı değildir.
        for byte in buffer {
            if byte < 248 && code.len() < RECOVERY_CODE_LEN {
                code.push(char::from(RECOVERY_ALPHABET[usize::from(byte % 31)]));
            }
        }
    }
    Ok(code)
}

/// Eski kurtarma kodlarını siler, yenilerini üretir; düz kodlar yalnızca bir kez gösterilir.
async fn replace_recovery_codes(
    state: &AppState,
    conn: &mut PgConnection,
    user_id: Uuid,
) -> ApiResult<Vec<String>> {
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *conn)
        .await?;
    let mut shown = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let code = generate_recovery_code()?;
        sqlx::query("INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)")
            .bind(user_id)
            .bind(recovery_hash(state, user_id, &code)?)
            .execute(&mut *conn)
            .await?;
        shown.push(format!("{}-{}", &code[..5], &code[5..]));
    }
    Ok(shown)
}

async fn use_recovery_code(
    state: &AppState,
    conn: &mut PgConnection,
    user_id: Uuid,
    input: &str,
) -> ApiResult<bool> {
    let Some(code) = normalize_recovery(input) else {
        return Ok(false);
    };
    let used = sqlx::query(
        "UPDATE recovery_codes SET used_at = now()
          WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL",
    )
    .bind(user_id)
    .bind(recovery_hash(state, user_id, &code)?)
    .execute(conn)
    .await?;
    Ok(used.rows_affected() == 1)
}

/// TOTP kodu veya kurtarma kodundan tam olarak biri verilmeli.
async fn check_factor(
    state: &AppState,
    conn: &mut PgConnection,
    user_id: Uuid,
    code: Option<&str>,
    recovery_code: Option<&str>,
) -> ApiResult<Option<Method>> {
    match (code, recovery_code) {
        (Some(code), None) => Ok(check_totp(state, conn, user_id, code, true)
            .await?
            .then_some(Method::Totp)),
        (None, Some(recovery)) => Ok(use_recovery_code(state, conn, user_id, recovery)
            .await?
            .then_some(Method::RecoveryCode)),
        _ => Err(ApiError::BadRequest("one_factor_required")),
    }
}

async fn mark_session(
    conn: &mut PgConnection,
    user: Uuid,
    family_id: Uuid,
    method: Method,
) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO session_factors (family_id, user_id, method) VALUES ($1, $2, $3)
         ON CONFLICT (family_id) DO UPDATE SET method = EXCLUDED.method, verified_at = now()
          WHERE session_factors.user_id = EXCLUDED.user_id",
    )
    .bind(family_id)
    .bind(user)
    .bind(method.as_str())
    .execute(conn)
    .await?;
    Ok(())
}

/// Kimlik bilgisi sürümünü artırır ve bekleyen ikinci adım biletlerini geçersiz kılar (SES-04).
async fn bump_credentials(conn: &mut PgConnection, user_id: Uuid) -> ApiResult<()> {
    sqlx::query(
        "UPDATE users SET credential_version = credential_version + 1, updated_at = now()
          WHERE id = $1",
    )
    .bind(user_id)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE mfa_challenges SET consumed_at = now() WHERE user_id = $1 AND consumed_at IS NULL",
    )
    .bind(user_id)
    .execute(conn)
    .await?;
    Ok(())
}

async fn totp_enabled(conn: &mut PgConnection, user_id: Uuid) -> ApiResult<bool> {
    let row: Option<(i32,)> =
        sqlx::query_as("SELECT 1 FROM user_totp WHERE user_id = $1 AND confirmed_at IS NOT NULL")
            .bind(user_id)
            .fetch_optional(conn)
            .await?;
    Ok(row.is_some())
}

/// Hesap başına birikimli ikinci adım hata sınırı (AUT-02): doluysa deneme yapılmaz. Denetim
/// çağıranın işleminde ve kilitlidir: aynı hesabın eşzamanlı denemeleri sınırı aşamaz ve işlem
/// açıkken havuzdan ikinci bağlantı istenmez.
async fn ensure_mfa_attempts(
    conn: &mut PgConnection,
    state: &AppState,
    user_id: Uuid,
) -> ApiResult<()> {
    rate_limit::lock_and_ensure_available(
        conn,
        &state.hmac_secret,
        rate_limit::MFA_FAILURES_PER_USER,
        &user_id.to_string(),
    )
    .await
}

/// Başarısız ikinci adım denemesini hesap başına sayar.
async fn count_mfa_failure(
    conn: &mut PgConnection,
    state: &AppState,
    user_id: Uuid,
) -> ApiResult<()> {
    rate_limit::record_failure(
        conn,
        &state.hmac_secret,
        rate_limit::MFA_FAILURES_PER_USER,
        &user_id.to_string(),
    )
    .await
}

/// Hassas hesap işlemleri (dışa aktarma, numara değişimi, silme) için adım yükseltme: kullanıcının
/// faktörü açıksa bu oturumda ikinci adım tamamlanmış olmalı (AUT-04).
pub(crate) async fn step_up(conn: &mut PgConnection, user: AuthUser) -> ApiResult<()> {
    let (enabled, verified): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM user_totp WHERE user_id = $1 AND confirmed_at IS NOT NULL),
                EXISTS (SELECT 1 FROM session_factors WHERE family_id = $2 AND user_id = $1)",
    )
    .bind(user.user_id)
    .bind(user.session_id)
    .fetch_one(conn)
    .await?;
    if enabled && !verified {
        return Err(ApiError::Forbidden("mfa_required"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Giriş: ikinci adım
// ---------------------------------------------------------------------------------------------

/// Faktörü açık kullanıcı için ikinci adım bileti oluşturur; faktör yoksa `None`. Bilet, parolanın
/// doğrulandığı andaki kimlik bilgisi sürümünü taşır: arada parola sıfırlanırsa bilet oturum açamaz.
pub(super) async fn start_challenge(
    conn: &mut PgConnection,
    user_id: Uuid,
    credential_version: i32,
    device: &DeviceInfo,
) -> ApiResult<Option<Challenge>> {
    if !totp_enabled(conn, user_id).await? {
        return Ok(None);
    }
    let (token, hash) = tokens::new_refresh_token().map_err(|_| ApiError::Internal)?;
    sqlx::query(
        "INSERT INTO mfa_challenges (user_id, token_hash, platform, device_name, expires_at,
                                     credential_version)
         VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5), $6)",
    )
    .bind(user_id)
    .bind(hash)
    .bind(&device.platform)
    .bind(&device.name)
    .bind(CHALLENGE_TTL_SECS as f64)
    .bind(credential_version)
    .execute(&mut *conn)
    .await?;
    record(
        conn,
        user_id,
        "auth.mfa_challenge",
        audit::Outcome::Success,
        json!({ "platform": device.platform }),
    )
    .await?;
    Ok(Some(Challenge {
        mfa_required: true,
        mfa_token: token,
        expires_in: CHALLENGE_TTL_SECS,
    }))
}

/// İkinci adımı tamamlar ve oturumu açar. Yanlış denemeler bilet üzerinde sayılır ve hemen
/// kalıcıdır; 5. yanlış denemede bilet tükenir.
pub async fn verify(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<VerifyRequest>,
) -> ApiResult<Json<TokenResponse>> {
    if request.code.is_some() == request.recovery_code.is_some() {
        return Err(ApiError::BadRequest("one_factor_required"));
    }
    let hash = tokens::refresh_token_hash(&request.mfa_token).ok_or(ApiError::Unauthorized)?;
    {
        let mut conn = state.db.acquire().await?;
        rate_limit::hit(
            &mut conn,
            &state.hmac_secret,
            rate_limit::MFA_PER_IP,
            &ip_of(&addr),
        )
        .await?;
    }

    let mut tx = state.db.begin().await?;
    let challenge: Option<(Uuid, Uuid, String, Option<String>, i32)> = sqlx::query_as(
        "SELECT c.id, c.user_id, c.platform, c.device_name, c.credential_version
           FROM mfa_challenges c
           JOIN users u ON u.id = c.user_id AND u.status IN ('active', 'pending_deletion')
          WHERE c.token_hash = $1 AND c.consumed_at IS NULL AND c.expires_at > now()
            AND c.attempts < $2
          FOR UPDATE OF c",
    )
    .bind(&hash)
    .bind(CHALLENGE_MAX_ATTEMPTS)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((challenge_id, user_id, platform, device_name, credential_version)) = challenge else {
        tx.commit().await?;
        return Err(ApiError::Unauthorized);
    };
    // Sınırlar biletin işleminde: işlem ve bilet kilidi açıkken havuzdan ikinci bağlantı istenmez.
    rate_limit::hit(
        &mut tx,
        &state.hmac_secret,
        rate_limit::MFA_PER_USER,
        &user_id.to_string(),
    )
    .await?;
    ensure_mfa_attempts(&mut tx, &state, user_id).await?;

    let method = check_factor(
        &state,
        &mut tx,
        user_id,
        request.code.as_deref(),
        request.recovery_code.as_deref(),
    )
    .await?;
    let Some(method) = method else {
        sqlx::query(
            "UPDATE mfa_challenges
                SET attempts = attempts + 1,
                    consumed_at = CASE WHEN attempts + 1 >= $2 THEN now() ELSE NULL END
              WHERE id = $1",
        )
        .bind(challenge_id)
        .bind(CHALLENGE_MAX_ATTEMPTS)
        .execute(&mut *tx)
        .await?;
        count_mfa_failure(&mut tx, &state, user_id).await?;
        record(
            &mut tx,
            user_id,
            "auth.mfa_failed",
            audit::Outcome::Failure,
            json!({}),
        )
        .await?;
        tx.commit().await?;
        return Err(ApiError::BadRequest("invalid_code"));
    };

    sqlx::query("UPDATE mfa_challenges SET consumed_at = now() WHERE id = $1")
        .bind(challenge_id)
        .execute(&mut *tx)
        .await?;
    // Bilet açıldıktan sonra parola sıfırlandıysa veya hesap kapatıldıysa oturum açılmaz.
    if let Err(error) =
        handlers::ensure_credentials_unchanged(&mut tx, user_id, credential_version).await
    {
        tx.commit().await?;
        return Err(error);
    }
    let device = DeviceInfo {
        platform,
        name: device_name,
    };
    let (session_id, refresh_token) = create_session(&mut tx, user_id, &device).await?;
    mark_session(&mut tx, user_id, session_id, method).await?;
    let cancelled = crate::privacy::cancel_scheduled_erasure(&mut tx, user_id).await?;
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: None,
            actor_user_id: Some(user_id),
            action: "auth.login",
            target_type: Some("session"),
            target_id: Some(&session_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({ "platform": device.platform, "mfa": method.as_str() }),
        },
    )
    .await?;
    let phone = phone_of(&mut tx, user_id).await?;
    tx.commit().await?;
    if cancelled {
        notify(&state, phone.clone(), crate::privacy::SMS_ERASURE_CANCELLED);
    }
    if matches!(method, Method::RecoveryCode) {
        notify(&state, phone, SMS_RECOVERY_USED);
    }
    Ok(Json(token_response(
        &state,
        user_id,
        session_id,
        refresh_token,
    )?))
}

// ---------------------------------------------------------------------------------------------
// Faktör yönetimi
// ---------------------------------------------------------------------------------------------

pub async fn status(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Status>> {
    let mut conn = state.db.acquire().await?;
    let (confirmed, remaining, verified): (Option<bool>, i64, bool) = sqlx::query_as(
        "SELECT (SELECT confirmed_at IS NOT NULL FROM user_totp WHERE user_id = $1),
                (SELECT count(*) FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL),
                EXISTS (SELECT 1 FROM session_factors WHERE family_id = $2 AND user_id = $1)",
    )
    .bind(user.user_id)
    .bind(user.session_id)
    .fetch_one(&mut *conn)
    .await?;
    Ok(Json(Status {
        totp: match confirmed {
            None => "none",
            Some(false) => "pending",
            Some(true) => "enabled",
        },
        recovery_codes_remaining: remaining,
        session_verified: verified,
    }))
}

/// Kurulumu başlatır: yeni sır üretir, şifreli saklar ve bir kez gösterir. Onaylanana kadar
/// girişte istenmez. Faktör zaten açıksa önce kapatılmalıdır.
pub async fn setup(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<PasswordRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    require_password(&state, user.user_id, request.password, "mfa.reauth").await?;
    let mut tx = state.db.begin().await?;
    let existing: Option<(bool,)> = sqlx::query_as(
        "SELECT confirmed_at IS NOT NULL FROM user_totp WHERE user_id = $1 FOR UPDATE",
    )
    .bind(user.user_id)
    .fetch_optional(&mut *tx)
    .await?;
    if matches!(existing, Some((true,))) {
        return Err(ApiError::Conflict("mfa_already_enabled"));
    }

    let secret = totp::generate_secret().map_err(|_| ApiError::Internal)?;
    let sealed = state
        .totp_key
        .seal(user.user_id.as_bytes(), &secret)
        .map_err(|_| ApiError::Internal)?;
    sqlx::query(
        "INSERT INTO user_totp (user_id, key_version, nonce, secret_ct) VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id) DO UPDATE
            SET key_version = EXCLUDED.key_version, nonce = EXCLUDED.nonce,
                secret_ct = EXCLUDED.secret_ct, confirmed_at = NULL, last_step = NULL,
                created_at = now()",
    )
    .bind(user.user_id)
    .bind(sealed.key_version)
    .bind(sealed.nonce.as_slice())
    .bind(&sealed.ciphertext)
    .execute(&mut *tx)
    .await?;
    let phone = phone_of(&mut tx, user.user_id).await?;
    record(
        &mut tx,
        user.user_id,
        "mfa.setup_started",
        audit::Outcome::Success,
        json!({}),
    )
    .await?;
    tx.commit().await?;

    let account = phone
        .as_deref()
        .map(mask_phone)
        .unwrap_or_else(|| "hesap".to_owned());
    Ok(Json(json!({
        "secret": totp::base32_encode(&secret),
        "otpauth_uri": totp::otpauth_uri(&secret, &account),
    })))
}

/// Kurulumu bir kodla onaylar; kurtarma kodlarını bir kez gösterir. Bu oturum ikinci adımı
/// tamamlamış sayılır; diğer oturumlar sayılmaz.
pub async fn confirm(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<CodeRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    {
        let mut conn = state.db.acquire().await?;
        rate_limit::hit(
            &mut conn,
            &state.hmac_secret,
            rate_limit::MFA_PER_USER,
            &user.user_id.to_string(),
        )
        .await?;
    }
    let mut tx = state.db.begin().await?;
    ensure_mfa_attempts(&mut tx, &state, user.user_id).await?;
    if !check_totp(&state, &mut tx, user.user_id, &request.code, false).await? {
        count_mfa_failure(&mut tx, &state, user.user_id).await?;
        record(
            &mut tx,
            user.user_id,
            "mfa.confirm",
            audit::Outcome::Failure,
            json!({}),
        )
        .await?;
        tx.commit().await?;
        return Err(ApiError::BadRequest("invalid_code"));
    }
    sqlx::query("UPDATE user_totp SET confirmed_at = now() WHERE user_id = $1")
        .bind(user.user_id)
        .execute(&mut *tx)
        .await?;
    let codes = replace_recovery_codes(&state, &mut tx, user.user_id).await?;
    mark_session(&mut tx, user.user_id, user.session_id, Method::Totp).await?;
    // MFA'yı açan oturum dışındaki bütün oturumlar kapanır: parola çalındıysa saldırganın açık
    // oturumu ikinci faktörden sonra yaşamaya devam etmez (SES-04). Kapanan cihazlara bildirim
    // gitmez. Kimlik bilgisi sürümü artar: parolası şu an doğrulanmakta olan bir giriş, ikinci
    // faktör sormadan oturum açamaz.
    bump_credentials(&mut tx, user.user_id).await?;
    let ended =
        handlers::revoke_user_sessions(&mut tx, user.user_id, Some(user.session_id)).await?;
    let phone = phone_of(&mut tx, user.user_id).await?;
    record(
        &mut tx,
        user.user_id,
        "mfa.enabled",
        audit::Outcome::Success,
        json!({ "method": "totp", "revoked_tokens": ended }),
    )
    .await?;
    tx.commit().await?;
    notify(&state, phone, SMS_ENABLED);
    Ok(Json(json!({ "recovery_codes": codes })))
}

/// Faktörü kapatır: parola ve geçerli bir TOTP veya kurtarma kodu gerekir. Bütün oturumların
/// ikinci adım kaydı silinir.
pub async fn disable(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<FactorRequest>,
) -> ApiResult<StatusCode> {
    require_password(&state, user.user_id, request.password, "mfa.reauth").await?;
    {
        let mut conn = state.db.acquire().await?;
        rate_limit::hit(
            &mut conn,
            &state.hmac_secret,
            rate_limit::MFA_PER_USER,
            &user.user_id.to_string(),
        )
        .await?;
    }
    let mut tx = state.db.begin().await?;
    ensure_mfa_attempts(&mut tx, &state, user.user_id).await?;
    if !totp_enabled(&mut tx, user.user_id).await? {
        return Err(ApiError::Conflict("mfa_not_enabled"));
    }
    let method = check_factor(
        &state,
        &mut tx,
        user.user_id,
        request.code.as_deref(),
        request.recovery_code.as_deref(),
    )
    .await?;
    if method.is_none() {
        count_mfa_failure(&mut tx, &state, user.user_id).await?;
        record(
            &mut tx,
            user.user_id,
            "mfa.disable",
            audit::Outcome::Failure,
            json!({}),
        )
        .await?;
        tx.commit().await?;
        return Err(ApiError::BadRequest("invalid_code"));
    }
    for statement in [
        "DELETE FROM user_totp WHERE user_id = $1",
        "DELETE FROM recovery_codes WHERE user_id = $1",
        "DELETE FROM session_factors WHERE user_id = $1",
        "DELETE FROM mfa_challenges WHERE user_id = $1",
    ] {
        sqlx::query(statement)
            .bind(user.user_id)
            .execute(&mut *tx)
            .await?;
    }
    bump_credentials(&mut tx, user.user_id).await?;
    let phone = phone_of(&mut tx, user.user_id).await?;
    record(
        &mut tx,
        user.user_id,
        "mfa.disabled",
        audit::Outcome::Success,
        json!({}),
    )
    .await?;
    tx.commit().await?;
    notify(&state, phone, SMS_DISABLED);
    Ok(StatusCode::NO_CONTENT)
}

/// Kurtarma kodlarını yeniler (eskiler geçersiz olur): parola ve geçerli bir TOTP kodu gerekir.
pub async fn regenerate_recovery_codes(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<FactorRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    if request.recovery_code.is_some() || request.code.is_none() {
        return Err(ApiError::BadRequest("totp_code_required"));
    }
    require_password(&state, user.user_id, request.password, "mfa.reauth").await?;
    {
        let mut conn = state.db.acquire().await?;
        rate_limit::hit(
            &mut conn,
            &state.hmac_secret,
            rate_limit::MFA_PER_USER,
            &user.user_id.to_string(),
        )
        .await?;
    }
    let mut tx = state.db.begin().await?;
    ensure_mfa_attempts(&mut tx, &state, user.user_id).await?;
    let code = request.code.unwrap_or_default();
    if !check_totp(&state, &mut tx, user.user_id, &code, true).await? {
        count_mfa_failure(&mut tx, &state, user.user_id).await?;
        tx.commit().await?;
        return Err(ApiError::BadRequest("invalid_code"));
    }
    let codes = replace_recovery_codes(&state, &mut tx, user.user_id).await?;
    record(
        &mut tx,
        user.user_id,
        "mfa.recovery_codes_regenerated",
        audit::Outcome::Success,
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({ "recovery_codes": codes })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_codes_use_the_alphabet_and_normalize() {
        let code = generate_recovery_code().expect("kod");
        assert_eq!(code.len(), RECOVERY_CODE_LEN);
        assert!(code.bytes().all(|b| RECOVERY_ALPHABET.contains(&b)));
        let shown = format!("{}-{}", &code[..5], &code[5..]).to_uppercase();
        assert_eq!(normalize_recovery(&shown).as_deref(), Some(code.as_str()));
        assert_eq!(normalize_recovery("abcde-fghj"), None);
        assert_eq!(normalize_recovery("abcde-fgh0k"), None);
        assert_ne!(generate_recovery_code().expect("kod"), code);
    }
}
