//! Davetler: bir organizasyonun yöneticisi telefon numarasıyla kişi davet eder; o numarayı SMS
//! koduyla doğrulamış hesap daveti uygulamada görür, kabul eder veya reddeder.
//!
//! Davet bağlantı ya da kod taşımaz, yani çalınacak bir davet token'ı yoktur; davet numaraya ve
//! organizasyona bağlıdır, 7 gün geçerlidir ve tek kez sonuçlanır (AUT-03). Davet SMS'inde
//! kullanıcının yazdığı hiçbir metin (organizasyon veya kişi adı) yer almaz; böylece platform
//! adına oltalama mesajı gönderilemez. Davet oluşturma yanıtı, numaranın kayıtlı olup olmadığını
//! belli etmez.

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{
    AppState, audit,
    auth::{AuthUser, normalize_phone, rate_limit},
    authz::{self, OrgContext, Role},
    db::set_context,
    error::{ApiError, ApiResult, is_unique_violation},
    sms::mask_phone,
};

const TTL_DAYS: i32 = 7;
/// Bir organizasyonda aynı anda açık olabilecek en fazla davet.
const MAX_OPEN: i64 = 50;
const INVITE_SMS: &str = "Shedu: Bir güvenlik hesabına davet edildiniz. Daveti görmek için Shedu \
                          uygulamasında bu telefon numarasıyla oturum açın.";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/organizations/{org_id}/invitations",
            get(list_for_org).post(create),
        )
        .route(
            "/organizations/{org_id}/invitations/{invitation_id}",
            delete(revoke),
        )
        .route("/invitations", get(list_mine))
        .route("/invitations/{invitation_id}/accept", post(accept))
        .route("/invitations/{invitation_id}/decline", post(decline))
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum InvitedRole {
    Admin,
    Member,
    Operator,
}

impl InvitedRole {
    fn role(self) -> Role {
        match self {
            Self::Admin => Role::Admin,
            Self::Member => Role::Member,
            Self::Operator => Role::Operator,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRequest {
    phone: String,
    role: InvitedRole,
}

#[derive(sqlx::FromRow)]
struct OrgInvitationRow {
    id: Uuid,
    phone: String,
    role: String,
    invited_by: Option<Uuid>,
    invited_by_name: Option<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// Yöneticinin gördüğü davet: numara maskelenir (API-02).
#[derive(Serialize)]
pub struct OrgInvitation {
    id: Uuid,
    phone_masked: String,
    role: String,
    invited_by: Option<Uuid>,
    invited_by_name: Option<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// Davet edilen kişinin gördüğü davet.
#[derive(Serialize, sqlx::FromRow)]
pub struct MyInvitation {
    id: Uuid,
    organization_id: Uuid,
    organization_name: String,
    organization_kind: String,
    role: String,
    invited_by_name: Option<String>,
    expires_at: DateTime<Utc>,
}

fn require_manager(ctx: &OrgContext) -> ApiResult<()> {
    if ctx.role.is_manager() {
        Ok(())
    } else {
        Err(ApiError::Forbidden("not_permitted"))
    }
}

async fn record_denied(
    conn: &mut PgConnection,
    ctx: &OrgContext,
    action: &'static str,
    details: serde_json::Value,
) -> ApiResult<()> {
    audit::record(
        conn,
        audit::Event {
            organization_id: Some(ctx.organization_id),
            actor_user_id: Some(ctx.user.user_id),
            action,
            target_type: None,
            target_id: None,
            outcome: audit::Outcome::Denied,
            details,
        },
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Yönetici tarafı
// ---------------------------------------------------------------------------------------------

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Path(org_id): Path<Uuid>,
    Json(request): Json<CreateRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let phone = normalize_phone(&request.phone).ok_or(ApiError::BadRequest("invalid_phone"))?;
    let role = request.role.role();

    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    // Yalnızca kendinden alt bir rol için davet gönderilebilir (AZ-05).
    if !ctx.role.outranks(role) {
        record_denied(
            &mut tx,
            &ctx,
            "invitation.create",
            json!({ "role": role.as_str() }),
        )
        .await?;
        tx.commit().await?;
        return Err(ApiError::Forbidden("not_permitted"));
    }
    if !authz::role_fits(&authz::organization_kind(&mut tx).await?, role) {
        return Err(ApiError::Unprocessable("role_not_allowed"));
    }

    let already_member: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
          WHERE u.phone = $1 AND m.organization_id = $2",
    )
    .bind(&phone)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?;
    if already_member.is_some() {
        return Err(ApiError::Conflict("already_member"));
    }

    // Süresi dolmuş açık davet yenisinin önünü kesmesin.
    sqlx::query(
        "UPDATE invitations SET revoked_at = now()
          WHERE organization_id = $1 AND phone = $2 AND expires_at <= now()
            AND accepted_at IS NULL AND declined_at IS NULL AND revoked_at IS NULL",
    )
    .bind(org_id)
    .bind(&phone)
    .execute(&mut *tx)
    .await?;

    let (open, same_phone): (i64, bool) = sqlx::query_as(
        "SELECT count(*), coalesce(bool_or(phone = $2), false) FROM invitations
          WHERE organization_id = $1 AND expires_at > now()
            AND accepted_at IS NULL AND declined_at IS NULL AND revoked_at IS NULL",
    )
    .bind(org_id)
    .bind(&phone)
    .fetch_one(&mut *tx)
    .await?;
    if same_phone {
        return Err(ApiError::Conflict("invitation_pending"));
    }
    if open >= MAX_OPEN {
        return Err(ApiError::Conflict("too_many_invitations"));
    }

    // Sayaçlar ayrı bağlantıda ve hemen kalıcı: işlem geri alınsa da sayılır.
    {
        let mut conn = state.db.acquire().await?;
        let limits = [
            (rate_limit::INVITE_PER_USER, ctx.user.user_id.to_string()),
            (rate_limit::INVITE_PER_ORG, org_id.to_string()),
            (rate_limit::INVITE_SMS_PER_PHONE, phone.clone()),
            (rate_limit::SMS_GLOBAL, "all".to_owned()),
        ];
        for (budget, value) in limits {
            rate_limit::hit(&mut conn, &state.hmac_secret, budget, &value).await?;
        }
    }

    let inserted: Result<(Uuid, DateTime<Utc>), sqlx::Error> = sqlx::query_as(
        "INSERT INTO invitations (organization_id, phone, role, invited_by, expires_at)
         VALUES ($1, $2, $3, $4, now() + make_interval(days => $5))
         RETURNING id, expires_at",
    )
    .bind(org_id)
    .bind(&phone)
    .bind(role.as_str())
    .bind(ctx.user.user_id)
    .bind(TTL_DAYS)
    .fetch_one(&mut *tx)
    .await;
    let (invitation_id, expires_at) = match inserted {
        Err(error) if is_unique_violation(&error) => {
            return Err(ApiError::Conflict("invitation_pending"));
        }
        other => other?,
    };

    audit::record(
        &mut tx,
        audit::Event {
            organization_id: Some(org_id),
            actor_user_id: Some(ctx.user.user_id),
            action: "invitation.created",
            target_type: Some("invitation"),
            target_id: Some(&invitation_id.to_string()),
            outcome: audit::Outcome::Success,
            // Numaranın kendisi denetim kaydına yazılmaz (LOG-02).
            details: json!({ "role": role.as_str() }),
        },
    )
    .await?;
    tx.commit().await?;

    // Numara kayıtlı olsun olmasın aynı SMS arka planda gider; yanıt süresi bir şey belli etmez.
    let sms = state.sms.clone();
    let to = phone.clone();
    tokio::spawn(async move {
        if sms.send(&to, INVITE_SMS).await.is_err() {
            tracing::error!(phone = %mask_phone(&to), "davet SMS'i gönderilemedi");
        }
    });

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": invitation_id,
            "phone_masked": mask_phone(&phone),
            "role": role.as_str(),
            "expires_at": expires_at,
        })),
    ))
}

pub async fn list_for_org(
    State(state): State<AppState>,
    user: AuthUser,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    require_manager(&ctx)?;
    let rows: Vec<OrgInvitationRow> = sqlx::query_as(
        "SELECT i.id, i.phone, i.role, i.invited_by, u.display_name AS invited_by_name,
                i.created_at, i.expires_at
           FROM invitations i LEFT JOIN users u ON u.id = i.invited_by
          WHERE i.organization_id = $1 AND i.expires_at > now()
            AND i.accepted_at IS NULL AND i.declined_at IS NULL AND i.revoked_at IS NULL
          ORDER BY i.created_at DESC",
    )
    .bind(org_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let invitations: Vec<OrgInvitation> = rows
        .into_iter()
        .map(|row| OrgInvitation {
            id: row.id,
            phone_masked: mask_phone(&row.phone),
            role: row.role,
            invited_by: row.invited_by,
            invited_by_name: row.invited_by_name,
            created_at: row.created_at,
            expires_at: row.expires_at,
        })
        .collect();
    Ok(Json(json!({ "invitations": invitations })))
}

pub async fn revoke(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    require_manager(&ctx)?;
    let role: Option<(String,)> = sqlx::query_as(
        "SELECT role FROM invitations
          WHERE id = $1 AND organization_id = $2
            AND accepted_at IS NULL AND declined_at IS NULL AND revoked_at IS NULL
          FOR UPDATE",
    )
    .bind(invitation_id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?;
    let (role,) = role.ok_or(ApiError::NotFound)?;
    let role = Role::parse(&role).ok_or(ApiError::Internal)?;
    if !ctx.role.outranks(role) {
        return Err(ApiError::Forbidden("not_permitted"));
    }
    sqlx::query("UPDATE invitations SET revoked_at = now() WHERE id = $1")
        .bind(invitation_id)
        .execute(&mut *tx)
        .await?;
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: Some(org_id),
            actor_user_id: Some(ctx.user.user_id),
            action: "invitation.revoked",
            target_type: Some("invitation"),
            target_id: Some(&invitation_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({}),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Yetkisini kaybeden (rolü düşürülen veya çıkarılan) kişinin açık davetlerini iptal eder.
pub(crate) async fn revoke_sent_by(
    conn: &mut PgConnection,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE invitations SET revoked_at = now()
          WHERE organization_id = $1 AND invited_by = $2
            AND accepted_at IS NULL AND declined_at IS NULL AND revoked_at IS NULL",
    )
    .bind(org_id)
    .bind(user_id)
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}

// ---------------------------------------------------------------------------------------------
// Davet edilen taraf
// ---------------------------------------------------------------------------------------------

/// Kullanıcının doğrulanmış numarasına gelen açık davetler. Organizasyon bağlamı yoktur;
/// veritabanı yalnızca bu numaraya ait davetleri ve onların organizasyon adını gösterir (AZ-02).
pub async fn list_mine(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<serde_json::Value>> {
    let mut tx = state.db.begin().await?;
    set_context(&mut tx, Some(user.user_id), None).await?;
    let invitations: Vec<MyInvitation> = sqlx::query_as(
        "SELECT i.id, i.organization_id, o.name AS organization_name, o.kind AS organization_kind,
                i.role, u.display_name AS invited_by_name, i.expires_at
           FROM invitations i
           JOIN organizations o ON o.id = i.organization_id
           LEFT JOIN users u ON u.id = i.invited_by
          WHERE i.phone = app_current_user_phone() AND i.expires_at > now()
            AND i.accepted_at IS NULL AND i.declined_at IS NULL AND i.revoked_at IS NULL
          ORDER BY i.created_at DESC",
    )
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(json!({ "invitations": invitations })))
}

/// Daveti kabul eder. Tek işlemde: davet atomik olarak kapatılır, üyelik eklenir. Davet eden
/// kişinin o rolü verme yetkisi kabul anında yeniden doğrulanır; yetkisini kaybetmiş birinin
/// daveti geçersizdir (SES-04, AZ-05). Bulunamayan, süresi dolmuş, başkasına ait ve geçersiz
/// davet aynı yanıtı alır.
pub async fn accept(
    State(state): State<AppState>,
    user: AuthUser,
    Path(invitation_id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let mut tx = state.db.begin().await?;
    set_context(&mut tx, Some(user.user_id), None).await?;
    // Davet edenin hesap satırı paylaşımlı kilitlenir. Davet edenin aynı anda başlattığı silme
    // talebi hesap satırını önce kilitler: ya kabul talepten önce biter (talep yeni üyeyi görür ve
    // sahipliğin devrini ister) ya da talepten sonra sıralanır ve kapanmış hesabın davetini
    // reddeder (AZ-03). Kilit sırası her yolda aynı: önce hesap, sonra davet.
    sqlx::query(
        "SELECT 1 FROM users
          WHERE id = (SELECT invited_by FROM invitations
                       WHERE id = $1 AND phone = app_current_user_phone())
          FOR SHARE",
    )
    .bind(invitation_id)
    .execute(&mut *tx)
    .await?;
    let accepted: Option<(Uuid, String)> = sqlx::query_as(
        "UPDATE invitations i SET accepted_at = now(), accepted_by = $2
          WHERE i.id = $1 AND i.phone = app_current_user_phone() AND i.expires_at > now()
            AND i.accepted_at IS NULL AND i.declined_at IS NULL AND i.revoked_at IS NULL
            AND EXISTS (SELECT 1 FROM users iu WHERE iu.id = i.invited_by AND iu.status = 'active')
            AND EXISTS (SELECT 1 FROM memberships m
                         WHERE m.user_id = i.invited_by AND m.organization_id = i.organization_id
                           AND (m.role = 'owner' OR (m.role = 'admin' AND i.role IN ('member', 'operator'))))
          RETURNING i.organization_id, i.role",
    )
    .bind(invitation_id)
    .bind(user.user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let (org_id, role) = accepted.ok_or(ApiError::NotFound)?;

    let inserted = sqlx::query(
        "INSERT INTO memberships (user_id, organization_id, role) VALUES ($1, $2, $3)
         ON CONFLICT (user_id, organization_id) DO NOTHING",
    )
    .bind(user.user_id)
    .bind(org_id)
    .bind(&role)
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        // İşlem geri alınır; davet açık kalır.
        return Err(ApiError::Conflict("already_member"));
    }

    set_context(&mut tx, Some(user.user_id), Some(org_id)).await?;
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: Some(org_id),
            actor_user_id: Some(user.user_id),
            action: "invitation.accepted",
            target_type: Some("invitation"),
            target_id: Some(&invitation_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({ "role": role }),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({ "organization_id": org_id, "role": role })))
}

pub async fn decline(
    State(state): State<AppState>,
    user: AuthUser,
    Path(invitation_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let mut tx = state.db.begin().await?;
    set_context(&mut tx, Some(user.user_id), None).await?;
    let declined: Option<(Uuid,)> = sqlx::query_as(
        "UPDATE invitations SET declined_at = now()
          WHERE id = $1 AND phone = app_current_user_phone() AND expires_at > now()
            AND accepted_at IS NULL AND declined_at IS NULL AND revoked_at IS NULL
          RETURNING organization_id",
    )
    .bind(invitation_id)
    .fetch_optional(&mut *tx)
    .await?;
    let (org_id,) = declined.ok_or(ApiError::NotFound)?;
    set_context(&mut tx, Some(user.user_id), Some(org_id)).await?;
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: Some(org_id),
            actor_user_id: Some(user.user_id),
            action: "invitation.declined",
            target_type: Some("invitation"),
            target_id: Some(&invitation_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({}),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
