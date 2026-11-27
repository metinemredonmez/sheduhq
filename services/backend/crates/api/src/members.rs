//! Organizasyon üyeleri: listeleme, rol değiştirme, çıkarma ve ayrılma.
//!
//! Kurallar (AZ-05):
//! - Kimse kendi rolünü değiştiremez.
//! - Yalnızca kendinden alt roldeki biri yönetilir ve yalnızca kendinden alt bir rol atanır: sahip
//!   yöneticiyi ve üyeyi, yönetici yalnızca üyeyi yönetir. Yönetici başkasını yönetici yapamaz.
//! - Sahip tektir; çıkarılamaz, rolü değiştirilemez, ayrılamaz (veritabanı da engeller).
//!
//! Değişiklik hemen geçerlidir (SES-04): rol ve üyelik her istekte, her WebSocket mesajında ve her
//! push gönderiminde veritabanından okunur. Üyelik silinince panel yetkileri de silinir; yetkisini
//! kaybeden kişinin gönderdiği açık davetler iptal edilir.

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    AppState, audit,
    auth::AuthUser,
    authz::{self, Role},
    error::{ApiError, ApiResult},
    invitations,
    sms::mask_phone,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/organizations/{org_id}/members", get(list))
        .route(
            "/organizations/{org_id}/members/{user_id}",
            axum::routing::patch(change_role).delete(remove),
        )
}

#[derive(sqlx::FromRow)]
struct MemberRow {
    user_id: Uuid,
    display_name: String,
    phone: Option<String>,
    role: String,
    joined_at: DateTime<Utc>,
}

/// Yöneticinin gördüğü üye: numara maskelenir (API-02).
#[derive(Serialize)]
pub struct MemberView {
    user_id: Uuid,
    display_name: String,
    phone_masked: Option<String>,
    role: String,
    joined_at: DateTime<Utc>,
    is_you: bool,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum AssignableRole {
    Admin,
    Member,
}

impl AssignableRole {
    fn role(self) -> Role {
        match self {
            Self::Admin => Role::Admin,
            Self::Member => Role::Member,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeRoleRequest {
    role: AssignableRole,
}

/// Üye listesi yalnızca yöneticilere açıktır.
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    if !ctx.role.is_manager() {
        return Err(ApiError::Forbidden("not_permitted"));
    }
    let rows: Vec<MemberRow> = sqlx::query_as(
        "SELECT m.user_id, u.display_name, u.phone, m.role, m.created_at AS joined_at
           FROM memberships m JOIN users u ON u.id = m.user_id
          WHERE m.organization_id = $1
          ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, m.created_at",
    )
    .bind(org_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let members: Vec<MemberView> = rows
        .into_iter()
        .map(|row| MemberView {
            is_you: row.user_id == ctx.user.user_id,
            user_id: row.user_id,
            display_name: row.display_name,
            phone_masked: row.phone.as_deref().map(mask_phone),
            role: row.role,
            joined_at: row.joined_at,
        })
        .collect();
    Ok(Json(json!({ "members": members })))
}

pub async fn change_role(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_id, target_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<ChangeRoleRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let new_role = request.role.role();
    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    if target_id == ctx.user.user_id {
        return Err(ApiError::Forbidden("cannot_change_self"));
    }

    // Satır kilidi: aynı üyeye eşzamanlı iki değişiklik sırayla işlenir (BUS-02).
    let current: Option<(String,)> = sqlx::query_as(
        "SELECT role FROM memberships WHERE user_id = $1 AND organization_id = $2 FOR UPDATE",
    )
    .bind(target_id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?;
    let current = match current {
        Some((role,)) => Role::parse(&role).ok_or(ApiError::Internal)?,
        // Yönetici olmayan biri üye listesini göremediği için varlığı da öğrenemez.
        None if ctx.role.is_manager() => return Err(ApiError::NotFound),
        None => return Err(ApiError::Forbidden("not_permitted")),
    };

    if !ctx.role.outranks(current) || !ctx.role.outranks(new_role) {
        audit::record(
            &mut tx,
            audit::Event {
                organization_id: Some(org_id),
                actor_user_id: Some(ctx.user.user_id),
                action: "member.role_change",
                target_type: Some("user"),
                target_id: Some(&target_id.to_string()),
                outcome: audit::Outcome::Denied,
                details: json!({ "from": current.as_str(), "to": new_role.as_str() }),
            },
        )
        .await?;
        tx.commit().await?;
        return Err(ApiError::Forbidden("not_permitted"));
    }
    if current == new_role {
        tx.commit().await?;
        return Ok(Json(
            json!({ "user_id": target_id, "role": new_role.as_str() }),
        ));
    }

    sqlx::query("UPDATE memberships SET role = $3 WHERE user_id = $1 AND organization_id = $2")
        .bind(target_id)
        .bind(org_id)
        .bind(new_role.as_str())
        .execute(&mut *tx)
        .await?;
    if current.is_manager() && !new_role.is_manager() {
        invitations::revoke_sent_by(&mut tx, org_id, target_id).await?;
    }
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: Some(org_id),
            actor_user_id: Some(ctx.user.user_id),
            action: "member.role_changed",
            target_type: Some("user"),
            target_id: Some(&target_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({ "from": current.as_str(), "to": new_role.as_str() }),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({ "user_id": target_id, "role": new_role.as_str() }),
    ))
}

/// Üyeyi çıkarır; kullanıcı kendi kimliğiyle çağırırsa organizasyondan ayrılır.
pub async fn remove(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_id, target_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    let leaving = target_id == ctx.user.user_id;
    if !leaving && !ctx.role.is_manager() {
        return Err(ApiError::Forbidden("not_permitted"));
    }

    let current: Option<(String,)> = sqlx::query_as(
        "SELECT role FROM memberships WHERE user_id = $1 AND organization_id = $2 FOR UPDATE",
    )
    .bind(target_id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?;
    let (current,) = current.ok_or(ApiError::NotFound)?;
    let current = Role::parse(&current).ok_or(ApiError::Internal)?;

    if leaving && current == Role::Owner {
        return Err(ApiError::Conflict("owner_cannot_leave"));
    }
    if !leaving && !ctx.role.outranks(current) {
        audit::record(
            &mut tx,
            audit::Event {
                organization_id: Some(org_id),
                actor_user_id: Some(ctx.user.user_id),
                action: "member.remove",
                target_type: Some("user"),
                target_id: Some(&target_id.to_string()),
                outcome: audit::Outcome::Denied,
                details: json!({ "role": current.as_str() }),
            },
        )
        .await?;
        tx.commit().await?;
        return Err(ApiError::Forbidden("not_permitted"));
    }

    // Panel yetkileri yabancı anahtarla birlikte silinir.
    let (grants,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM access_grants WHERE user_id = $1 AND organization_id = $2",
    )
    .bind(target_id)
    .bind(org_id)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM memberships WHERE user_id = $1 AND organization_id = $2")
        .bind(target_id)
        .bind(org_id)
        .execute(&mut *tx)
        .await?;
    let revoked = invitations::revoke_sent_by(&mut tx, org_id, target_id).await?;
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: Some(org_id),
            actor_user_id: Some(ctx.user.user_id),
            action: if leaving {
                "member.left"
            } else {
                "member.removed"
            },
            target_type: Some("user"),
            target_id: Some(&target_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({
                "role": current.as_str(),
                "grants_removed": grants,
                "invitations_revoked": revoked,
            }),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
