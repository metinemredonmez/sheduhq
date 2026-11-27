//! Panel yetkileri: kim, hangi panelde veya bölümde, neyi, hangi gün ve saatlerde yapabilir.
//!
//! Yalnızca yöneticiler yetki verir, değiştirir ve kaldırır; üye kendi yetkilerini görebilir.
//! Yöneticiler zaten bütün panellerde tam yetkilidir, onlara ayrıca yetki verilmez; böylece
//! kimse kendine yetki veremez (AZ-05). Gövdedeki her kimlik organizasyon içinde doğrulanır:
//! üye, panel ve bölüm (AZ-04); veritabanı da başka kiracının paneline ve üye olmayana yetkiyi
//! engeller. Yetkinin kapsamı (kişi, panel, bölüm) sonradan değiştirilemez; değiştirme isteği
//! yalnızca izinleri, geçerlilik süresini ve pencereleri taşır (API-02).

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, put},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{
    AppState, audit,
    auth::AuthUser,
    authz::{self, OrgContext, Role},
    error::{ApiError, ApiResult, is_unique_violation},
};

/// Bir yetkideki en fazla pencere (haftanın her günü için dört aralık).
const MAX_WINDOWS: usize = 28;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/organizations/{org_id}/members/{user_id}/grants",
            get(list).post(create),
        )
        .route(
            "/organizations/{org_id}/grants/{grant_id}",
            put(update).delete(remove),
        )
}

#[derive(Deserialize, Serialize, Clone, Copy)]
#[serde(deny_unknown_fields)]
pub struct Window {
    /// ISO 8601: 1 = Pazartesi, 7 = Pazar.
    day: i16,
    start_minute: i16,
    /// Hariç; `start_minute`'tan küçükse pencere gece yarısını aşar.
    end_minute: i16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRequest {
    panel_id: Uuid,
    /// Yoksa panelin bütün bölümleri.
    partition_id: Option<Uuid>,
    can_view_events: bool,
    can_arm: bool,
    can_disarm: bool,
    can_bypass: bool,
    always_open: bool,
    valid_from: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    windows: Vec<Window>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateRequest {
    can_view_events: bool,
    can_arm: bool,
    can_disarm: bool,
    can_bypass: bool,
    always_open: bool,
    valid_from: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    windows: Vec<Window>,
}

/// Yetkinin değiştirilebilir kısmı.
struct Terms {
    can_view_events: bool,
    can_arm: bool,
    can_disarm: bool,
    can_bypass: bool,
    always_open: bool,
    valid_from: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    windows: Vec<Window>,
}

impl From<UpdateRequest> for Terms {
    fn from(r: UpdateRequest) -> Self {
        Self {
            can_view_events: r.can_view_events,
            can_arm: r.can_arm,
            can_disarm: r.can_disarm,
            can_bypass: r.can_bypass,
            always_open: r.always_open,
            valid_from: r.valid_from,
            expires_at: r.expires_at,
            windows: r.windows,
        }
    }
}

impl Terms {
    fn validate(&self, now: DateTime<Utc>) -> ApiResult<()> {
        let acts = self.can_arm || self.can_disarm || self.can_bypass;
        if !acts && !self.can_view_events {
            return Err(ApiError::BadRequest("empty_grant"));
        }
        // Görmeden kurma/kapatma yapılamaz; komut önce görme yetkisini ister.
        if acts && !self.can_view_events {
            return Err(ApiError::BadRequest("actions_require_view"));
        }
        if self.always_open && !self.windows.is_empty() {
            return Err(ApiError::BadRequest("windows_with_always_open"));
        }
        if self.windows.len() > MAX_WINDOWS {
            return Err(ApiError::BadRequest("too_many_windows"));
        }
        let valid_window = |w: &Window| {
            (1..=7).contains(&w.day)
                && (0..=1439).contains(&w.start_minute)
                && (0..=1439).contains(&w.end_minute)
                && w.start_minute != w.end_minute
        };
        if !self.windows.iter().all(valid_window) {
            return Err(ApiError::BadRequest("invalid_window"));
        }
        if let (Some(from), Some(to)) = (self.valid_from, self.expires_at)
            && to <= from
        {
            return Err(ApiError::BadRequest("invalid_range"));
        }
        if self.expires_at.is_some_and(|to| to <= now) {
            return Err(ApiError::BadRequest("expires_in_past"));
        }
        Ok(())
    }

    fn summary(&self) -> serde_json::Value {
        json!({
            "can_view_events": self.can_view_events,
            "can_arm": self.can_arm,
            "can_disarm": self.can_disarm,
            "can_bypass": self.can_bypass,
            "always_open": self.always_open,
            "valid_from": self.valid_from,
            "expires_at": self.expires_at,
            "windows": self.windows.len(),
        })
    }
}

#[derive(sqlx::FromRow)]
struct GrantRow {
    id: Uuid,
    user_id: Uuid,
    panel_id: Uuid,
    partition_id: Option<Uuid>,
    can_view_events: bool,
    can_arm: bool,
    can_disarm: bool,
    can_bypass: bool,
    always_open: bool,
    valid_from: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct GrantView {
    id: Uuid,
    user_id: Uuid,
    panel_id: Uuid,
    partition_id: Option<Uuid>,
    can_view_events: bool,
    can_arm: bool,
    can_disarm: bool,
    can_bypass: bool,
    always_open: bool,
    valid_from: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    windows: Vec<Window>,
    created_at: DateTime<Utc>,
}

/// Yetki satırını okuyan sorgu; `$tail` koşul ve sıralamadır.
macro_rules! select_grants {
    ($tail:literal) => {
        concat!(
            "SELECT id, user_id, panel_id, partition_id, can_view_events, can_arm, can_disarm,
                    can_bypass, always_open, valid_from, expires_at, created_at
               FROM access_grants ",
            $tail
        )
    };
}

async fn load_views(conn: &mut PgConnection, rows: Vec<GrantRow>) -> ApiResult<Vec<GrantView>> {
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let windows: Vec<(Uuid, i16, i16, i16)> = sqlx::query_as(
        "SELECT grant_id, day, start_minute, end_minute FROM access_windows
          WHERE grant_id = ANY($1) ORDER BY day, start_minute",
    )
    .bind(&ids)
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| GrantView {
            windows: windows
                .iter()
                .filter(|w| w.0 == r.id)
                .map(|w| Window {
                    day: w.1,
                    start_minute: w.2,
                    end_minute: w.3,
                })
                .collect(),
            id: r.id,
            user_id: r.user_id,
            panel_id: r.panel_id,
            partition_id: r.partition_id,
            can_view_events: r.can_view_events,
            can_arm: r.can_arm,
            can_disarm: r.can_disarm,
            can_bypass: r.can_bypass,
            always_open: r.always_open,
            valid_from: r.valid_from,
            expires_at: r.expires_at,
            created_at: r.created_at,
        })
        .collect())
}

async fn load_one(conn: &mut PgConnection, id: Uuid) -> ApiResult<GrantView> {
    let row: GrantRow = sqlx::query_as(select_grants!("WHERE id = $1"))
        .bind(id)
        .fetch_one(&mut *conn)
        .await?;
    load_views(conn, vec![row])
        .await?
        .pop()
        .ok_or(ApiError::Internal)
}

async fn replace_windows(
    conn: &mut PgConnection,
    org_id: Uuid,
    grant_id: Uuid,
    windows: &[Window],
) -> ApiResult<()> {
    sqlx::query("DELETE FROM access_windows WHERE grant_id = $1")
        .bind(grant_id)
        .execute(&mut *conn)
        .await?;
    if windows.is_empty() {
        return Ok(());
    }
    let days: Vec<i16> = windows.iter().map(|w| w.day).collect();
    let starts: Vec<i16> = windows.iter().map(|w| w.start_minute).collect();
    let ends: Vec<i16> = windows.iter().map(|w| w.end_minute).collect();
    sqlx::query(
        "INSERT INTO access_windows (organization_id, grant_id, day, start_minute, end_minute)
         SELECT $1, $2, d, s, e FROM unnest($3::smallint[], $4::smallint[], $5::smallint[]) AS t(d, s, e)",
    )
    .bind(org_id)
    .bind(grant_id)
    .bind(&days)
    .bind(&starts)
    .bind(&ends)
    .execute(conn)
    .await?;
    Ok(())
}

async fn deny(
    conn: &mut PgConnection,
    ctx: &OrgContext,
    action: &'static str,
    target: Option<String>,
) -> ApiResult<()> {
    audit::record(
        conn,
        audit::Event {
            organization_id: Some(ctx.organization_id),
            actor_user_id: Some(ctx.user.user_id),
            action,
            target_type: target.as_ref().map(|_| "access_grant"),
            target_id: target.as_deref(),
            outcome: audit::Outcome::Denied,
            details: json!({}),
        },
    )
    .await?;
    Ok(())
}

/// Bir üyenin yetkileri: yöneticiler herkesinkini, üye yalnızca kendisininkini görür.
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_id, member_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<serde_json::Value>> {
    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    if !ctx.role.is_manager() && member_id != ctx.user.user_id {
        return Err(ApiError::Forbidden("not_permitted"));
    }
    let rows: Vec<GrantRow> =
        sqlx::query_as(select_grants!("WHERE user_id = $1 ORDER BY created_at"))
            .bind(member_id)
            .fetch_all(&mut *tx)
            .await?;
    let grants = load_views(&mut tx, rows).await?;
    tx.commit().await?;
    Ok(Json(json!({ "grants": grants })))
}

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_id, member_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<CreateRequest>,
) -> ApiResult<(StatusCode, Json<GrantView>)> {
    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    if !ctx.role.is_manager() {
        deny(&mut tx, &ctx, "grant.create", None).await?;
        tx.commit().await?;
        return Err(ApiError::Forbidden("not_permitted"));
    }

    let member: Option<(String,)> = sqlx::query_as(
        "SELECT role FROM memberships WHERE user_id = $1 AND organization_id = $2 FOR SHARE",
    )
    .bind(member_id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?;
    let (member_role,) = member.ok_or(ApiError::NotFound)?;
    if Role::parse(&member_role).is_some_and(Role::is_manager) {
        return Err(ApiError::Conflict("member_is_manager"));
    }

    // Panel ve bölüm bu organizasyonda olmalı; RLS başka kiracının panelini zaten göstermez.
    let panel: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM panels WHERE id = $1")
        .bind(request.panel_id)
        .fetch_optional(&mut *tx)
        .await?;
    if panel.is_none() {
        return Err(ApiError::Unprocessable("unknown_panel"));
    }
    if let Some(partition_id) = request.partition_id {
        let partition: Option<(i32,)> =
            sqlx::query_as("SELECT 1 FROM partitions WHERE id = $1 AND panel_id = $2")
                .bind(partition_id)
                .bind(request.panel_id)
                .fetch_optional(&mut *tx)
                .await?;
        if partition.is_none() {
            return Err(ApiError::Unprocessable("unknown_partition"));
        }
    }

    let (panel_id, partition_id) = (request.panel_id, request.partition_id);
    let terms = Terms {
        can_view_events: request.can_view_events,
        can_arm: request.can_arm,
        can_disarm: request.can_disarm,
        can_bypass: request.can_bypass,
        always_open: request.always_open,
        valid_from: request.valid_from,
        expires_at: request.expires_at,
        windows: request.windows,
    };
    terms.validate(Utc::now())?;

    let inserted: Result<(Uuid,), sqlx::Error> = sqlx::query_as(
        "INSERT INTO access_grants (organization_id, user_id, panel_id, partition_id, can_view_events,
                                    can_arm, can_disarm, can_bypass, always_open, valid_from,
                                    expires_at, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id",
    )
    .bind(org_id)
    .bind(member_id)
    .bind(panel_id)
    .bind(partition_id)
    .bind(terms.can_view_events)
    .bind(terms.can_arm)
    .bind(terms.can_disarm)
    .bind(terms.can_bypass)
    .bind(terms.always_open)
    .bind(terms.valid_from)
    .bind(terms.expires_at)
    .bind(ctx.user.user_id)
    .fetch_one(&mut *tx)
    .await;
    let (grant_id,) = match inserted {
        Err(error) if is_unique_violation(&error) => {
            return Err(ApiError::Conflict("grant_exists"));
        }
        other => other?,
    };
    replace_windows(&mut tx, org_id, grant_id, &terms.windows).await?;

    let mut details = terms.summary();
    details["user_id"] = json!(member_id);
    details["panel_id"] = json!(panel_id);
    details["partition_id"] = json!(partition_id);
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: Some(org_id),
            actor_user_id: Some(ctx.user.user_id),
            action: "grant.created",
            target_type: Some("access_grant"),
            target_id: Some(&grant_id.to_string()),
            outcome: audit::Outcome::Success,
            details,
        },
    )
    .await?;
    let view = load_one(&mut tx, grant_id).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(view)))
}

pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_id, grant_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateRequest>,
) -> ApiResult<Json<GrantView>> {
    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    if !ctx.role.is_manager() {
        deny(&mut tx, &ctx, "grant.update", Some(grant_id.to_string())).await?;
        tx.commit().await?;
        return Err(ApiError::Forbidden("not_permitted"));
    }
    let terms = Terms::from(request);
    terms.validate(Utc::now())?;

    let updated = sqlx::query(
        "UPDATE access_grants
            SET can_view_events = $2, can_arm = $3, can_disarm = $4, can_bypass = $5,
                always_open = $6, valid_from = $7, expires_at = $8
          WHERE id = $1",
    )
    .bind(grant_id)
    .bind(terms.can_view_events)
    .bind(terms.can_arm)
    .bind(terms.can_disarm)
    .bind(terms.can_bypass)
    .bind(terms.always_open)
    .bind(terms.valid_from)
    .bind(terms.expires_at)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    replace_windows(&mut tx, org_id, grant_id, &terms.windows).await?;
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: Some(org_id),
            actor_user_id: Some(ctx.user.user_id),
            action: "grant.updated",
            target_type: Some("access_grant"),
            target_id: Some(&grant_id.to_string()),
            outcome: audit::Outcome::Success,
            details: terms.summary(),
        },
    )
    .await?;
    let view = load_one(&mut tx, grant_id).await?;
    tx.commit().await?;
    Ok(Json(view))
}

pub async fn remove(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_id, grant_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    if !ctx.role.is_manager() {
        deny(&mut tx, &ctx, "grant.delete", Some(grant_id.to_string())).await?;
        tx.commit().await?;
        return Err(ApiError::Forbidden("not_permitted"));
    }
    let deleted: Option<(Uuid, Uuid)> =
        sqlx::query_as("DELETE FROM access_grants WHERE id = $1 RETURNING user_id, panel_id")
            .bind(grant_id)
            .fetch_optional(&mut *tx)
            .await?;
    let (member_id, panel_id) = deleted.ok_or(ApiError::NotFound)?;
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: Some(org_id),
            actor_user_id: Some(ctx.user.user_id),
            action: "grant.deleted",
            target_type: Some("access_grant"),
            target_id: Some(&grant_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({ "user_id": member_id, "panel_id": panel_id }),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
