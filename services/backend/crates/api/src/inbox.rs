//! Bildirim merkezi: kişinin bütün organizasyonlarındaki olaylar tek akışta, okundu bilgisiyle.
//!
//! Bildirimler ayrıca saklanmaz; her istekte olaylardan, kişinin o anki yetkisiyle türetilir
//! (olay geçmişi ve push ile aynı kural: yöneticiler ve operatör bütün paneli, üye yalnızca görme
//! yetkisi olan bölümleri görür). Her organizasyon kendi kiracı bağlamında ve `authz::begin` ile
//! okunur: üyelik ve personel için MFA koşulu aynen uygulanır; ikinci adımı tamamlanmamış
//! oturumda o organizasyonun bildirimleri gösterilmez, yalnızca kilitli olduğu söylenir.
//! Organizasyona katılmadan önceki olaylar okunmuş sayılır. Bildirim tercihleri yalnızca push'u
//! etkiler; merkezde bütün olaylar görünür.

use axum::{
    Json, Router,
    extract::{Query, State},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{
    AppState,
    auth::AuthUser,
    authz::{self, OrgContext},
    error::{ApiError, ApiResult},
    push,
};

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 100;
/// Okunmamış sayısı bu değerde kesilir ("999+").
const COUNT_CAP: i64 = 999;
const MAX_IDS: usize = 100;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/notifications", get(list))
        .route("/notifications/unread-count", get(unread_count))
        .route("/notifications/read", post(mark_read))
}

/// Görünürlük: $1 kişi, $2 bütün paneli görür mü.
macro_rules! visible {
    () => {
        "($2 OR EXISTS (
             SELECT 1 FROM access_grants g
              WHERE g.user_id = $1 AND g.panel_id = e.panel_id AND g.can_view_events
                AND (g.valid_from IS NULL OR g.valid_from <= now())
                AND (g.expires_at IS NULL OR g.expires_at > now())
                AND (g.partition_id IS NULL OR e.partition_number IS NULL
                     OR g.partition_id = (SELECT p2.id FROM partitions p2
                                           WHERE p2.panel_id = e.panel_id
                                             AND p2.number = e.partition_number))))"
    };
}

/// Okunmamış: $1 kişi, $3 organizasyon. Katılmadan önceki olaylar okunmuş sayılır.
macro_rules! unread {
    () => {
        "(e.id > coalesce((SELECT r.last_read_event_id FROM notification_reads r
                             WHERE r.user_id = $1 AND r.organization_id = $3), 0)
          AND e.received_at >= (SELECT m.created_at FROM memberships m
                                 WHERE m.user_id = $1 AND m.organization_id = $3)
          AND NOT EXISTS (SELECT 1 FROM notification_item_reads i
                           WHERE i.user_id = $1 AND i.event_id = e.id))"
    };
}

#[derive(Serialize)]
pub struct Locked {
    organization_id: Uuid,
    reason: &'static str,
}

#[derive(Serialize)]
pub struct Notification {
    event_id: i64,
    organization_id: Uuid,
    organization_name: String,
    panel_id: Uuid,
    kind: String,
    priority: String,
    title: String,
    body: String,
    occurred_at: DateTime<Utc>,
    read: bool,
}

#[derive(sqlx::FromRow)]
struct Row {
    id: i64,
    panel_id: Uuid,
    kind: String,
    alarm_kind: Option<String>,
    arm_mode: Option<String>,
    priority: String,
    zone_number: Option<i16>,
    occurred_at: DateTime<Utc>,
    panel_name: String,
    partition_name: Option<String>,
    zone_name: Option<String>,
    unread: bool,
}

/// Kişinin üyesi olduğu organizasyonlar.
async fn organizations(state: &AppState, user: AuthUser) -> ApiResult<Vec<Uuid>> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT organization_id FROM memberships WHERE user_id = $1 ORDER BY organization_id",
    )
    .bind(user.user_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Organizasyonu kişinin bağlamıyla açar. MFA kilidi veya araya giren üyelik silinmesi `None`.
async fn open(
    state: &AppState,
    user: AuthUser,
    organization_id: Uuid,
    locked: &mut Vec<Locked>,
) -> ApiResult<Option<(sqlx::Transaction<'static, sqlx::Postgres>, OrgContext)>> {
    match authz::begin(state, user, organization_id).await {
        Ok(opened) => Ok(Some(opened)),
        Err(ApiError::Forbidden("mfa_required")) => {
            locked.push(Locked {
                organization_id,
                reason: "mfa_required",
            });
            Ok(None)
        }
        Err(ApiError::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    before: Option<i64>,
    limit: Option<i64>,
    #[serde(default)]
    unread_only: bool,
}

pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(ApiError::BadRequest("invalid_limit"));
    }
    let mut locked = Vec::new();
    let mut items: Vec<Notification> = Vec::new();
    for organization_id in organizations(&state, user).await? {
        let Some((mut tx, ctx)) = open(&state, user, organization_id, &mut locked).await? else {
            continue;
        };
        let (organization_name,): (String,) =
            sqlx::query_as("SELECT name FROM organizations WHERE id = app_current_org()")
                .fetch_one(&mut *tx)
                .await?;
        let rows: Vec<Row> = sqlx::query_as(concat!(
            "SELECT e.id, e.panel_id, e.kind, e.alarm_kind, e.arm_mode, e.priority, e.zone_number,
                    e.occurred_at, p.name AS panel_name, pt.name AS partition_name,
                    z.name AS zone_name, ",
            unread!(),
            " AS unread
               FROM panel_events e
               JOIN panels p ON p.id = e.panel_id
               LEFT JOIN partitions pt ON pt.panel_id = e.panel_id AND pt.number = e.partition_number
               LEFT JOIN zones z ON z.panel_id = e.panel_id AND z.number = e.zone_number
              WHERE ",
            visible!(),
            " AND ($4::bigint IS NULL OR e.id < $4) AND (NOT $5 OR ",
            unread!(),
            ") ORDER BY e.id DESC LIMIT $6"
        ))
        .bind(ctx.user.user_id)
        .bind(ctx.role.sees_all_panels())
        .bind(organization_id)
        .bind(query.before)
        .bind(query.unread_only)
        .bind(limit + 1)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        items.extend(rows.into_iter().map(|row| {
            let (title, body) = push::text(
                &row.kind,
                row.alarm_kind.as_deref(),
                row.arm_mode.as_deref(),
                &row.panel_name,
                row.partition_name.as_deref(),
                row.zone_name.as_deref(),
                row.zone_number,
            );
            Notification {
                event_id: row.id,
                organization_id,
                organization_name: organization_name.clone(),
                panel_id: row.panel_id,
                kind: row.kind,
                priority: row.priority,
                title,
                body,
                occurred_at: row.occurred_at,
                read: !row.unread,
            }
        }));
    }
    // Olay kimlikleri bütün organizasyonlarda tek sıradan gelir; birleşik akış kimliğe göre sıralı.
    items.sort_by_key(|item| std::cmp::Reverse(item.event_id));
    let limit = usize::try_from(limit).unwrap_or(0);
    let has_more = items.len() > limit;
    items.truncate(limit);
    let next_before = if has_more {
        items.last().map(|i| i.event_id)
    } else {
        None
    };
    Ok(Json(json!({
        "notifications": items,
        "next_before": next_before,
        "locked": locked,
    })))
}

async fn count_unread(conn: &mut PgConnection, ctx: &OrgContext) -> ApiResult<i64> {
    let (count,): (i64,) = sqlx::query_as(concat!(
        "SELECT count(*) FROM (SELECT 1 FROM panel_events e WHERE ",
        visible!(),
        " AND ",
        unread!(),
        " LIMIT $4) x"
    ))
    .bind(ctx.user.user_id)
    .bind(ctx.role.sees_all_panels())
    .bind(ctx.organization_id)
    .bind(COUNT_CAP)
    .fetch_one(conn)
    .await?;
    Ok(count)
}

pub async fn unread_count(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<serde_json::Value>> {
    let mut locked = Vec::new();
    let mut by_organization = serde_json::Map::new();
    let mut total = 0;
    for organization_id in organizations(&state, user).await? {
        let Some((mut tx, ctx)) = open(&state, user, organization_id, &mut locked).await? else {
            continue;
        };
        let count = count_unread(&mut tx, &ctx).await?;
        tx.commit().await?;
        total += count;
        by_organization.insert(organization_id.to_string(), json!(count));
    }
    Ok(Json(json!({
        "total": total.min(COUNT_CAP),
        "by_organization": by_organization,
        "locked": locked,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadRequest {
    /// Hepsini okundu yap (isteğe bağlı olarak tek organizasyonda).
    #[serde(default)]
    all: bool,
    organization_id: Option<Uuid>,
    /// Tek tek okundu yapılacak olaylar (en fazla 100). Görülemeyen olaylar sessizce yok sayılır.
    event_ids: Option<Vec<i64>>,
}

pub async fn mark_read(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<ReadRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let ids = request.event_ids.unwrap_or_default();
    if request.all == !ids.is_empty() || ids.len() > MAX_IDS {
        return Err(ApiError::BadRequest("all_or_event_ids"));
    }
    if !request.all && request.organization_id.is_some() {
        return Err(ApiError::BadRequest("organization_only_with_all"));
    }
    let targets = match request.organization_id {
        Some(organization_id) => {
            // Üye olunmayan organizasyon: varlığı belli olmaz.
            if !organizations(&state, user)
                .await?
                .contains(&organization_id)
            {
                return Err(ApiError::NotFound);
            }
            vec![organization_id]
        }
        None => organizations(&state, user).await?,
    };

    let mut locked = Vec::new();
    let mut marked: u64 = 0;
    for organization_id in targets {
        let Some((mut tx, ctx)) = open(&state, user, organization_id, &mut locked).await? else {
            continue;
        };
        if request.all {
            let (max,): (Option<i64>,) = sqlx::query_as(concat!(
                "SELECT max(e.id) FROM panel_events e WHERE ",
                visible!()
            ))
            .bind(ctx.user.user_id)
            .bind(ctx.role.sees_all_panels())
            .fetch_one(&mut *tx)
            .await?;
            if let Some(max) = max {
                sqlx::query(
                    "INSERT INTO notification_reads (user_id, organization_id, last_read_event_id)
                     VALUES ($1, $2, $3)
                     ON CONFLICT (user_id, organization_id) DO UPDATE
                        SET last_read_event_id = greatest(notification_reads.last_read_event_id,
                                                          EXCLUDED.last_read_event_id),
                            updated_at = now()",
                )
                .bind(ctx.user.user_id)
                .bind(organization_id)
                .bind(max)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "DELETE FROM notification_item_reads
                      WHERE user_id = $1 AND organization_id = $2 AND event_id <= $3",
                )
                .bind(ctx.user.user_id)
                .bind(organization_id)
                .bind(max)
                .execute(&mut *tx)
                .await?;
            }
        } else {
            let visible_ids: Vec<(i64,)> = sqlx::query_as(concat!(
                "SELECT e.id FROM panel_events e WHERE e.id = ANY($3) AND ",
                visible!()
            ))
            .bind(ctx.user.user_id)
            .bind(ctx.role.sees_all_panels())
            .bind(&ids)
            .fetch_all(&mut *tx)
            .await?;
            for (event_id,) in visible_ids {
                marked += sqlx::query(
                    "INSERT INTO notification_item_reads (user_id, organization_id, event_id)
                     VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                )
                .bind(ctx.user.user_id)
                .bind(organization_id)
                .bind(event_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            }
        }
        tx.commit().await?;
    }
    Ok(Json(json!({ "marked": marked, "locked": locked })))
}
