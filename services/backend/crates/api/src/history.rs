//! Olay geçmişi, panik butonu ve sanal panelde alarm.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    AppState, audit,
    auth::{AuthUser, rate_limit},
    authz,
    error::{ApiError, ApiResult},
};

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/organizations/{org_id}/panels/{panel_id}/events",
            get(list_events),
        )
        .route(
            "/organizations/{org_id}/panels/{panel_id}/panic",
            post(panic),
        )
        .route(
            "/organizations/{org_id}/panels/{panel_id}/simulate-alarm",
            post(simulate_alarm),
        )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventQuery {
    /// Bu kimlikten eski olaylar (sayfalama).
    before: Option<i64>,
    limit: Option<i64>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct EventView {
    id: i64,
    kind: String,
    alarm_kind: Option<String>,
    arm_mode: Option<String>,
    priority: String,
    partition_number: Option<i16>,
    zone_number: Option<i16>,
    source: String,
    occurred_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct EventPage {
    events: Vec<EventView>,
    /// Sonraki sayfa için `before` değeri; yoksa son sayfa.
    next_before: Option<i64>,
}

/// Panelin olay geçmişi, yeniden eskiye. Üye yalnızca görmeye yetkili olduğu bölümlerin olaylarını
/// ve panel düzeyindeki olayları (bağlantı, güç, panik) görür.
pub async fn list_events(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_id, panel_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<EventQuery>,
) -> ApiResult<Json<EventPage>> {
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(ApiError::BadRequest("invalid_limit"));
    }
    if let (Some(from), Some(to)) = (query.from, query.to)
        && from > to
    {
        return Err(ApiError::BadRequest("invalid_range"));
    }

    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    if !authz::permissions(&mut tx, &ctx, panel_id, None)
        .await?
        .view
    {
        return Err(ApiError::NotFound);
    }
    let partition_numbers = authz::visible_partition_numbers(&mut tx, &ctx, panel_id).await?;

    let mut events: Vec<EventView> = sqlx::query_as(
        "SELECT id, kind, alarm_kind, arm_mode, priority, partition_number, zone_number, source, occurred_at
           FROM panel_events
          WHERE panel_id = $1 AND organization_id = $7
            AND ($2::bigint IS NULL OR id < $2)
            AND ($3::timestamptz IS NULL OR occurred_at >= $3)
            AND ($4::timestamptz IS NULL OR occurred_at <= $4)
            AND ($5::smallint[] IS NULL OR partition_number IS NULL OR partition_number = ANY($5))
          ORDER BY id DESC
          LIMIT $6",
    )
    .bind(panel_id)
    .bind(query.before)
    .bind(query.from)
    .bind(query.to)
    .bind(&partition_numbers)
    .bind(limit + 1)
    .bind(org_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;

    let has_more = events.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    events.truncate(usize::try_from(limit).unwrap_or(0));
    let next_before = if has_more {
        events.last().map(|e| e.id)
    } else {
        None
    };
    Ok(Json(EventPage {
        events,
        next_before,
    }))
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum PanicKind {
    Police,
    Medical,
    Fire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PanicRequest {
    kind: PanicKind,
}

/// Uygulamadaki panik butonu: kritik bir olay yazar; yetkili herkese kritik bildirim gider.
/// Paneli görmeye yetkili her üye kullanabilir (güvenlik gerekçesiyle pencereye bağlı değildir).
pub async fn panic(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_id, panel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<PanicRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    {
        let mut conn = state.db.acquire().await?;
        rate_limit::hit(
            &mut conn,
            &state.hmac_secret,
            rate_limit::PANIC_PER_USER,
            &user.user_id.to_string(),
        )
        .await?;
    }
    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    if !authz::permissions(&mut tx, &ctx, panel_id, None)
        .await?
        .view
    {
        return Err(ApiError::NotFound);
    }
    let alarm_kind = match request.kind {
        PanicKind::Police => "panic",
        PanicKind::Medical => "medical",
        PanicKind::Fire => "fire",
    };
    let (event_id,): (i64,) = sqlx::query_as(
        "INSERT INTO panel_events (organization_id, panel_id, kind, alarm_kind, priority, occurred_at, source)
         VALUES ($1, $2, 'alarm', $3, 'critical', now(), 'app') RETURNING id",
    )
    .bind(org_id)
    .bind(panel_id)
    .bind(alarm_kind)
    .fetch_one(&mut *tx)
    .await?;
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: Some(org_id),
            actor_user_id: Some(ctx.user.user_id),
            action: "panel.panic",
            target_type: Some("panel_event"),
            target_id: Some(&event_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({ "panel_id": panel_id, "kind": alarm_kind }),
        },
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "event_id": event_id }))))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulateAlarmRequest {
    zone_number: i16,
}

/// Sanal panelde bir zonu tetikler. Hırsızlık zonu yalnızca kurulu bölümde alarm verir; yangın, gaz,
/// su, panik, tıbbi ve sabotaj zonları her zaman (24 saat) alarm verir. Yalnızca yöneticiler.
pub async fn simulate_alarm(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_id, panel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<SimulateAlarmRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    if !ctx.role.is_manager() {
        return Err(ApiError::Forbidden("not_permitted"));
    }
    let simulated: Option<(bool,)> =
        sqlx::query_as("SELECT simulated FROM panels WHERE id = $1 AND organization_id = $2")
            .bind(panel_id)
            .bind(org_id)
            .fetch_optional(&mut *tx)
            .await?;
    match simulated {
        None => return Err(ApiError::NotFound),
        Some((false,)) => return Err(ApiError::Conflict("not_simulated")),
        Some((true,)) => {}
    }

    let zone: Option<(String,)> =
        sqlx::query_as("SELECT kind FROM zones WHERE panel_id = $1 AND number = $2")
            .bind(panel_id)
            .bind(request.zone_number)
            .fetch_optional(&mut *tx)
            .await?;
    let (zone_kind,) = zone.ok_or(ApiError::BadRequest("unknown_zone"))?;
    let always_active = zone_kind != "intrusion" && zone_kind != "other";
    let alarm_kind = match zone_kind.as_str() {
        "fire" | "gas" | "flood" | "panic" | "medical" | "tamper" => zone_kind.clone(),
        _ => "intrusion".to_owned(),
    };

    // Zonun ait olduğu bölümler; hırsızlıkta yalnızca kurulu olanlar alarma geçer.
    let partitions: Vec<(Uuid, i16)> = sqlx::query_as(
        "UPDATE partitions pt SET state = 'alarm', state_changed_at = now()
           FROM zone_partitions zp JOIN zones z ON z.id = zp.zone_id
          WHERE zp.partition_id = pt.id AND z.panel_id = $1 AND z.number = $2
            AND ($3 OR pt.state IN ('armed_away', 'armed_stay', 'armed_night'))
            AND NOT z.bypassed
          RETURNING pt.id, pt.number",
    )
    .bind(panel_id)
    .bind(request.zone_number)
    .bind(always_active)
    .fetch_all(&mut *tx)
    .await?;
    if partitions.is_empty() {
        return Err(ApiError::Conflict("partition_not_armed"));
    }

    // Zon birden fazla bölümdeyse alarma geçen her bölüm için ayrı kritik olay yazılır: yalnızca o
    // bölümü görebilen alıcı da bildirimi alır (AZ-04, BUS-02).
    let mut numbers: Vec<i16> = partitions.iter().map(|(_, number)| *number).collect();
    numbers.sort_unstable();
    let mut event_ids: Vec<i64> = Vec::with_capacity(numbers.len());
    for partition_number in numbers {
        let (event_id,): (i64,) = sqlx::query_as(
            "INSERT INTO panel_events (organization_id, panel_id, partition_number, zone_number, kind, alarm_kind,
                                       priority, occurred_at, source)
             VALUES ($1, $2, $3, $4, 'alarm', $5, 'critical', now(), 'simulator') RETURNING id",
        )
        .bind(org_id)
        .bind(panel_id)
        .bind(partition_number)
        .bind(request.zone_number)
        .bind(&alarm_kind)
        .fetch_one(&mut *tx)
        .await?;
        event_ids.push(event_id);
    }
    let event_id = event_ids[0];
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: Some(org_id),
            actor_user_id: Some(ctx.user.user_id),
            action: "panel.alarm_simulated",
            target_type: Some("panel_event"),
            target_id: Some(&event_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({
                "panel_id": panel_id,
                "zone_number": request.zone_number,
                "event_ids": event_ids,
            }),
        },
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "event_id": event_id, "event_ids": event_ids })),
    ))
}
