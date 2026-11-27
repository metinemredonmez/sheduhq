//! Panel listesi, panel ayrıntısı ve sanal (demo) panel.

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    AppState, audit,
    auth::AuthUser,
    authz::{self, OrgContext},
    error::{ApiError, ApiResult, violated_constraint},
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/organizations/{org_id}/panels", get(list_panels))
        .route(
            "/organizations/{org_id}/panels/{panel_id}",
            get(panel_detail),
        )
        .route(
            "/organizations/{org_id}/demo-panel",
            post(create_demo_panel),
        )
}

#[derive(Serialize, sqlx::FromRow)]
pub struct PanelSummary {
    id: Uuid,
    name: String,
    brand: String,
    model: Option<String>,
    connectivity: String,
    ready_to_arm: bool,
    last_seen_at: Option<DateTime<Utc>>,
    simulated: bool,
    #[sqlx(skip)]
    partitions: Vec<PartitionSummary>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct PartitionSummary {
    id: Uuid,
    number: i16,
    name: String,
    state: String,
    state_changed_at: DateTime<Utc>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct ZoneSummary {
    id: Uuid,
    number: i16,
    name: String,
    kind: String,
    bypassed: bool,
    partitions: Vec<Uuid>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct OutputSummary {
    id: Uuid,
    number: i16,
    name: String,
}

#[derive(Serialize)]
pub struct PanelDetail {
    #[serde(flatten)]
    panel: PanelSummary,
    zones: Vec<ZoneSummary>,
    /// Yalnızca yöneticilere gösterilir.
    #[serde(skip_serializing_if = "Option::is_none")]
    outputs: Option<Vec<OutputSummary>>,
}

/// Kullanıcının görebileceği paneller: yöneticiler hepsini, diğerleri yalnızca geçerli bir görme
/// yetkisi olanları.
async fn visible_panels(
    conn: &mut sqlx::PgConnection,
    ctx: &OrgContext,
) -> ApiResult<Vec<PanelSummary>> {
    let panels = if ctx.role.is_manager() {
        sqlx::query_as::<_, PanelSummary>(
            "SELECT id, name, brand, model, connectivity, ready_to_arm, last_seen_at, simulated
               FROM panels ORDER BY name",
        )
        .fetch_all(&mut *conn)
        .await?
    } else {
        sqlx::query_as::<_, PanelSummary>(
            "SELECT id, name, brand, model, connectivity, ready_to_arm, last_seen_at, simulated
               FROM panels
              WHERE id IN (SELECT panel_id FROM access_grants
                            WHERE user_id = $1 AND can_view_events
                              AND (valid_from IS NULL OR valid_from <= now())
                              AND (expires_at IS NULL OR expires_at > now()))
              ORDER BY name",
        )
        .bind(ctx.user.user_id)
        .fetch_all(&mut *conn)
        .await?
    };
    Ok(panels)
}

async fn partitions_of(
    conn: &mut sqlx::PgConnection,
    ctx: &OrgContext,
    panel_id: Uuid,
) -> ApiResult<Vec<PartitionSummary>> {
    let visible = authz::visible_partitions(conn, ctx, panel_id).await?;
    let all: Vec<PartitionSummary> = sqlx::query_as(
        "SELECT id, number, name, state, state_changed_at
           FROM partitions WHERE panel_id = $1 ORDER BY number",
    )
    .bind(panel_id)
    .fetch_all(conn)
    .await?;
    Ok(match visible {
        None => all,
        Some(ids) => all.into_iter().filter(|p| ids.contains(&p.id)).collect(),
    })
}

pub async fn list_panels(
    State(state): State<AppState>,
    user: AuthUser,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Json<Vec<PanelSummary>>> {
    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    let mut panels = visible_panels(&mut tx, &ctx).await?;
    for panel in &mut panels {
        panel.partitions = partitions_of(&mut tx, &ctx, panel.id).await?;
    }
    tx.commit().await?;
    Ok(Json(panels))
}

pub async fn panel_detail(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_id, panel_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<PanelDetail>> {
    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    let mut panel = visible_panels(&mut tx, &ctx)
        .await?
        .into_iter()
        .find(|p| p.id == panel_id)
        .ok_or(ApiError::NotFound)?;
    panel.partitions = partitions_of(&mut tx, &ctx, panel_id).await?;
    let visible: Vec<Uuid> = panel.partitions.iter().map(|p| p.id).collect();

    let zones: Vec<ZoneSummary> = sqlx::query_as(
        "SELECT z.id, z.number, z.name, z.kind, z.bypassed,
                coalesce(array_agg(zp.partition_id) FILTER (WHERE zp.partition_id IS NOT NULL), '{}') AS partitions
           FROM zones z LEFT JOIN zone_partitions zp ON zp.zone_id = z.id
          WHERE z.panel_id = $1
          GROUP BY z.id
          ORDER BY z.number",
    )
    .bind(panel_id)
    .fetch_all(&mut *tx)
    .await?;
    let zones = zones
        .into_iter()
        .filter(|z| ctx.role.is_manager() || z.partitions.iter().any(|p| visible.contains(p)))
        .collect();

    let outputs = if ctx.role.is_manager() {
        Some(
            sqlx::query_as(
                "SELECT id, number, name FROM outputs WHERE panel_id = $1 ORDER BY number",
            )
            .bind(panel_id)
            .fetch_all(&mut *tx)
            .await?,
        )
    } else {
        None
    };
    tx.commit().await?;
    Ok(Json(PanelDetail {
        panel,
        zones,
        outputs,
    }))
}

/// Gerçek bir cihaza bağlı olmayan sanal panel oluşturur: iki bölüm ve beş zon. Komutları
/// sunucu içinde simüle edilir. Yalnızca yöneticiler; organizasyon başına bir tane.
pub async fn create_demo_panel(
    State(state): State<AppState>,
    user: AuthUser,
    Path(org_id): Path<Uuid>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    if !ctx.role.is_manager() {
        return Err(ApiError::Forbidden("not_permitted"));
    }

    let panel_id = Uuid::new_v4();
    let inserted = sqlx::query(
        "INSERT INTO panels (id, organization_id, name, brand, model, device_serial, connectivity,
                             ready_to_arm, last_seen_at, simulated)
         VALUES ($1, $2, 'Demo panel', 'shedu-demo', 'sanal', $3, 'online', true, now(), true)",
    )
    .bind(panel_id)
    .bind(org_id)
    .bind(format!("demo-{panel_id}"))
    .execute(&mut *tx)
    .await;
    if let Err(error) = inserted {
        if violated_constraint(&error).as_deref() == Some("panels_one_simulated_per_org") {
            return Err(ApiError::Conflict("demo_panel_exists"));
        }
        return Err(error.into());
    }

    let home = Uuid::new_v4();
    let garage = Uuid::new_v4();
    for (id, number, name) in [(home, 1_i16, "Ev"), (garage, 2_i16, "Garaj")] {
        sqlx::query(
            "INSERT INTO partitions (id, organization_id, panel_id, number, name) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(org_id)
        .bind(panel_id)
        .bind(number)
        .bind(name)
        .execute(&mut *tx)
        .await?;
    }

    let zones: [(i16, &str, &str, Uuid); 5] = [
        (1, "Ön kapı", "intrusion", home),
        (2, "Salon hareket", "intrusion", home),
        (3, "Mutfak duman", "fire", home),
        (4, "Banyo su baskını", "flood", home),
        (5, "Garaj kapısı", "intrusion", garage),
    ];
    for (number, name, kind, partition) in zones {
        let zone_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO zones (id, organization_id, panel_id, number, name, kind) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(zone_id)
        .bind(org_id)
        .bind(panel_id)
        .bind(number)
        .bind(name)
        .bind(kind)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO zone_partitions (organization_id, panel_id, zone_id, partition_id) VALUES ($1, $2, $3, $4)",
        )
        .bind(org_id)
        .bind(panel_id)
        .bind(zone_id)
        .bind(partition)
        .execute(&mut *tx)
        .await?;
    }

    audit::record(
        &mut tx,
        audit::Event {
            organization_id: Some(org_id),
            actor_user_id: Some(ctx.user.user_id),
            action: "panel.demo_created",
            target_type: Some("panel"),
            target_id: Some(&panel_id.to_string()),
            outcome: audit::Outcome::Success,
            details: json!({}),
        },
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": panel_id }))))
}
