//! Komut API'si: kur / evde / gece / kapat ve zon devre dışı bırakma (bypass).
//!
//! Akış (docs/mimari.md, "Komut akışı"):
//! 1. Üyelik ve panel/bölüm yetkisi, erişim penceresiyle birlikte kontrol edilir (AZ-01).
//! 2. Aynı tekrar anahtarı aynı istekle gelirse ilk komut döner; farklı istekle gelirse reddedilir.
//! 3. Bölüm satırı kilitlenir ve domain kuralları uygulanır (BUS-01). Kural reddi de kaydedilir.
//! 4. Bir bölümde aynı anda yalnızca bir komut yolda olabilir; veritabanı da bunu zorlar (BUS-02).
//! 5. Kabul edilen komut denetim kaydına yazılır ve panele iletilmek üzere bekler. Sanal panelde
//!    simülatör tamamlar; gerçek panelde gateway tamamlayacak.

use std::collections::BTreeSet;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use shedu_domain::panel::{self, ArmMode, Command, CommandRejection, Connectivity, PartitionState};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{
    AppState, audit,
    auth::{AuthUser, rate_limit},
    authz::{self, OrgContext},
    error::{ApiError, ApiResult, violated_constraint},
    simulator,
};

const MAX_ZONES_PER_COMMAND: usize = 64;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/organizations/{org_id}/panels/{panel_id}/commands",
            post(create_command),
        )
        .route(
            "/organizations/{org_id}/commands/{command_id}",
            get(get_command),
        )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandKind {
    ArmAway,
    ArmStay,
    ArmNight,
    Disarm,
    BypassZones,
    UnbypassZones,
}

impl CommandKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ArmAway => "arm_away",
            Self::ArmStay => "arm_stay",
            Self::ArmNight => "arm_night",
            Self::Disarm => "disarm",
            Self::BypassZones => "bypass_zones",
            Self::UnbypassZones => "unbypass_zones",
        }
    }

    fn arm_command(self) -> Option<Command> {
        match self {
            Self::ArmAway => Some(Command::Arm(ArmMode::Away)),
            Self::ArmStay => Some(Command::Arm(ArmMode::Stay)),
            Self::ArmNight => Some(Command::Arm(ArmMode::Night)),
            Self::Disarm => Some(Command::Disarm),
            Self::BypassZones | Self::UnbypassZones => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRequest {
    partition_id: Uuid,
    kind: CommandKind,
    #[serde(default)]
    zones: Option<Vec<u16>>,
    /// İstemcinin her yeni işlem için ürettiği rastgele anahtar (16–128 karakter).
    idempotency_key: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct CommandView {
    id: Uuid,
    panel_id: Uuid,
    partition_id: Uuid,
    kind: String,
    zones: Option<Vec<i16>>,
    status: String,
    rejection_reason: Option<String>,
    requested_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    #[serde(skip)]
    user_id: Uuid,
}

pub fn parse_state(value: &str) -> Option<PartitionState> {
    Some(match value {
        "disarmed" => PartitionState::Disarmed,
        "armed_away" => PartitionState::Armed(ArmMode::Away),
        "armed_stay" => PartitionState::Armed(ArmMode::Stay),
        "armed_night" => PartitionState::Armed(ArmMode::Night),
        "alarm" => PartitionState::Alarm,
        _ => return None,
    })
}

fn parse_connectivity(value: &str) -> Connectivity {
    // Bilinmeyen değer çevrimdışı sayılır (fail-closed).
    if value == "online" {
        Connectivity::Online
    } else {
        Connectivity::Offline
    }
}

pub fn rejection_code(rejection: &CommandRejection) -> &'static str {
    match rejection {
        CommandRejection::PanelOffline => "panel_offline",
        CommandRejection::AlreadyInState => "already_in_state",
        CommandRejection::DisarmRequiredFirst => "disarm_required_first",
        CommandRejection::NotReadyToArm => "not_ready_to_arm",
        CommandRejection::NoZonesRequested => "no_zones_requested",
        CommandRejection::ZonesNotInPartition(_) => "zones_not_in_partition",
    }
}

fn valid_idempotency_key(key: &str) -> bool {
    (16..=128).contains(&key.len())
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn zones_as_i16(zones: &BTreeSet<u16>) -> Vec<i16> {
    zones
        .iter()
        .filter_map(|z| i16::try_from(*z).ok())
        .collect()
}

async fn record_audit(
    conn: &mut PgConnection,
    ctx: &OrgContext,
    kind: CommandKind,
    command_id: Option<Uuid>,
    outcome: audit::Outcome,
    details: serde_json::Value,
) -> Result<(), sqlx::Error> {
    let action = match kind {
        CommandKind::ArmAway => "command.arm_away",
        CommandKind::ArmStay => "command.arm_stay",
        CommandKind::ArmNight => "command.arm_night",
        CommandKind::Disarm => "command.disarm",
        CommandKind::BypassZones => "command.bypass_zones",
        CommandKind::UnbypassZones => "command.unbypass_zones",
    };
    let target = command_id.map(|id| id.to_string());
    audit::record(
        conn,
        audit::Event {
            organization_id: Some(ctx.organization_id),
            actor_user_id: Some(ctx.user.user_id),
            action,
            target_type: Some("command"),
            target_id: target.as_deref(),
            outcome,
            details,
        },
    )
    .await
}

pub async fn create_command(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_id, panel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<CommandRequest>,
) -> ApiResult<(StatusCode, Json<CommandView>)> {
    if !valid_idempotency_key(&request.idempotency_key) {
        return Err(ApiError::BadRequest("invalid_idempotency_key"));
    }
    let is_bypass = matches!(
        request.kind,
        CommandKind::BypassZones | CommandKind::UnbypassZones
    );
    let zones: Option<BTreeSet<u16>> = request.zones.map(|z| z.into_iter().collect());
    match (&zones, is_bypass) {
        (Some(z), true) if z.is_empty() => return Err(ApiError::BadRequest("no_zones_requested")),
        (Some(z), true) if z.len() > MAX_ZONES_PER_COMMAND => {
            return Err(ApiError::BadRequest("too_many_zones"));
        }
        (None, true) => return Err(ApiError::BadRequest("no_zones_requested")),
        (Some(_), false) => return Err(ApiError::BadRequest("zones_not_allowed")),
        _ => {}
    }
    let zones_db = zones.as_ref().map(zones_as_i16);

    {
        let mut conn = state.db.acquire().await?;
        rate_limit::hit(
            &mut conn,
            &state.hmac_secret,
            rate_limit::COMMAND_PER_USER,
            &user.user_id.to_string(),
        )
        .await?;
    }

    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;

    // Aynı anahtar daha önce kullanıldıysa: aynı istekse ilk sonucu döndür, değilse reddet.
    let previous: Option<CommandView> = sqlx::query_as(
        "SELECT id, panel_id, partition_id, kind, zones, status, rejection_reason,
                requested_at, completed_at, user_id
           FROM commands WHERE user_id = $1 AND idempotency_key = $2",
    )
    .bind(user.user_id)
    .bind(&request.idempotency_key)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(previous) = previous {
        let same = previous.panel_id == panel_id
            && previous.partition_id == request.partition_id
            && previous.kind == request.kind.as_str()
            && previous.zones == zones_db;
        tx.commit().await?;
        return if same {
            Ok((StatusCode::OK, Json(previous)))
        } else {
            Err(ApiError::Unprocessable("idempotency_key_reused"))
        };
    }

    // Panel ve bölüm; bölüm satırı işlem sonuna kadar kilitlenir.
    let target: Option<(String, bool, bool, String)> = sqlx::query_as(
        "SELECT p.connectivity, p.ready_to_arm, p.simulated, pt.state
           FROM panels p JOIN partitions pt ON pt.panel_id = p.id
          WHERE p.id = $1 AND pt.id = $2 AND p.organization_id = $3
            FOR UPDATE OF pt",
    )
    .bind(panel_id)
    .bind(request.partition_id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?;
    let (connectivity, ready_to_arm, simulated, state_text) = target.ok_or(ApiError::NotFound)?;

    let permissions =
        authz::permissions(&mut tx, &ctx, panel_id, Some(request.partition_id)).await?;
    let mut allowed = match request.kind {
        CommandKind::ArmAway | CommandKind::ArmStay | CommandKind::ArmNight => permissions.arm,
        CommandKind::Disarm => permissions.disarm,
        CommandKind::BypassZones | CommandKind::UnbypassZones => permissions.bypass,
    };
    // Bypass zonun kendisini değiştirir: zon başka bölümlerde de kullanılıyorsa o bölümleri de
    // etkiler. Bu yüzden zonun ait olduğu her bölümde bypass yetkisi gerekir (AZ-04).
    if allowed && is_bypass {
        let shared: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT DISTINCT zp.partition_id
               FROM zones z JOIN zone_partitions zp ON zp.zone_id = z.id
              WHERE z.panel_id = $1 AND z.number = ANY($2) AND zp.partition_id <> $3",
        )
        .bind(panel_id)
        .bind(zones_db.as_deref().unwrap_or_default())
        .bind(request.partition_id)
        .fetch_all(&mut *tx)
        .await?;
        for (partition_id,) in shared {
            if !authz::permissions(&mut tx, &ctx, panel_id, Some(partition_id))
                .await?
                .bypass
            {
                allowed = false;
                break;
            }
        }
    }
    if !allowed {
        // Hiç görme yetkisi yoksa panelin varlığı da belli edilmez.
        if !permissions.view {
            return Err(ApiError::NotFound);
        }
        record_audit(
            &mut tx,
            &ctx,
            request.kind,
            None,
            audit::Outcome::Denied,
            json!({ "panel_id": panel_id }),
        )
        .await?;
        tx.commit().await?;
        return Err(ApiError::Forbidden("not_permitted"));
    }

    let connectivity = parse_connectivity(&connectivity);
    let rejection = if let Some(command) = request.kind.arm_command() {
        let current = parse_state(&state_text).ok_or(ApiError::Internal)?;
        panel::expected_state(connectivity, ready_to_arm, current, command).err()
    } else {
        let partition_zones: Vec<(i16,)> = sqlx::query_as(
            "SELECT z.number FROM zones z JOIN zone_partitions zp ON zp.zone_id = z.id WHERE zp.partition_id = $1",
        )
        .bind(request.partition_id)
        .fetch_all(&mut *tx)
        .await?;
        let partition_zones: BTreeSet<u16> = partition_zones
            .into_iter()
            .filter_map(|(n,)| u16::try_from(n).ok())
            .collect();
        panel::validate_zone_selection(
            connectivity,
            &partition_zones,
            zones.as_ref().unwrap_or(&BTreeSet::new()),
        )
        .err()
    };

    let command_id = Uuid::new_v4();
    let (status, reason) = match &rejection {
        Some(rejection) => ("rejected", Some(rejection_code(rejection))),
        None => ("accepted", None),
    };
    let inserted = sqlx::query(
        "INSERT INTO commands (id, organization_id, panel_id, partition_id, user_id, kind, zones,
                               idempotency_key, status, rejection_reason, completed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CASE WHEN $9 = 'rejected' THEN now() END)",
    )
    .bind(command_id)
    .bind(org_id)
    .bind(panel_id)
    .bind(request.partition_id)
    .bind(user.user_id)
    .bind(request.kind.as_str())
    .bind(&zones_db)
    .bind(&request.idempotency_key)
    .bind(status)
    .bind(reason)
    .execute(&mut *tx)
    .await;
    if let Err(error) = inserted {
        return Err(match violated_constraint(&error).as_deref() {
            Some("commands_one_in_flight_per_partition") => {
                ApiError::Conflict("command_in_progress")
            }
            Some("commands_user_id_idempotency_key_key") => {
                ApiError::Unprocessable("idempotency_key_reused")
            }
            _ => error.into(),
        });
    }

    let outcome = if rejection.is_some() {
        audit::Outcome::Failure
    } else {
        audit::Outcome::Success
    };
    record_audit(
        &mut tx,
        &ctx,
        request.kind,
        Some(command_id),
        outcome,
        json!({ "panel_id": panel_id, "partition_id": request.partition_id, "status": status, "reason": reason }),
    )
    .await?;
    let view: CommandView = sqlx::query_as(
        "SELECT id, panel_id, partition_id, kind, zones, status, rejection_reason,
                requested_at, completed_at, user_id
           FROM commands WHERE id = $1 AND organization_id = $2",
    )
    .bind(command_id)
    .bind(org_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;

    if let Some(rejection) = rejection {
        return Err(ApiError::Conflict(rejection_code(&rejection)));
    }
    if simulated {
        simulator::schedule(state.clone(), org_id, command_id);
    }
    Ok((StatusCode::ACCEPTED, Json(view)))
}

/// Komutun durumu. Yöneticiler organizasyondaki bütün komutları, diğerleri yalnızca kendi
/// komutlarını görür.
pub async fn get_command(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_id, command_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<CommandView>> {
    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    let view: Option<CommandView> = sqlx::query_as(
        "SELECT id, panel_id, partition_id, kind, zones, status, rejection_reason,
                requested_at, completed_at, user_id
           FROM commands WHERE id = $1 AND organization_id = $2",
    )
    .bind(command_id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    match view {
        Some(view) if ctx.role.is_manager() || view.user_id == ctx.user.user_id => Ok(Json(view)),
        _ => Err(ApiError::NotFound),
    }
}
