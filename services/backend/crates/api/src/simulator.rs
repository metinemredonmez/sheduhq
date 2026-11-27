//! Sanal (demo) panel simülatörü.
//!
//! Gerçek panellerde komutu gateway tamamlar. Sanal panelde kısa bir gecikmeden sonra komut
//! başarılı sayılır, bölüm durumu güncellenir ve panel olayı yazılır; böylece uygulama uçtan uca
//! (WebSocket bildirimleri dahil) gerçek bir panel olmadan denenebilir. Yalnızca `simulated`
//! işaretli panellerdeki komutlara dokunur.

use uuid::Uuid;

use crate::{AppState, audit, db::set_context};

/// (panel, bölüm, tür, zonlar, bölüm numarası)
type CompletedCommand = (Uuid, Uuid, String, Option<Vec<i16>>, i16);

/// Kabul edilip bu kadar süre içinde tamamlanmayan sanal komut takılmış sayılır (süreç yeniden
/// başladı veya tamamlama başarısız oldu).
const STALE_AFTER_SECS: i32 = 30;

/// Takılan sanal komutları açılışta ve dakikada bir tamamlar (BUS-01, ARC-05). Komut kalıcı olarak
/// `accepted` durumunda bekler; süreç içindeki zamanlayıcı kaybolsa da tarama onu bulur ve aynı
/// koşullu güncellemeyle (`status = 'accepted'`) bir kez tamamlar. Böylece bölümdeki bekleyen
/// komut kısıtı sonraki komutları kalıcı olarak engellemez.
pub fn start_recovery(state: &AppState) -> tokio::task::JoinHandle<()> {
    let state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            match recover_stale(&state, STALE_AFTER_SECS).await {
                Ok(0) => {}
                Ok(count) => tracing::warn!(count, "takılan sanal panel komutları tamamlandı"),
                Err(error) => tracing::error!(?error, "takılan sanal komut taraması başarısız"),
            }
        }
    })
}

/// `max_age_secs` saniyeden eski, hâlâ `accepted` sanal komutları tamamlar; tamamlanan sayısını
/// döner.
pub async fn recover_stale(state: &AppState, max_age_secs: i32) -> Result<usize, sqlx::Error> {
    let stale: Vec<(Uuid, Uuid)> =
        sqlx::query_as("SELECT id, organization_id FROM stale_simulated_commands($1, 100)")
            .bind(max_age_secs)
            .fetch_all(&state.db)
            .await?;
    let mut completed = 0;
    for (command_id, organization_id) in stale {
        if complete(state, organization_id, command_id).await? {
            completed += 1;
        }
    }
    Ok(completed)
}

pub fn schedule(state: AppState, organization_id: Uuid, command_id: Uuid) {
    tokio::spawn(async move {
        tokio::time::sleep(state.simulator_delay).await;
        if let Err(error) = complete(&state, organization_id, command_id).await {
            tracing::warn!(?error, %command_id, "sanal panel komutu tamamlanamadı");
        }
    });
}

/// Komutu tamamlar; komut zaten tamamlandıysa (başka kopya veya tarama) hiçbir şey yapmaz.
/// Tamamladıysa `true`.
async fn complete(
    state: &AppState,
    organization_id: Uuid,
    command_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let mut tx = state.db.begin().await?;
    set_context(&mut tx, None, Some(organization_id)).await?;

    let done: Option<CompletedCommand> = sqlx::query_as(
        "UPDATE commands c SET status = 'succeeded', completed_at = now()
           FROM panels p, partitions pt
          WHERE c.id = $1 AND c.status = 'accepted'
            AND p.id = c.panel_id AND p.simulated
            AND pt.id = c.partition_id
          RETURNING c.panel_id, c.partition_id, c.kind, c.zones, pt.number",
    )
    .bind(command_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((panel_id, partition_id, kind, zones, partition_number)) = done else {
        tx.commit().await?;
        return Ok(false);
    };

    let new_state = match kind.as_str() {
        "arm_away" => Some(("armed_away", "armed", Some("away"))),
        "arm_stay" => Some(("armed_stay", "armed", Some("stay"))),
        "arm_night" => Some(("armed_night", "armed", Some("night"))),
        "disarm" => Some(("disarmed", "disarmed", None)),
        _ => None,
    };

    if let Some((partition_state, event_kind, arm_mode)) = new_state {
        sqlx::query("UPDATE partitions SET state = $1, state_changed_at = now() WHERE id = $2")
            .bind(partition_state)
            .bind(partition_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO panel_events (organization_id, panel_id, partition_number, kind, arm_mode, priority, occurred_at)
             VALUES ($1, $2, $3, $4, $5, 'info', now())",
        )
        .bind(organization_id)
        .bind(panel_id)
        .bind(partition_number)
        .bind(event_kind)
        .bind(arm_mode)
        .execute(&mut *tx)
        .await?;
    } else {
        sqlx::query("UPDATE zones SET bypassed = $1 WHERE panel_id = $2 AND number = ANY($3)")
            .bind(kind == "bypass_zones")
            .bind(panel_id)
            .bind(zones.unwrap_or_default())
            .execute(&mut *tx)
            .await?;
    }

    audit::record(
        &mut tx,
        audit::Event {
            organization_id: Some(organization_id),
            actor_user_id: None,
            action: "command.completed",
            target_type: Some("command"),
            target_id: Some(&command_id.to_string()),
            outcome: audit::Outcome::Success,
            details: serde_json::json!({ "simulated": true }),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}
