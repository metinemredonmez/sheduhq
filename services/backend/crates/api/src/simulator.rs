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

pub fn schedule(state: AppState, organization_id: Uuid, command_id: Uuid) {
    tokio::spawn(async move {
        tokio::time::sleep(state.simulator_delay).await;
        if let Err(error) = complete(&state, organization_id, command_id).await {
            tracing::warn!(?error, %command_id, "sanal panel komutu tamamlanamadı");
        }
    });
}

async fn complete(
    state: &AppState,
    organization_id: Uuid,
    command_id: Uuid,
) -> Result<(), sqlx::Error> {
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
        return Ok(());
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
    tx.commit().await
}
