//! Bildirim tercihleri: kişi, üyesi olduğu her organizasyonda hangi bildirim kategorilerini
//! alacağını seçer. Alarm bildirimleri kapatılamaz (domain kuralı ve veritabanı kısıtı). Tercih
//! yalnızca push'u etkiler; olaylar geçmişte ve WebSocket akışında her zaman görünür.

use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use shedu_domain::alarm::NotificationCategory;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{
    AppState, audit,
    auth::AuthUser,
    authz::{self, OrgContext},
    error::{ApiError, ApiResult},
};

pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/organizations/{org_id}/notification-preferences",
        get(list).patch(update),
    )
}

pub(crate) fn category_name(category: NotificationCategory) -> &'static str {
    match category {
        NotificationCategory::Alarm => "alarm",
        NotificationCategory::Connectivity => "connectivity",
        NotificationCategory::Power => "power",
        NotificationCategory::Arming => "arming",
    }
}

/// Veritabanındaki olay türünün bildirim kategorisi.
pub(crate) fn category_of_event(kind: &str) -> Option<NotificationCategory> {
    Some(match kind {
        "alarm" => NotificationCategory::Alarm,
        "connected" | "disconnected" => NotificationCategory::Connectivity,
        "power_problem" => NotificationCategory::Power,
        "armed" | "disarmed" => NotificationCategory::Arming,
        _ => return None,
    })
}

#[derive(Serialize)]
pub struct Preference {
    category: &'static str,
    enabled: bool,
    can_disable: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Update {
    alarm: Option<bool>,
    connectivity: Option<bool>,
    power: Option<bool>,
    arming: Option<bool>,
}

async fn current(conn: &mut PgConnection, ctx: &OrgContext) -> ApiResult<Vec<Preference>> {
    let disabled: Vec<(String,)> = sqlx::query_as(
        "SELECT category FROM notification_preferences
          WHERE user_id = $1 AND organization_id = $2 AND NOT enabled",
    )
    .bind(ctx.user.user_id)
    .bind(ctx.organization_id)
    .fetch_all(conn)
    .await?;
    Ok(NotificationCategory::ALL
        .into_iter()
        .map(|category| {
            let name = category_name(category);
            Preference {
                category: name,
                enabled: !category.can_be_disabled() || !disabled.iter().any(|(c,)| c == name),
                can_disable: category.can_be_disabled(),
            }
        })
        .collect())
}

pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    let preferences = current(&mut tx, &ctx).await?;
    tx.commit().await?;
    Ok(Json(json!({ "preferences": preferences })))
}

/// Yalnızca gönderilen kategoriler değişir. Alarmı kapatma isteği reddedilir.
pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path(org_id): Path<Uuid>,
    Json(request): Json<Update>,
) -> ApiResult<Json<serde_json::Value>> {
    if request.alarm == Some(false) {
        return Err(ApiError::BadRequest("alarm_notifications_required"));
    }
    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    let changes: Vec<(NotificationCategory, bool)> = [
        (NotificationCategory::Connectivity, request.connectivity),
        (NotificationCategory::Power, request.power),
        (NotificationCategory::Arming, request.arming),
    ]
    .into_iter()
    .filter_map(|(category, value)| value.map(|v| (category, v)))
    .collect();

    for (category, enabled) in &changes {
        sqlx::query(
            "INSERT INTO notification_preferences (user_id, organization_id, category, enabled)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (user_id, organization_id, category)
             DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = now()",
        )
        .bind(ctx.user.user_id)
        .bind(org_id)
        .bind(category_name(*category))
        .bind(enabled)
        .execute(&mut *tx)
        .await?;
    }
    if !changes.is_empty() {
        let details: serde_json::Map<String, serde_json::Value> = changes
            .iter()
            .map(|(category, enabled)| (category_name(*category).to_owned(), json!(enabled)))
            .collect();
        // Kimin hangi bildirimi kapattığı, "haber verildi mi?" sorusunun kanıtının parçasıdır.
        audit::record(
            &mut tx,
            audit::Event {
                organization_id: Some(org_id),
                actor_user_id: Some(ctx.user.user_id),
                action: "notification.preferences_updated",
                target_type: Some("user"),
                target_id: Some(&ctx.user.user_id.to_string()),
                outcome: audit::Outcome::Success,
                details: serde_json::Value::Object(details),
            },
        )
        .await?;
    }
    let preferences = current(&mut tx, &ctx).await?;
    tx.commit().await?;
    Ok(Json(json!({ "preferences": preferences })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_event_kind_has_a_category_and_alarms_are_locked() {
        for kind in [
            "alarm",
            "armed",
            "disarmed",
            "connected",
            "disconnected",
            "power_problem",
        ] {
            assert!(category_of_event(kind).is_some(), "{kind}");
        }
        assert_eq!(category_of_event("bilinmeyen"), None);
        let alarm = category_of_event("alarm").expect("alarm");
        assert!(!alarm.can_be_disabled());
    }
}
