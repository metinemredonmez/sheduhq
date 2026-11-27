//! Bildirim tercihleri entegrasyon testleri: alarm kapatılamaz, tercih yalnızca kişinin kendi
//! bildirimlerini etkiler.
#![cfg(feature = "db-tests")]

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use uuid::Uuid;

const MEMBER: &str = "+905557776655";
const OUTSIDER: &str = "+905553332211";

fn key() -> String {
    format!("test-{}", Uuid::new_v4().simple())
}

async fn join(app: &TestApp, by: &str, org: &str, phone: &str) -> (String, String, String) {
    let (status, body) = app
        .post_auth(
            &format!("/v1/organizations/{org}/invitations"),
            json!({ "phone": phone, "role": "member" }),
            by,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (access, user_id, home) = app.user(phone).await;
    let (_, mine) = app.get("/v1/invitations", &access).await;
    let id = s(&mine["invitations"][0], "id");
    let (status, body) = app
        .post_auth(&format!("/v1/invitations/{id}/accept"), json!({}), &access)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (access, user_id, home)
}

async fn preferences(app: &TestApp, access: &str, org: &str) -> (StatusCode, Value) {
    app.get(
        &format!("/v1/organizations/{org}/notification-preferences"),
        access,
    )
    .await
}

async fn set(app: &TestApp, access: &str, org: &str, body: Value) -> (StatusCode, Value) {
    app.patch(
        &format!("/v1/organizations/{org}/notification-preferences"),
        body,
        access,
    )
    .await
}

fn enabled(list: &Value, category: &str) -> bool {
    list["preferences"]
        .as_array()
        .and_then(|l| l.iter().find(|p| p["category"] == category))
        .and_then(|p| p["enabled"].as_bool())
        .expect("kategori")
}

#[sqlx::test(migrations = "../../migrations")]
async fn preferences_default_on_and_alarms_cannot_be_disabled(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (owner, owner_id, org) = app.user(PHONE).await;

    let (status, list) = preferences(&app, &owner, &org).await;
    assert_eq!(status, StatusCode::OK);
    let all = list["preferences"].as_array().expect("liste");
    assert_eq!(all.len(), 4);
    assert!(
        all.iter().all(|p| p["enabled"] == true),
        "varsayılan hepsi açık"
    );
    let alarm = all
        .iter()
        .find(|p| p["category"] == "alarm")
        .expect("alarm");
    assert_eq!(alarm["can_disable"], false);

    // Alarm kapatılamaz; kapatma isteği başka değişikliği de uygulamaz.
    let (status, body) = set(
        &app,
        &owner,
        &org,
        json!({ "alarm": false, "power": false }),
    )
    .await;
    assert_eq!(
        (status, s(&body, "error")),
        (
            StatusCode::BAD_REQUEST,
            "alarm_notifications_required".into()
        )
    );
    let (_, list) = preferences(&app, &owner, &org).await;
    assert!(enabled(&list, "power"));

    let (status, list) = set(&app, &owner, &org, json!({ "arming": false })).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!enabled(&list, "arming") && enabled(&list, "alarm") && enabled(&list, "power"));
    let (status, list) = set(&app, &owner, &org, json!({ "alarm": true, "power": false })).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!enabled(&list, "power") && enabled(&list, "alarm"));
    let (status, _) = set(&app, &owner, &org, json!({ "sound": false })).await;
    assert!(status.is_client_error(), "bilinmeyen alan reddedilmeli");

    let (rows,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM notification_preferences WHERE user_id = $1::uuid")
            .bind(&owner_id)
            .fetch_one(&app.admin)
            .await
            .expect("sorgu");
    assert_eq!(rows, 2);
    let (audits,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM audit_log WHERE action = 'notification.preferences_updated'",
    )
    .fetch_one(&app.admin)
    .await
    .expect("sorgu");
    assert_eq!(audits, 2);

    // Üye olmayan kişi bu organizasyonda tercih göremez ve yazamaz.
    let (outsider, _, _) = app.user(OUTSIDER).await;
    assert_eq!(
        preferences(&app, &outsider, &org).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        set(&app, &outsider, &org, json!({ "arming": false }))
            .await
            .0,
        StatusCode::NOT_FOUND
    );

    // Tercih organizasyon başınadır: üyenin buradaki tercihi kendi evini etkilemez.
    let (member, _, member_home) = join(&app, &owner, &org, MEMBER).await;
    let (status, _) = set(&app, &member, &org, json!({ "connectivity": false })).await;
    assert_eq!(status, StatusCode::OK);
    let (_, home) = preferences(&app, &member, &member_home).await;
    assert!(enabled(&home, "connectivity"));
    let (_, here) = preferences(&app, &owner, &org).await;
    assert!(
        enabled(&here, "connectivity"),
        "başkasının tercihi sahibinkini değiştirmemeli"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn dispatch_respects_preferences_but_always_sends_alarms(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    app.start_background().await;
    let (owner, _, org) = app.user(PHONE).await;
    let (status, _) = app
        .post_auth(
            &format!("/v1/organizations/{org}/demo-panel"),
            json!({}),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, panels) = app
        .get(&format!("/v1/organizations/{org}/panels"), &owner)
        .await;
    let panel = s(&panels[0], "id");
    let garage = panels[0]["partitions"]
        .as_array()
        .and_then(|l| l.iter().find(|p| p["number"] == 2))
        .map(|p| s(p, "id"))
        .expect("garaj");
    let (member, member_id, _) = join(&app, &owner, &org, MEMBER).await;
    let (status, _) = app
        .post_auth(
            &format!("/v1/organizations/{org}/members/{member_id}/grants"),
            json!({
                "panel_id": panel, "partition_id": garage,
                "can_view_events": true, "can_arm": true, "can_disarm": true, "can_bypass": false,
                "always_open": true
            }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    for (access, token) in [(&owner, "owner-device"), (&member, "member-device")] {
        let (status, _) = app
            .put(
                "/v1/devices/current/push-token",
                json!({ "token": token }),
                access,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    let (status, _) = set(&app, &member, &org, json!({ "arming": false })).await;
    assert_eq!(status, StatusCode::OK);

    // Kurma: yalnızca sahibe gider.
    let command = |kind: &'static str| json!({ "partition_id": garage, "kind": kind, "idempotency_key": key() });
    let (status, _) = app
        .post_auth(
            &format!("/v1/organizations/{org}/panels/{panel}/commands"),
            command("arm_away"),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(tokens_for(&app, "armed").await, vec!["owner-device"]);

    // Alarm: kurmayı kapatmış üyeye de gider.
    let (status, alarm) = app
        .post_auth(
            &format!("/v1/organizations/{org}/panels/{panel}/simulate-alarm"),
            json!({ "zone_number": 5 }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{alarm}");
    assert_eq!(
        tokens_for(&app, "alarm").await,
        vec!["member-device", "owner-device"]
    );

    // Üye tercihi geri açınca kapatma bildirimi ikisine de gider.
    let (status, _) = set(&app, &member, &org, json!({ "arming": true })).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = app
        .post_auth(
            &format!("/v1/organizations/{org}/panels/{panel}/commands"),
            command("disarm"),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(
        tokens_for(&app, "disarmed").await,
        vec!["member-device", "owner-device"]
    );
}

/// Belirli türdeki olay için gönderilen push'ların cihaz token'ları (sıralı).
async fn tokens_for(app: &TestApp, kind: &str) -> Vec<String> {
    for _ in 0..200 {
        if app.push.messages().iter().any(|m| m.kind == kind) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut tokens: Vec<String> = app
        .push
        .messages()
        .into_iter()
        .filter(|m| m.kind == kind)
        .map(|m| m.token)
        .collect();
    tokens.sort();
    tokens
}
