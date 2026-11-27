//! Olay geçmişi, push bildirimleri, panik ve sanal alarm entegrasyon testleri.
#![cfg(feature = "db-tests")]

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use serde_json::{Value, json};
use shedu_api::push::{self, PushPriority};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use uuid::Uuid;

const MEMBER_PHONE: &str = "+905557776655";
const MEMBER2_PHONE: &str = "+905554443322";
const OUTSIDER_PHONE: &str = "+905553332211";

fn key() -> String {
    format!("test-{}", Uuid::new_v4().simple())
}

struct Demo {
    org: String,
    panel: String,
    home: String,
    garage: String,
}

async fn demo(app: &TestApp, access: &str, org: &str) -> Demo {
    let (status, _) = app
        .post_auth(
            &format!("/v1/organizations/{org}/demo-panel"),
            json!({}),
            access,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, panels) = app
        .get(&format!("/v1/organizations/{org}/panels"), access)
        .await;
    let panel = &panels[0];
    let partition = |number: i64| {
        panel["partitions"]
            .as_array()
            .and_then(|list| list.iter().find(|p| p["number"] == number))
            .map(|p| s(p, "id"))
            .expect("bölüm")
    };
    Demo {
        org: org.to_owned(),
        panel: s(panel, "id"),
        home: partition(1),
        garage: partition(2),
    }
}

/// Komut verir ve tamamlanmasını bekler.
async fn run(app: &TestApp, access: &str, d: &Demo, partition: &str, kind: &str) {
    let (status, body) = app
        .post_auth(
            &format!("/v1/organizations/{}/panels/{}/commands", d.org, d.panel),
            json!({ "partition_id": partition, "kind": kind, "idempotency_key": key() }),
            access,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let id = s(&body, "id");
    for _ in 0..100 {
        let (_, c) = app
            .get(
                &format!("/v1/organizations/{}/commands/{id}", d.org),
                access,
            )
            .await;
        if c["status"] == "succeeded" {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("komut tamamlanmadı");
}

async fn add_member(app: &TestApp, org: &str, user: &str, panel: &str, partition: Option<&str>) {
    sqlx::query("INSERT INTO memberships (user_id, organization_id, role) VALUES ($1::uuid, $2::uuid, 'member')")
        .bind(user)
        .bind(org)
        .execute(&app.admin)
        .await
        .expect("üyelik");
    sqlx::query(
        "INSERT INTO access_grants (organization_id, user_id, panel_id, partition_id, can_arm, can_disarm, can_view_events, always_open)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, true, true, true, true)",
    )
    .bind(org)
    .bind(user)
    .bind(panel)
    .bind(partition)
    .execute(&app.admin)
    .await
    .expect("yetki");
}

async fn set_token(app: &TestApp, access: &str, token: &str) {
    let (status, _) = app
        .put(
            "/v1/devices/current/push-token",
            json!({ "token": token }),
            access,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

async fn simulate(app: &TestApp, access: &str, d: &Demo, zone: i16) -> (StatusCode, Value) {
    app.post_auth(
        &format!(
            "/v1/organizations/{}/panels/{}/simulate-alarm",
            d.org, d.panel
        ),
        json!({ "zone_number": zone }),
        access,
    )
    .await
}

/// Belirli bir olay için gelen push'ları bekler.
async fn pushes_for(app: &TestApp, event_id: i64, expected: usize) -> Vec<push::PushMessage> {
    for _ in 0..150 {
        let found: Vec<_> = app
            .push
            .messages()
            .into_iter()
            .filter(|m| m.event_id == event_id)
            .collect();
        if found.len() >= expected {
            tokio::time::sleep(Duration::from_millis(200)).await;
            return app
                .push
                .messages()
                .into_iter()
                .filter(|m| m.event_id == event_id)
                .collect();
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    app.push
        .messages()
        .into_iter()
        .filter(|m| m.event_id == event_id)
        .collect()
}

fn event_id(body: &Value) -> i64 {
    body["event_id"].as_i64().expect("event_id")
}

// ---------------------------------------------------------------------------------------------
// Olay geçmişi
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn event_history_is_paginated_filtered_and_private(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let d = demo(&app, &owner, &org).await;
    run(&app, &owner, &d, &d.home, "arm_away").await;
    run(&app, &owner, &d, &d.home, "disarm").await;
    run(&app, &owner, &d, &d.home, "arm_stay").await;

    let base = format!("/v1/organizations/{}/panels/{}/events", d.org, d.panel);
    let (status, page1) = app.get(&format!("{base}?limit=2"), &owner).await;
    assert_eq!(status, StatusCode::OK);
    let kinds: Vec<&str> = page1["events"]
        .as_array()
        .expect("liste")
        .iter()
        .map(|e| e["kind"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(kinds, ["armed", "disarmed"], "yeniden eskiye");
    let before = page1["next_before"].as_i64().expect("sonraki sayfa");
    let (_, page2) = app
        .get(&format!("{base}?limit=2&before={before}"), &owner)
        .await;
    assert_eq!(page2["events"].as_array().map(Vec::len), Some(1));
    assert!(page2["next_before"].is_null());

    let (_, future) = app
        .get(&format!("{base}?from=2099-01-01T00:00:00Z"), &owner)
        .await;
    assert_eq!(future["events"].as_array().map(Vec::len), Some(0));
    let (status, _) = app.get(&format!("{base}?limit=0"), &owner).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = app.get(&format!("{base}?role=admin"), &owner).await;
    assert!(
        status.is_client_error(),
        "bilinmeyen parametre reddedilmeli"
    );

    let (outsider, _, _) = app.user(OUTSIDER_PHONE).await;
    let (status, _) = app.get(&base, &outsider).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "../../migrations")]
async fn member_sees_only_events_of_permitted_partitions(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let d = demo(&app, &owner, &org).await;
    let (member, member_id, _) = app.user(MEMBER_PHONE).await;
    add_member(&app, &org, &member_id, &d.panel, Some(&d.garage)).await;

    run(&app, &owner, &d, &d.home, "arm_away").await;
    run(&app, &member, &d, &d.garage, "arm_away").await;

    let base = format!("/v1/organizations/{}/panels/{}/events", d.org, d.panel);
    let (_, owners) = app.get(&base, &owner).await;
    assert_eq!(owners["events"].as_array().map(Vec::len), Some(2));
    let (_, members) = app.get(&base, &member).await;
    let numbers: Vec<i64> = members["events"]
        .as_array()
        .expect("liste")
        .iter()
        .filter_map(|e| e["partition_number"].as_i64())
        .collect();
    assert_eq!(numbers, [2], "üye yalnızca garaj olaylarını görmeli");
}

// ---------------------------------------------------------------------------------------------
// Push bildirimleri
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn alarm_push_reaches_only_authorized_devices_with_critical_priority(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    app.start_background().await;
    let (owner, owner_id, org) = app.user(PHONE).await;
    let d = demo(&app, &owner, &org).await;
    let (garage_member, garage_id, _) = app.user(MEMBER_PHONE).await;
    let (home_member, home_id, _) = app.user(MEMBER2_PHONE).await;
    let (outsider, _, _) = app.user(OUTSIDER_PHONE).await;
    add_member(&app, &org, &garage_id, &d.panel, Some(&d.garage)).await;
    add_member(&app, &org, &home_id, &d.panel, Some(&d.home)).await;
    for (access, token) in [
        (&owner, "tok-owner"),
        (&garage_member, "tok-garage"),
        (&home_member, "tok-home"),
        (&outsider, "tok-outsider"),
    ] {
        set_token(&app, access, token).await;
    }

    run(&app, &owner, &d, &d.home, "arm_away").await;
    let (status, body) = simulate(&app, &owner, &d, 1).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let pushes = pushes_for(&app, event_id(&body), 2).await;

    let mut tokens: Vec<&str> = pushes.iter().map(|m| m.token.as_str()).collect();
    tokens.sort_unstable();
    assert_eq!(
        tokens,
        ["tok-home", "tok-owner"],
        "yalnızca ev bölümünü görebilenler"
    );
    assert!(pushes.iter().all(|m| m.priority == PushPriority::Critical));
    assert_eq!(pushes[0].body, "Hırsızlık alarmı — Ön kapı");
    assert!(pushes.iter().any(|m| m.user_id.to_string() == owner_id));

    let (deliveries,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM push_deliveries WHERE panel_event_id = $1 AND status = 'sent'",
    )
    .bind(event_id(&body))
    .fetch_one(&app.admin)
    .await
    .expect("sayım");
    assert_eq!(deliveries, 2, "teslim kaydı tutulmalı");

    // Alarm kapatılabilir.
    run(&app, &owner, &d, &d.home, "disarm").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn intrusion_needs_armed_partition_but_fire_is_always_active(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let d = demo(&app, &owner, &org).await;

    let (status, body) = simulate(&app, &owner, &d, 1).await;
    assert_eq!(
        (status, s(&body, "error")),
        (StatusCode::CONFLICT, "partition_not_armed".into())
    );
    let (status, _) = simulate(&app, &owner, &d, 3).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "yangın zonu her zaman alarm verir"
    );

    let (_, detail) = app
        .get(
            &format!("/v1/organizations/{}/panels/{}", d.org, d.panel),
            &owner,
        )
        .await;
    let home = detail["partitions"]
        .as_array()
        .and_then(|p| p.iter().find(|p| p["number"] == 1))
        .cloned()
        .expect("bölüm");
    assert_eq!(home["state"], "alarm");

    let (member, member_id, _) = app.user(MEMBER_PHONE).await;
    add_member(&app, &org, &member_id, &d.panel, None).await;
    let (status, _) = simulate(&app, &member, &d, 3).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "yalnızca yönetici simüle edebilir"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn logged_out_device_gets_no_push(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    app.start_background().await;
    let (phone_access, _, org) = app.user(PHONE).await;
    let d = demo(&app, &phone_access, &org).await;
    let (_, tablet) = app.login(PHONE, PASSWORD).await;
    let tablet_access = s(&tablet, "access_token");
    set_token(&app, &phone_access, "tok-phone").await;
    set_token(&app, &tablet_access, "tok-tablet").await;

    let (status, _) = app
        .post_auth("/v1/auth/logout", json!({}), &tablet_access)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, body) = simulate(&app, &phone_access, &d, 3).await;
    let pushes = pushes_for(&app, event_id(&body), 1).await;
    let tokens: Vec<&str> = pushes.iter().map(|m| m.token.as_str()).collect();
    assert_eq!(
        tokens,
        ["tok-phone"],
        "çıkış yapılmış tablete bildirim gitmemeli"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn same_push_token_moves_to_the_new_account(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (first, first_id, _) = app.user(PHONE).await;
    let (second, _, _) = app.user(MEMBER_PHONE).await;
    set_token(&app, &first, "paylasilan-cihaz").await;
    set_token(&app, &second, "paylasilan-cihaz").await;

    let (count,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM user_devices WHERE user_id = $1::uuid AND push_token IS NOT NULL",
    )
    .bind(&first_id)
    .fetch_one(&app.admin)
    .await
    .expect("sayım");
    assert_eq!(count, 0, "eski hesaptan silinmeli");
    let (status, _) = app
        .put(
            "/v1/devices/current/push-token",
            json!({ "token": "bosluk var" }),
            &first,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "../../migrations")]
async fn panic_sends_critical_push_to_everyone_who_can_view(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    app.start_background().await;
    let (owner, _, org) = app.user(PHONE).await;
    let d = demo(&app, &owner, &org).await;
    let (member, member_id, _) = app.user(MEMBER_PHONE).await;
    add_member(&app, &org, &member_id, &d.panel, Some(&d.garage)).await;
    set_token(&app, &owner, "tok-owner").await;
    set_token(&app, &member, "tok-member").await;

    let panic_path = format!("/v1/organizations/{}/panels/{}/panic", d.org, d.panel);
    let (status, body) = app
        .post_auth(&panic_path, json!({ "kind": "police" }), &member)
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let pushes = pushes_for(&app, event_id(&body), 2).await;
    assert_eq!(pushes.len(), 2, "panel düzeyindeki panik herkese gitmeli");
    assert!(
        pushes
            .iter()
            .all(|m| m.priority == PushPriority::Critical && m.body == "Panik alarmı")
    );

    let (source,): (String,) = sqlx::query_as("SELECT source FROM panel_events WHERE id = $1")
        .bind(event_id(&body))
        .fetch_one(&app.admin)
        .await
        .expect("olay");
    assert_eq!(source, "app");

    let (outsider, _, _) = app.user(OUTSIDER_PHONE).await;
    let (status, _) = app
        .post_auth(&panic_path, json!({ "kind": "fire" }), &outsider)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "../../migrations")]
async fn dispatch_is_exactly_once_and_sweep_recovers_missed_events(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    // Arka plan görevleri bilerek başlatılmıyor: NOTIFY kaçırılmış gibi.
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let d = demo(&app, &owner, &org).await;
    set_token(&app, &owner, "tok-owner").await;

    let (_, first) = simulate(&app, &owner, &d, 3).await;
    let (_, second) = simulate(&app, &owner, &d, 4).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        app.push.messages().is_empty(),
        "dağıtıcı çalışmıyor; henüz bildirim olmamalı"
    );

    // İki kopya aynı anda aynı olayı dağıtmaya çalışır: yalnızca biri gönderir.
    let org_id: Uuid = org.parse().expect("uuid");
    let (a, b) = tokio::join!(
        push::dispatch(&app.state, org_id, event_id(&first)),
        push::dispatch(&app.state, org_id, event_id(&first)),
    );
    assert_eq!(a.expect("dağıtım") + b.expect("dağıtım"), 1, "tek gönderim");

    // Kaçırılan ikinci olay taramayla yakalanır.
    sqlx::query(
        "UPDATE panel_events SET received_at = now() - interval '10 seconds' WHERE id = $1",
    )
    .bind(event_id(&second))
    .execute(&app.admin)
    .await
    .expect("güncelleme");
    let swept = push::sweep_pending(&app.state).await.expect("tarama");
    assert_eq!(swept, 1);
    assert_eq!(app.push.messages().len(), 2);
    assert_eq!(
        push::sweep_pending(&app.state).await.expect("tarama"),
        0,
        "ikinci tarama boş"
    );
}
