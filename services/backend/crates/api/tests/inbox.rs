//! Bildirim merkezi entegrasyon testleri: görünürlük, okundu bilgisi, üyelik ve MFA.
#![cfg(feature = "db-tests")]

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use uuid::Uuid;

const MEMBER: &str = "+905557776655";

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
    let partition = |n: i64| {
        panels[0]["partitions"]
            .as_array()
            .and_then(|l| l.iter().find(|p| p["number"] == n))
            .map(|p| s(p, "id"))
            .expect("bölüm")
    };
    Demo {
        org: org.to_owned(),
        panel: s(&panels[0], "id"),
        home: partition(1),
        garage: partition(2),
    }
}

/// Komut verir ve tamamlanmasını bekler.
async fn run(app: &TestApp, access: &str, d: &Demo, partition: &str, kind: &str) {
    let (status, body) = app
        .post_auth(
            &format!("/v1/organizations/{}/panels/{}/commands", d.org, d.panel),
            json!({ "partition_id": partition, "kind": kind,
                    "idempotency_key": format!("test-{}", Uuid::new_v4().simple()) }),
            access,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let id = s(&body, "id");
    for _ in 0..200 {
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

async fn join(app: &TestApp, owner: &str, org: &str) -> (String, String) {
    let (status, _) = app
        .post_auth(
            &format!("/v1/organizations/{org}/invitations"),
            json!({ "phone": MEMBER, "role": "member" }),
            owner,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (access, user_id, _) = app.user(MEMBER).await;
    let (_, mine) = app.get("/v1/invitations", &access).await;
    let id = s(&mine["invitations"][0], "id");
    let (status, _) = app
        .post_auth(&format!("/v1/invitations/{id}/accept"), json!({}), &access)
        .await;
    assert_eq!(status, StatusCode::OK);
    (access, user_id)
}

async fn grant(app: &TestApp, owner: &str, d: &Demo, member: &str, partition: Option<&str>) {
    let (status, body) = app
        .post_auth(
            &format!("/v1/organizations/{}/members/{member}/grants", d.org),
            json!({
                "panel_id": d.panel, "partition_id": partition,
                "can_view_events": true, "can_arm": true, "can_disarm": true, "can_bypass": false,
                "always_open": true
            }),
            owner,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

async fn feed(app: &TestApp, access: &str, query: &str) -> Value {
    let (status, body) = app.get(&format!("/v1/notifications{query}"), access).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

fn items(body: &Value) -> &Vec<Value> {
    body["notifications"].as_array().expect("liste")
}

async fn unread(app: &TestApp, access: &str) -> i64 {
    let (status, body) = app.get("/v1/notifications/unread-count", access).await;
    assert_eq!(status, StatusCode::OK);
    body["total"].as_i64().expect("sayı")
}

async fn read(app: &TestApp, access: &str, body: Value) -> (StatusCode, Value) {
    app.post_auth("/v1/notifications/read", body, access).await
}

/// Olay kaydını (ve olay sayısını) bekler.
async fn wait_events(app: &TestApp, org: &str, expected: i64) {
    for _ in 0..200 {
        let (n,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM panel_events WHERE organization_id = $1::uuid")
                .bind(org)
                .fetch_one(&app.admin)
                .await
                .expect("sorgu");
        if n >= expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("olaylar gelmedi");
}

#[sqlx::test(migrations = "../../migrations")]
async fn inbox_shows_only_visible_events_and_tracks_read_state(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let d = demo(&app, &owner, &org).await;
    let (member, member_id) = join(&app, &owner, &org).await;
    grant(&app, &owner, &d, &member_id, Some(&d.garage)).await;

    run(&app, &owner, &d, &d.home, "arm_away").await;
    run(&app, &owner, &d, &d.garage, "arm_away").await;
    let (status, _) = app
        .post_auth(
            &format!("/v1/organizations/{org}/panels/{}/simulate-alarm", d.panel),
            json!({ "zone_number": 3 }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    wait_events(&app, &org, 3).await;

    // Sahip hepsini, üye yalnızca garajı görür.
    let owners = feed(&app, &owner, "").await;
    assert_eq!(items(&owners).len(), 3);
    assert!(items(&owners).iter().all(|n| n["read"] == false));
    let alarm = &items(&owners)[0];
    assert_eq!(
        (alarm["kind"].as_str(), alarm["priority"].as_str()),
        (Some("alarm"), Some("critical"))
    );
    assert!(s(alarm, "body").contains("Yangın alarmı"));
    assert_eq!(alarm["organization_id"], org.as_str());
    let members = feed(&app, &member, "").await;
    assert_eq!(
        items(&members).len(),
        1,
        "üye yalnızca yetkili bölümü görür"
    );
    let garage_event = items(&members)[0]["event_id"].as_i64().expect("olay");
    assert_eq!(
        (unread(&app, &owner).await, unread(&app, &member).await),
        (3, 1)
    );

    // Görülemeyen olay okundu yapılamaz (sessizce yok sayılır); görülebilen yapılır.
    let home_event = items(&owners)
        .iter()
        .find(|n| n["kind"] == "armed" && n["event_id"] != garage_event)
        .and_then(|n| n["event_id"].as_i64())
        .expect("ev olayı");
    let (status, body) = read(&app, &member, json!({ "event_ids": [home_event] })).await;
    assert_eq!((status, body["marked"].as_i64()), (StatusCode::OK, Some(0)));
    let (_, body) = read(&app, &member, json!({ "event_ids": [garage_event] })).await;
    assert_eq!(body["marked"], 1);
    assert_eq!(unread(&app, &member).await, 0);
    assert_eq!(items(&feed(&app, &member, "").await)[0]["read"], true);
    assert_eq!(
        unread(&app, &owner).await,
        3,
        "başkasının okuması etkilemez"
    );

    // Sayfalama ve yalnızca okunmamışlar.
    let page = feed(&app, &owner, "?limit=2").await;
    assert_eq!(items(&page).len(), 2);
    let cursor = page["next_before"].as_i64().expect("imleç");
    let rest = feed(&app, &owner, &format!("?limit=2&before={cursor}")).await;
    assert_eq!(items(&rest).len(), 1);
    assert!(rest["next_before"].is_null());
    let alarm_id = alarm["event_id"].as_i64().expect("olay");
    read(&app, &owner, json!({ "event_ids": [alarm_id] })).await;
    assert_eq!(
        items(&feed(&app, &owner, "?unread_only=true").await).len(),
        2
    );

    // Hepsini okundu yap; sonra gelen olay yeniden okunmamış.
    let (status, _) = read(&app, &owner, json!({ "all": true })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(unread(&app, &owner).await, 0);
    run(&app, &owner, &d, &d.garage, "disarm").await;
    wait_events(&app, &org, 4).await;
    assert_eq!(
        (unread(&app, &owner).await, unread(&app, &member).await),
        (1, 1)
    );

    // Geçersiz istekler.
    for (body, expected) in [
        (
            json!({ "all": true, "event_ids": [1] }),
            StatusCode::BAD_REQUEST,
        ),
        (json!({}), StatusCode::BAD_REQUEST),
        (
            json!({ "event_ids": (0..101).collect::<Vec<i64>>() }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "event_ids": [1], "organization_id": org }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "all": true, "organization_id": Uuid::new_v4() }),
            StatusCode::NOT_FOUND,
        ),
    ] {
        assert_eq!(read(&app, &owner, body.clone()).await.0, expected, "{body}");
    }
    let (status, _) = app.get("/v1/notifications?limit=0", &owner).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "../../migrations")]
async fn inbox_follows_join_time_membership_and_mfa(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let d = demo(&app, &owner, &org).await;
    run(&app, &owner, &d, &d.home, "arm_away").await;
    wait_events(&app, &org, 1).await;

    // Katılmadan önceki olay görünür ama okunmuş sayılır.
    let (member, member_id) = join(&app, &owner, &org).await;
    grant(&app, &owner, &d, &member_id, None).await;
    let body = feed(&app, &member, "").await;
    assert_eq!(items(&body).len(), 1);
    assert_eq!(items(&body)[0]["read"], true);
    assert_eq!(unread(&app, &member).await, 0);
    run(&app, &owner, &d, &d.home, "disarm").await;
    wait_events(&app, &org, 2).await;
    assert_eq!(unread(&app, &member).await, 1);
    read(
        &app,
        &member,
        json!({ "all": true, "organization_id": org }),
    )
    .await;
    assert_eq!(unread(&app, &member).await, 0);

    // Üyelik silinince bildirimler ve okundu bilgisi de gider.
    let (status, _) = app
        .delete(
            &format!("/v1/organizations/{org}/members/{member_id}"),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let body = feed(&app, &member, "").await;
    assert!(
        items(&body)
            .iter()
            .all(|n| n["organization_id"] != org.as_str())
    );
    let (rows,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM notification_reads WHERE user_id = $1::uuid")
            .bind(&member_id)
            .fetch_one(&app.admin)
            .await
            .expect("sorgu");
    assert_eq!(rows, 0);

    // İşletme personeli: ikinci adım tamamlanmadan bildirimler gösterilmez, kilitli denir.
    sqlx::query("UPDATE organizations SET kind = 'business' WHERE id = $1::uuid")
        .bind(&org)
        .execute(&app.admin)
        .await
        .expect("tür");
    let body = feed(&app, &owner, "").await;
    assert!(items(&body).is_empty());
    assert_eq!(body["locked"][0]["organization_id"], org.as_str());
    assert_eq!(body["locked"][0]["reason"], "mfa_required");
    let (_, counts) = app.get("/v1/notifications/unread-count", &owner).await;
    assert_eq!(counts["locked"][0]["reason"], "mfa_required");
    app.enable_mfa(&owner).await;
    assert_eq!(items(&feed(&app, &owner, "").await).len(), 2);
}
