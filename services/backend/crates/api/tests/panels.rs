//! Panel, komut ve olay akışı entegrasyon testleri (gerçek PostgreSQL, uygulama rolüyle).
#![cfg(feature = "db-tests")]

mod common;

use std::{net::SocketAddr, time::Duration};

use axum::http::StatusCode;
use common::*;
use futures_util::StreamExt;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest, http::HeaderValue};
use uuid::Uuid;

const OTHER_PHONE: &str = "+905557776655";

fn key() -> String {
    format!("test-{}", Uuid::new_v4().simple())
}

/// Demo panel oluşturur; (panel kimliği, Ev bölümü, Garaj bölümü) döner.
async fn demo(app: &TestApp, access: &str, org: &str) -> (String, String, String) {
    let (status, body) = app
        .post_auth(
            &format!("/v1/organizations/{org}/demo-panel"),
            json!({}),
            access,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
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
    (s(panel, "id"), partition(1), partition(2))
}

#[allow(clippy::too_many_arguments)]
async fn command(
    app: &TestApp,
    access: &str,
    org: &str,
    panel: &str,
    partition: &str,
    kind: &str,
    zones: Option<Vec<u16>>,
    idempotency_key: &str,
) -> (StatusCode, Value) {
    let mut body =
        json!({ "partition_id": partition, "kind": kind, "idempotency_key": idempotency_key });
    if let Some(zones) = zones {
        body["zones"] = json!(zones);
    }
    app.post_auth(
        &format!("/v1/organizations/{org}/panels/{panel}/commands"),
        body,
        access,
    )
    .await
}

async fn wait_status(app: &TestApp, access: &str, org: &str, id: &str, expected: &str) {
    for _ in 0..100 {
        let (_, body) = app
            .get(&format!("/v1/organizations/{org}/commands/{id}"), access)
            .await;
        if body["status"] == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("komut {expected} olmadı");
}

async fn add_member(app: &TestApp, org: &str, user: &str, role: &str) {
    sqlx::query(
        "INSERT INTO memberships (user_id, organization_id, role) VALUES ($1::uuid, $2::uuid, $3)",
    )
    .bind(user)
    .bind(org)
    .bind(role)
    .execute(&app.admin)
    .await
    .expect("üyelik");
}

#[allow(clippy::too_many_arguments)]
async fn grant(
    app: &TestApp,
    org: &str,
    user: &str,
    panel: &str,
    partition: Option<&str>,
    arm: bool,
    disarm: bool,
    always_open: bool,
) -> String {
    let (id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO access_grants (organization_id, user_id, panel_id, partition_id, can_arm, can_disarm, can_view_events, always_open)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, true, $7) RETURNING id",
    )
    .bind(org)
    .bind(user)
    .bind(panel)
    .bind(partition)
    .bind(arm)
    .bind(disarm)
    .bind(always_open)
    .fetch_one(&app.admin)
    .await
    .expect("yetki");
    id.to_string()
}

// ---------------------------------------------------------------------------------------------
// Paneller
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn demo_panel_is_created_once_and_listed(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (access, _, org) = app.user(PHONE).await;
    let (panel, _, _) = demo(&app, &access, &org).await;

    let (status, body) = app
        .post_auth(
            &format!("/v1/organizations/{org}/demo-panel"),
            json!({}),
            &access,
        )
        .await;
    assert_eq!(
        (status, s(&body, "error")),
        (StatusCode::CONFLICT, "demo_panel_exists".into())
    );

    let (status, detail) = app
        .get(&format!("/v1/organizations/{org}/panels/{panel}"), &access)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["simulated"], true);
    assert_eq!(detail["connectivity"], "online");
    assert_eq!(detail["partitions"].as_array().map(Vec::len), Some(2));
    assert_eq!(detail["zones"].as_array().map(Vec::len), Some(5));
    assert!(detail["outputs"].is_array(), "yönetici çıkışları görür");
}

#[sqlx::test(migrations = "../../migrations")]
async fn outsider_cannot_see_or_control_another_organizations_panel(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let (panel, home, _) = demo(&app, &owner, &org).await;
    let (outsider, _, outsider_org) = app.user(OTHER_PHONE).await;

    for path in [
        format!("/v1/organizations/{org}/panels"),
        format!("/v1/organizations/{org}/panels/{panel}"),
    ] {
        let (status, _) = app.get(&path, &outsider).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
    let (status, _) = command(&app, &outsider, &org, &panel, &home, "disarm", None, &key()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Kendi organizasyonunun yoluyla başkasının paneli de görünmez (RLS).
    let (status, _) = app
        .get(
            &format!("/v1/organizations/{outsider_org}/panels/{panel}"),
            &outsider,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = command(
        &app,
        &outsider,
        &outsider_org,
        &panel,
        &home,
        "arm_away",
        None,
        &key(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------------------------
// Komutlar
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn arm_command_completes_on_demo_panel_and_is_audited(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (access, _, org) = app.user(PHONE).await;
    let (panel, home, _) = demo(&app, &access, &org).await;

    let (status, body) =
        command(&app, &access, &org, &panel, &home, "arm_away", None, &key()).await;
    assert_eq!(
        (status, s(&body, "status")),
        (StatusCode::ACCEPTED, "accepted".into())
    );
    wait_status(&app, &access, &org, &s(&body, "id"), "succeeded").await;

    let (_, detail) = app
        .get(&format!("/v1/organizations/{org}/panels/{panel}"), &access)
        .await;
    let home_state = detail["partitions"]
        .as_array()
        .and_then(|p| p.iter().find(|p| p["id"] == home.as_str()))
        .map(|p| s(p, "state"));
    assert_eq!(home_state.as_deref(), Some("armed_away"));

    let actions: Vec<(String,)> =
        sqlx::query_as("SELECT action FROM audit_log WHERE action LIKE 'command.%' ORDER BY id")
            .fetch_all(&app.admin)
            .await
            .expect("denetim");
    let actions: Vec<&str> = actions.iter().map(|(a,)| a.as_str()).collect();
    assert_eq!(actions, ["command.arm_away", "command.completed"]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn idempotency_key_replays_same_command_and_rejects_a_different_one(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (access, _, org) = app.user(PHONE).await;
    let (panel, home, _) = demo(&app, &access, &org).await;
    let k = key();

    let (status, first) = command(&app, &access, &org, &panel, &home, "arm_stay", None, &k).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, again) = command(&app, &access, &org, &panel, &home, "arm_stay", None, &k).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        again["id"], first["id"],
        "aynı anahtar aynı komutu döndürmeli"
    );

    let (status, body) = command(&app, &access, &org, &panel, &home, "disarm", None, &k).await;
    assert_eq!(
        (status, s(&body, "error")),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            "idempotency_key_reused".into()
        )
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn second_command_is_rejected_while_one_is_in_flight(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app_with(connect, Duration::from_secs(5)).await;
    let (access, _, org) = app.user(PHONE).await;
    let (panel, home, _) = demo(&app, &access, &org).await;

    let (status, _) = command(&app, &access, &org, &panel, &home, "arm_away", None, &key()).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, body) = command(
        &app,
        &access,
        &org,
        &panel,
        &home,
        "arm_night",
        None,
        &key(),
    )
    .await;
    assert_eq!(
        (status, s(&body, "error")),
        (StatusCode::CONFLICT, "command_in_progress".into())
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn domain_rules_reject_and_the_rejection_is_recorded(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (access, _, org) = app.user(PHONE).await;
    let (panel, home, _) = demo(&app, &access, &org).await;

    let (status, body) = command(&app, &access, &org, &panel, &home, "disarm", None, &key()).await;
    assert_eq!(
        (status, s(&body, "error")),
        (StatusCode::CONFLICT, "already_in_state".into())
    );
    let (reason,): (Option<String>,) =
        sqlx::query_as("SELECT rejection_reason FROM commands WHERE status = 'rejected'")
            .fetch_one(&app.admin)
            .await
            .expect("kayıt");
    assert_eq!(reason.as_deref(), Some("already_in_state"));

    sqlx::query("UPDATE panels SET connectivity = 'offline' WHERE id = $1::uuid")
        .bind(&panel)
        .execute(&app.admin)
        .await
        .expect("güncelleme");
    let (status, body) =
        command(&app, &access, &org, &panel, &home, "arm_away", None, &key()).await;
    assert_eq!(
        (status, s(&body, "error")),
        (StatusCode::CONFLICT, "panel_offline".into())
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn bypass_only_accepts_zones_of_the_partition(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (access, _, org) = app.user(PHONE).await;
    let (panel, home, _) = demo(&app, &access, &org).await;

    // Zon 5 garaj bölümüne ait.
    let (status, body) = command(
        &app,
        &access,
        &org,
        &panel,
        &home,
        "bypass_zones",
        Some(vec![1, 5]),
        &key(),
    )
    .await;
    assert_eq!(
        (status, s(&body, "error")),
        (StatusCode::CONFLICT, "zones_not_in_partition".into())
    );
    let (status, body) = command(
        &app,
        &access,
        &org,
        &panel,
        &home,
        "bypass_zones",
        None,
        &key(),
    )
    .await;
    assert_eq!(
        (status, s(&body, "error")),
        (StatusCode::BAD_REQUEST, "no_zones_requested".into())
    );
    let (status, body) = command(
        &app,
        &access,
        &org,
        &panel,
        &home,
        "arm_away",
        Some(vec![1]),
        &key(),
    )
    .await;
    assert_eq!(
        (status, s(&body, "error")),
        (StatusCode::BAD_REQUEST, "zones_not_allowed".into())
    );

    let (status, body) = command(
        &app,
        &access,
        &org,
        &panel,
        &home,
        "bypass_zones",
        Some(vec![1]),
        &key(),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    wait_status(&app, &access, &org, &s(&body, "id"), "succeeded").await;
    let (_, detail) = app
        .get(&format!("/v1/organizations/{org}/panels/{panel}"), &access)
        .await;
    let zone1 = detail["zones"]
        .as_array()
        .and_then(|z| z.iter().find(|z| z["number"] == 1))
        .cloned()
        .expect("zon");
    assert_eq!(zone1["bypassed"], true);
}

// ---------------------------------------------------------------------------------------------
// Üye yetkileri ve erişim penceresi
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn member_permissions_and_access_window_are_enforced(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let (panel, home, garage) = demo(&app, &owner, &org).await;
    let (member, member_id, _) = app.user(OTHER_PHONE).await;
    add_member(&app, &org, &member_id, "member").await;

    // Yetki kaydı yok: panel görünmez, komut verilemez, demo panel oluşturulamaz.
    let (_, panels) = app
        .get(&format!("/v1/organizations/{org}/panels"), &member)
        .await;
    assert_eq!(panels.as_array().map(Vec::len), Some(0));
    let (status, _) = command(&app, &member, &org, &panel, &home, "arm_away", None, &key()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = app
        .post_auth(
            &format!("/v1/organizations/{org}/demo-panel"),
            json!({}),
            &member,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Yalnızca garaj bölümü, kurma yetkisi var, kapatma yok, her zaman açık.
    let grant_id = grant(
        &app,
        &org,
        &member_id,
        &panel,
        Some(&garage),
        true,
        false,
        true,
    )
    .await;
    let (_, detail) = app
        .get(&format!("/v1/organizations/{org}/panels/{panel}"), &member)
        .await;
    assert_eq!(
        detail["partitions"].as_array().map(Vec::len),
        Some(1),
        "yalnızca garaj görünmeli"
    );
    assert_eq!(
        detail["zones"].as_array().map(Vec::len),
        Some(1),
        "yalnızca garaj zonu görünmeli"
    );
    assert!(detail.get("outputs").is_none(), "üye çıkışları görmez");

    let (status, body) = command(
        &app,
        &member,
        &org,
        &panel,
        &garage,
        "arm_away",
        None,
        &key(),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    wait_status(&app, &member, &org, &s(&body, "id"), "succeeded").await;
    let (status, body) =
        command(&app, &member, &org, &panel, &garage, "disarm", None, &key()).await;
    assert_eq!(
        (status, s(&body, "error")),
        (StatusCode::FORBIDDEN, "not_permitted".into())
    );
    // Yetkisi olmayan bölüm: varlığı da belli olmaz.
    let (status, _) = command(&app, &member, &org, &panel, &home, "arm_away", None, &key()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Pencere kapalı (her zaman açık değil ve hiç pencere yok): görebilir ama kuramaz.
    sqlx::query("UPDATE access_grants SET always_open = false WHERE id = $1::uuid")
        .bind(&grant_id)
        .execute(&app.admin)
        .await
        .expect("güncelleme");
    let (status, _) = command(&app, &member, &org, &panel, &garage, "disarm", None, &key()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = app
        .get(&format!("/v1/organizations/{org}/panels/{panel}"), &member)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Üye, sahibinin komutunu göremez.
    let (_, owners) = command(&app, &owner, &org, &panel, &home, "arm_night", None, &key()).await;
    let (status, _) = app
        .get(
            &format!("/v1/organizations/{org}/commands/{}", s(&owners, "id")),
            &member,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------------------------
// WebSocket olay akışı
// ---------------------------------------------------------------------------------------------

async fn serve(app: &TestApp) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("dinleme");
    let addr = listener.local_addr().expect("adres");
    let router =
        shedu_api::router(app.state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, router).await.expect("sunucu") });
    app.state.start_event_listener();
    // Dinleyicinin LISTEN komutunu vermesi için kısa bir süre.
    tokio::time::sleep(Duration::from_millis(300)).await;
    addr
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn open(
    addr: SocketAddr,
    org: &str,
    access: Option<&str>,
    origin: Option<&str>,
) -> Result<Socket, u16> {
    let mut request = format!("ws://{addr}/v1/organizations/{org}/events")
        .into_client_request()
        .expect("istek");
    if let Some(token) = access {
        request.headers_mut().insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).expect("başlık"),
        );
    }
    if let Some(origin) = origin {
        request
            .headers_mut()
            .insert("origin", HeaderValue::from_str(origin).expect("başlık"));
    }
    match tokio_tungstenite::connect_async(request).await {
        Ok((socket, _)) => Ok(socket),
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            Err(response.status().as_u16())
        }
        Err(error) => panic!("beklenmeyen hata: {error}"),
    }
}

/// `deadline` boyunca gelen JSON mesajları toplar; `stop` doğru dönünce erken biter.
async fn collect(
    socket: &mut Socket,
    deadline: Duration,
    stop: impl Fn(&[Value]) -> bool,
) -> (Vec<Value>, bool) {
    let mut messages = Vec::new();
    let mut closed = false;
    let _ = tokio::time::timeout(deadline, async {
        while let Some(message) = socket.next().await {
            match message {
                Ok(Message::Text(text)) => {
                    messages.push(serde_json::from_str(text.as_str()).unwrap_or(Value::Null));
                    if stop(&messages) {
                        break;
                    }
                }
                Ok(Message::Close(_)) | Err(_) => {
                    closed = true;
                    break;
                }
                Ok(_) => {}
            }
        }
    })
    .await;
    (messages, closed)
}

#[sqlx::test(migrations = "../../migrations")]
async fn websocket_streams_command_and_partition_updates(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (access, _, org) = app.user(PHONE).await;
    let (panel, home, _) = demo(&app, &access, &org).await;
    let addr = serve(&app).await;
    let mut socket = open(addr, &org, Some(&access), None)
        .await
        .expect("bağlantı");

    command(&app, &access, &org, &panel, &home, "arm_away", None, &key()).await;
    let (messages, _) = collect(&mut socket, Duration::from_secs(5), |m| {
        m.iter()
            .any(|v| v["type"] == "command" && v["status"] == "succeeded")
            && m.iter()
                .any(|v| v["type"] == "partition" && v["state"] == "armed_away")
            && m.iter().any(|v| v["type"] == "panel_event")
    })
    .await;
    assert!(
        messages
            .iter()
            .any(|v| v["type"] == "command" && v["status"] == "accepted"),
        "{messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|v| v["type"] == "command" && v["status"] == "succeeded"),
        "{messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|v| v["type"] == "partition" && v["state"] == "armed_away"),
        "{messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|v| v["type"] == "panel_event" && v["kind"] == "armed"),
        "{messages:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn websocket_requires_token_and_rejects_foreign_origin(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (access, _, org) = app.user(PHONE).await;
    let (outsider, _, _) = app.user(OTHER_PHONE).await;
    let addr = serve(&app).await;

    assert_eq!(open(addr, &org, None, None).await.err(), Some(401));
    assert_eq!(
        open(addr, &org, Some(&access), Some("https://kotu-site.example"))
            .await
            .err(),
        Some(403)
    );
    assert_eq!(
        open(addr, &org, Some(&outsider), None).await.err(),
        Some(404),
        "üye olmayan bağlanamaz"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn websocket_does_not_leak_other_organizations_events(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let (panel, home, _) = demo(&app, &owner, &org).await;
    let (outsider, _, outsider_org) = app.user(OTHER_PHONE).await;
    let addr = serve(&app).await;
    let mut socket = open(addr, &outsider_org, Some(&outsider), None)
        .await
        .expect("bağlantı");

    command(&app, &owner, &org, &panel, &home, "arm_away", None, &key()).await;
    let (messages, _) = collect(&mut socket, Duration::from_secs(2), |_| false).await;
    assert!(
        messages.is_empty(),
        "başka organizasyonun olayı gelmemeli: {messages:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn websocket_is_closed_after_logout(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let (panel, home, garage) = demo(&app, &owner, &org).await;
    let (member, member_id, _) = app.user(OTHER_PHONE).await;
    add_member(&app, &org, &member_id, "member").await;
    grant(
        &app,
        &org,
        &member_id,
        &panel,
        Some(&garage),
        true,
        true,
        true,
    )
    .await;
    let addr = serve(&app).await;
    let mut socket = open(addr, &org, Some(&owner), None)
        .await
        .expect("bağlantı");

    let (status, _) = app.post_auth("/v1/auth/logout", json!({}), &owner).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // Başka bir kullanıcının komutu olay üretir; sahibin bağlantısı artık veri almamalı ve kapanmalı.
    command(
        &app,
        &member,
        &org,
        &panel,
        &garage,
        "arm_away",
        None,
        &key(),
    )
    .await;
    let (messages, closed) = collect(&mut socket, Duration::from_secs(5), |_| false).await;
    assert!(
        messages.is_empty(),
        "çıkıştan sonra veri gelmemeli: {messages:?}"
    );
    assert!(closed, "bağlantı kapanmalı");
    let _ = home;
}
