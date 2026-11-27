//! AI olay özeti entegrasyon testleri: gerçek PostgreSQL ve sahte bir AI servisi (yerel HTTP).
#![cfg(feature = "db-tests")]

mod common;

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::{State, connect_info::MockConnectInfo},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    routing::post,
};
use common::*;
use serde_json::{Value, json};
use shedu_api::ai::{AiClient, FLAG, USER_DAILY_MICROUSD};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

const TOKEN: &str = "ai-service-token-0123456789abcdefghij";
const MEMBER: &str = "+905557776655";
const OUTSIDER: &str = "+905553332211";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Answer,
    /// Model reddetti; harcama bildirilir.
    Refuse,
    /// Model çağrılamadı; harcama yok.
    Fail,
    /// Servis beklenmedik biçimde düştü (JSON olmayan 500): harcama bilinmiyor.
    Crash,
}

/// (Authorization başlığı, istek gövdesi)
type Seen = (Option<String>, Value);

/// Sahte AI servisi: gelen istekleri saklar, kipine göre yanıt verir.
#[derive(Clone)]
struct FakeAi {
    requests: Arc<Mutex<Vec<Seen>>>,
    mode: Arc<Mutex<Mode>>,
}

impl FakeAi {
    fn requests(&self) -> Vec<Seen> {
        self.requests.lock().expect("kilit").clone()
    }

    fn set(&self, mode: Mode) {
        *self.mode.lock().expect("kilit") = mode;
    }
}

async fn fake_summary(
    State(fake): State<FakeAi>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let auth = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    fake.requests.lock().expect("kilit").push((auth, body));
    let mode = *fake.mode.lock().expect("kilit");
    match mode {
        // Sayılar ve dikkat işareti bilerek yanlış: API bunları kullanmamalı.
        Mode::Answer => (
            StatusCode::OK,
            Json(json!({
                "summary": "  Garajda   bir alarm oldu.\n",
                "highlights": ["Garaj alarmı", "   ", "Bağlantı koptu"],
                "needs_attention": false,
                "stats": { "alarms": 0 },
                "generated": true,
                "model": "claude-opus-5-5",
                "input_tokens": 321,
                "output_tokens": 45,
                "cost_microusd": 2184
            })),
        )
            .into_response(),
        Mode::Refuse => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "detail": "ai_refused",
                "usage": {
                    "model": "claude-opus-5-5",
                    "input_tokens": 300,
                    "output_tokens": 0,
                    "cost_microusd": 1200
                }
            })),
        )
            .into_response(),
        Mode::Fail => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "detail": "ai_unavailable", "usage": null })),
        )
            .into_response(),
        Mode::Crash => (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response(),
    }
}

async fn start_fake() -> (String, FakeAi) {
    let fake = FakeAi {
        requests: Arc::default(),
        mode: Arc::new(Mutex::new(Mode::Answer)),
    };
    let router = Router::new()
        .route("/v1/summaries/events", post(fake_summary))
        .with_state(fake.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("dinleyici");
    let addr = listener.local_addr().expect("adres");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (format!("http://{addr}"), fake)
}

/// Uygulamayı verilen AI servisiyle yeniden kurar.
fn use_ai(app: &mut TestApp, url: &str) {
    use_ai_with(app, AiClient::new(url, TOKEN).expect("istemci"));
}

fn use_ai_with(app: &mut TestApp, client: AiClient) {
    let mut state = app.state.clone();
    state.ai = Some(Arc::new(client));
    app.router = shedu_api::router(state.clone())
        .layer(MockConnectInfo(SocketAddr::from(([203, 0, 113, 7], 4000))));
    app.state = state;
}

async fn enable_flag(app: &TestApp) {
    sqlx::query(
        "INSERT INTO feature_flags (key, description, enabled, rollout_percent)
         VALUES ($1, 'AI olay özeti', true, 100)",
    )
    .bind(FLAG)
    .execute(&app.admin)
    .await
    .expect("bayrak");
}

/// Demo paneli kurar; (panel kimliği, garaj bölümü kimliği).
async fn demo(app: &TestApp, access: &str, org: &str) -> (String, String) {
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
    let garage = panel["partitions"]
        .as_array()
        .and_then(|list| list.iter().find(|p| p["number"] == 2))
        .map(|p| s(p, "id"))
        .expect("garaj");
    (s(panel, "id"), garage)
}

#[allow(clippy::too_many_arguments)]
async fn insert_event(
    app: &TestApp,
    org: &str,
    panel: &str,
    partition: Option<i16>,
    zone: Option<i16>,
    kind: &str,
    alarm_kind: Option<&str>,
    minutes_ago: i32,
) {
    let arm_mode = (kind == "armed").then_some("away");
    let priority = if kind == "alarm" { "critical" } else { "info" };
    sqlx::query(
        "INSERT INTO panel_events (organization_id, panel_id, partition_number, zone_number, kind,
                                   alarm_kind, arm_mode, priority, occurred_at, source)
         VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8,
                 now() - make_interval(mins => $9), 'simulator')",
    )
    .bind(org)
    .bind(panel)
    .bind(partition)
    .bind(zone)
    .bind(kind)
    .bind(alarm_kind)
    .bind(arm_mode)
    .bind(priority)
    .bind(minutes_ago)
    .execute(&app.admin)
    .await
    .expect("olay");
}

async fn add_member(app: &TestApp, org: &str, user: &str, panel: &str, partition: Option<&str>) {
    sqlx::query(
        "INSERT INTO memberships (user_id, organization_id, role) VALUES ($1::uuid, $2::uuid, 'member')",
    )
    .bind(user)
    .bind(org)
    .execute(&app.admin)
    .await
    .expect("üyelik");
    sqlx::query(
        "INSERT INTO access_grants (organization_id, user_id, panel_id, partition_id, can_arm, can_disarm,
                                    can_view_events, always_open)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, false, false, true, true)",
    )
    .bind(org)
    .bind(user)
    .bind(panel)
    .bind(partition)
    .execute(&app.admin)
    .await
    .expect("yetki");
}

fn summary_path(org: &str, panel: &str) -> String {
    format!("/v1/organizations/{org}/panels/{panel}/ai-summary")
}

/// Defterdeki harcamalar: (sonuç, mikro-dolar), eskiden yeniye.
async fn ledger(app: &TestApp, org: &str) -> Vec<(String, i64)> {
    sqlx::query_as(
        "SELECT outcome, cost_microusd FROM ai_usage WHERE organization_id = $1::uuid ORDER BY id",
    )
    .bind(org)
    .fetch_all(&app.admin)
    .await
    .expect("defter")
}

async fn audit_actions(app: &TestApp, org: &str) -> Vec<(String, Value)> {
    sqlx::query_as(
        "SELECT action, details FROM audit_log
          WHERE organization_id = $1::uuid AND action LIKE 'ai.%' ORDER BY id",
    )
    .bind(org)
    .fetch_all(&app.admin)
    .await
    .expect("denetim")
}

#[sqlx::test(migrations = "../../migrations")]
async fn summary_needs_flag_service_and_view_permission(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let mut app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let (panel, _) = demo(&app, &owner, &org).await;
    let path = summary_path(&org, &panel);

    // AI servisi yapılandırılmamış ve bayrak tanımsız: kapalı.
    let (status, body) = app.post_auth(&path, json!({}), &owner).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("feature_disabled"))
    );
    enable_flag(&app).await;
    let (status, body) = app.post_auth(&path, json!({}), &owner).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("ai_unavailable"))
    );

    let (url, fake) = start_fake().await;
    use_ai(&mut app, &url);
    let (outsider, _, _) = app.user(OUTSIDER).await;
    assert_eq!(
        app.post_auth(&path, json!({}), &outsider).await.0,
        StatusCode::NOT_FOUND
    );
    for bad in [json!({ "hours": 0 }), json!({ "hours": 169 })] {
        let (status, body) = app.post_auth(&path, bad, &owner).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_hours"))
        );
    }
    assert_eq!(
        app.post_auth(&path, json!({ "prompt": "x" }), &owner)
            .await
            .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert!(fake.requests().is_empty(), "reddedilen istek AI'ya gitmez");

    let (status, body) = app.post_auth(&path, json!({ "hours": 6 }), &owner).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(fake.requests().len(), 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn summary_sends_only_visible_minimal_data(_: PgPoolOptions, connect: PgConnectOptions) {
    let mut app = app(connect).await;
    let (url, fake) = start_fake().await;
    use_ai(&mut app, &url);
    enable_flag(&app).await;
    let (owner, owner_id, org) = app.user(PHONE).await;
    let (panel, _garage) = demo(&app, &owner, &org).await;
    let (member, member_id, _) = app.user(MEMBER).await;
    let (_, panels) = app
        .get(&format!("/v1/organizations/{org}/panels"), &owner)
        .await;
    let home = panels[0]["partitions"]
        .as_array()
        .and_then(|list| list.iter().find(|p| p["number"] == 1))
        .map(|p| s(p, "id"))
        .expect("ev");
    add_member(&app, &org, &member_id, &panel, Some(&home)).await;

    insert_event(&app, &org, &panel, Some(1), None, "armed", None, 120).await;
    insert_event(
        &app,
        &org,
        &panel,
        Some(2),
        Some(5),
        "alarm",
        Some("intrusion"),
        90,
    )
    .await;
    insert_event(&app, &org, &panel, Some(1), None, "disarmed", None, 60).await;
    insert_event(&app, &org, &panel, None, None, "disconnected", None, 0).await;
    // Dönem dışı: gönderilmez, sayılmaz.
    insert_event(
        &app,
        &org,
        &panel,
        Some(1),
        None,
        "alarm",
        Some("fire"),
        48 * 60,
    )
    .await;

    // Sahip: bütün bölümler. Sayılar API'de hesaplanır; AI'nın yanlış sayıları kullanılmaz.
    let (status, body) = app
        .post_auth(&summary_path(&org, &panel), json!({}), &owner)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["summary"], "Garajda bir alarm oldu.");
    assert_eq!(
        body["highlights"],
        json!(["Garaj alarmı", "Bağlantı koptu"])
    );
    assert_eq!(body["ai_generated"], true);
    assert_eq!(body["needs_attention"], true);
    assert_eq!(body["stats"]["alarms"], 1);
    assert_eq!(body["stats"]["total"], 4);
    assert_eq!(body["truncated"], false);

    let (auth, sent) = fake.requests().pop().expect("istek");
    assert_eq!(auth.as_deref(), Some(format!("Bearer {TOKEN}").as_str()));
    let text = sent.to_string();
    for secret in [
        org.as_str(),
        owner_id.as_str(),
        member_id.as_str(),
        panel.as_str(),
        PHONE,
        MEMBER,
    ] {
        assert!(!text.contains(secret), "AI'ya kimlik gitmemeli: {secret}");
    }
    let keys: Vec<&str> = sent
        .as_object()
        .expect("nesne")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "events",
            "panel_name",
            "period_end",
            "period_start",
            "time_zone",
            "truncated"
        ]
    );
    assert_eq!(sent["time_zone"], "Europe/Istanbul");
    let events = sent["events"].as_array().expect("olaylar");
    assert_eq!(events.len(), 4);
    let alarm = events.iter().find(|e| e["kind"] == "alarm").expect("alarm");
    assert_eq!(alarm["partition"], "Garaj");
    assert_eq!(alarm["zone"], "Garaj kapısı");

    // Yalnızca "Ev" bölümünü gören üye: garaj alarmı ne AI'ya gider ne sayılır.
    let (status, body) = app
        .post_auth(&summary_path(&org, &panel), json!({}), &member)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["stats"]["alarms"], 0);
    assert_eq!(body["stats"]["total"], 3);
    // Bağlantı hâlâ kopuk: dikkat gerekir.
    assert_eq!(body["needs_attention"], true);
    let (_, sent) = fake.requests().pop().expect("istek");
    let text = sent.to_string();
    assert!(
        !text.contains("Garaj"),
        "görünmeyen bölüm AI'ya gitmemeli: {text}"
    );
    assert_eq!(sent["events"].as_array().map(Vec::len), Some(3));

    // Denetim kaydı: sayılar ve token kullanımı var, metin yok.
    let audits = audit_actions(&app, &org).await;
    assert_eq!(audits.len(), 2);
    let (action, details) = &audits[0];
    assert_eq!(action, "ai.summary_generated");
    assert_eq!(details["input_tokens"], 321);
    assert_eq!(details["event_count"], 4);
    assert_eq!(details["cost_microusd"], 2184);
    assert!(!details.to_string().contains("Garajda"));
    assert_eq!(
        ledger(&app, &org).await,
        [("success".to_owned(), 2184), ("success".to_owned(), 2184)]
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn summary_failures_budget_and_truncation(_: PgPoolOptions, connect: PgConnectOptions) {
    let mut app = app(connect).await;
    let (url, fake) = start_fake().await;
    use_ai(&mut app, &url);
    enable_flag(&app).await;
    let (owner, _, org) = app.user(PHONE).await;
    let (panel, _) = demo(&app, &owner, &org).await;
    let path = summary_path(&org, &panel);

    // Listeden fazla olay: AI'ya en yeni 500 gider, sayılar yine kesin.
    sqlx::query(
        "INSERT INTO panel_events (organization_id, panel_id, partition_number, kind, arm_mode, priority,
                                   occurred_at, source)
         SELECT $1::uuid, $2::uuid, 1, 'armed', 'away', 'info', now() - make_interval(secs => g), 'simulator'
           FROM generate_series(1, 520) g",
    )
    .bind(&org)
    .bind(&panel)
    .execute(&app.admin)
    .await
    .expect("olaylar");
    let (status, body) = app.post_auth(&path, json!({}), &owner).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["truncated"], true);
    assert_eq!(body["stats"]["armed"], 520);
    let (_, sent) = fake.requests().pop().expect("istek");
    assert_eq!(sent["events"].as_array().map(Vec::len), Some(500));
    assert_eq!(sent["truncated"], true);

    // Model reddi ve kesinti sabit kodlara dönüşür, denetime yazılır.
    fake.set(Mode::Refuse);
    let (status, body) = app.post_auth(&path, json!({}), &owner).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("ai_refused"))
    );
    for mode in [Mode::Fail, Mode::Crash] {
        fake.set(mode);
        let (status, body) = app.post_auth(&path, json!({}), &owner).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::SERVICE_UNAVAILABLE, Some("ai_unavailable"))
        );
    }
    let audits = audit_actions(&app, &org).await;
    let failed: Vec<&str> = audits
        .iter()
        .filter(|(action, _)| action == "ai.summary_failed")
        .map(|(_, d)| d["reason"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(failed, ["ai_refused", "ai_unavailable", "ai_unavailable"]);
    // Harcama sonuçtan bağımsız yazılır: ret bildirilen tutarla, model çağrılamadıysa hiç,
    // servis düştüyse en kötü durum tahminiyle.
    let spent = ledger(&app, &org).await;
    let outcomes: Vec<&str> = spent.iter().map(|(o, _)| o.as_str()).collect();
    assert_eq!(outcomes, ["success", "refused", "unknown"]);
    assert_eq!(spent[1].1, 1200);
    // En az: 4096 çıktı token'ı en pahalı katmandan (50 µ$/token).
    assert!(
        spent[2].1 >= 204_800,
        "tahmin temkinli olmalı: {}",
        spent[2].1
    );

    // Kullanıcı başına saatte 10 özet: 4 kullanıldı, 6 daha geçer, 11. reddedilir ve AI'ya gitmez.
    fake.set(Mode::Answer);
    for _ in 0..6 {
        assert_eq!(
            app.post_auth(&path, json!({}), &owner).await.0,
            StatusCode::OK
        );
    }
    let before = fake.requests().len();
    let (status, _) = app.post_auth(&path, json!({}), &owner).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(fake.requests().len(), before);

    // Servise bağlanılamıyor: istek gitmedi, harcama yazılmaz; kısa sürede 503.
    use_ai(&mut app, "http://127.0.0.1:9");
    let (other, _, other_org) = app.user(MEMBER).await;
    let (other_panel, _) = demo(&app, &other, &other_org).await;
    let (status, body) = app
        .post_auth(&summary_path(&other_org, &other_panel), json!({}), &other)
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("ai_unavailable"))
    );
    assert!(ledger(&app, &other_org).await.is_empty());
}

#[sqlx::test(migrations = "../../migrations")]
async fn spending_limits_stop_calls_before_they_are_made(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let mut app = app(connect).await;
    let (url, fake) = start_fake().await;
    use_ai(&mut app, &url);
    enable_flag(&app).await;
    let (owner, owner_id, org) = app.user(PHONE).await;
    let (panel, _) = demo(&app, &owner, &org).await;
    let path = summary_path(&org, &panel);

    // Kullanıcının son 24 saatteki harcaması sınırda (başka bir organizasyonda yapılmış olsa da).
    sqlx::query(
        "INSERT INTO ai_usage (organization_id, user_id, feature, input_tokens, output_tokens,
                               cost_microusd, outcome)
         VALUES (gen_random_uuid(), $1::uuid, 'event_summary', 0, 0, $2, 'success')",
    )
    .bind(&owner_id)
    .bind(USER_DAILY_MICROUSD)
    .execute(&app.admin)
    .await
    .expect("harcama");
    let (status, _) = app.post_auth(&path, json!({}), &owner).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(fake.requests().is_empty(), "sınır doluyken model çağrılmaz");

    // 24 saatten eski harcama sayılmaz; ama bütün sistemin sınırı doluysa yine çağrılmaz.
    let (other, _, other_org) = app.user(MEMBER).await;
    let (other_panel, _) = demo(&app, &other, &other_org).await;
    let other_path = summary_path(&other_org, &other_panel);
    assert_eq!(
        app.post_auth(&other_path, json!({}), &other).await.0,
        StatusCode::OK
    );
    assert_eq!(fake.requests().len(), 1);
    use_ai_with(
        &mut app,
        AiClient::new(&url, TOKEN)
            .expect("istemci")
            .with_global_budget(USER_DAILY_MICROUSD),
    );
    assert_eq!(
        app.post_auth(&other_path, json!({}), &other).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(fake.requests().len(), 1);
}
