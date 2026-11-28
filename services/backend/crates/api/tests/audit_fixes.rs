//! İkinci denetimin (27 Kasım 2026, Codex; S01–S20) ve doğrulama denetiminin (Y01–Y11) bulgularına
//! karşı regresyon testleri. Her test önce meşru işlemin çalıştığını, sonra açığın kapandığını
//! gösterir.
#![cfg(feature = "db-tests")]

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use serde_json::{Value, json};
use shedu_api::{
    admin::{self, Operator},
    db,
    error::ApiError,
    privacy, push, simulator,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use uuid::Uuid;

const OTHER: &str = "+905554443322";
const NEW_NUMBER: &str = "+905559990011";

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

async fn simulate(app: &TestApp, access: &str, d: &Demo, zone: i16) -> Value {
    let (status, body) = app
        .post_auth(
            &format!(
                "/v1/organizations/{}/panels/{}/simulate-alarm",
                d.org, d.panel
            ),
            json!({ "zone_number": zone }),
            access,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    body
}

fn event_id(body: &Value) -> i64 {
    body["event_id"].as_i64().expect("olay")
}

async fn delivery(app: &TestApp, event: i64) -> (String, i16) {
    sqlx::query_as("SELECT status, attempts FROM push_deliveries WHERE panel_event_id = $1")
        .bind(event)
        .fetch_one(&app.admin)
        .await
        .expect("teslim")
}

/// Zonu (numarasıyla) ikinci bölüme de bağlar: paylaşılan zon.
async fn share_zone(app: &TestApp, d: &Demo, zone: i16, partition: &str) {
    sqlx::query(
        "INSERT INTO zone_partitions (organization_id, panel_id, zone_id, partition_id)
         SELECT organization_id, panel_id, id, $3::uuid FROM zones
          WHERE panel_id = $1::uuid AND number = $2",
    )
    .bind(&d.panel)
    .bind(zone)
    .bind(partition)
    .execute(&app.admin)
    .await
    .expect("paylaşılan zon");
}

/// Kişiyi organizasyona üye yapar ve bir bölümde yetki verir.
async fn grant(app: &TestApp, d: &Demo, user: &str, partition: &str, bypass: bool) {
    sqlx::query(
        "INSERT INTO memberships (user_id, organization_id, role) VALUES ($1::uuid, $2::uuid, 'member')
         ON CONFLICT DO NOTHING",
    )
    .bind(user)
    .bind(&d.org)
    .execute(&app.admin)
    .await
    .expect("üyelik");
    sqlx::query(
        "INSERT INTO access_grants (organization_id, user_id, panel_id, partition_id, can_view_events,
                                    can_arm, can_disarm, can_bypass, always_open)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, true, true, true, $5, true)",
    )
    .bind(&d.org)
    .bind(user)
    .bind(&d.panel)
    .bind(partition)
    .bind(bypass)
    .execute(&app.admin)
    .await
    .expect("yetki");
}

async fn reset_code(app: &TestApp, phone: &str) -> String {
    let before = app.sms.messages_to(phone).len();
    let (status, _) = app
        .post("/v1/auth/password-reset/start", json!({ "phone": phone }))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    app.last_code(phone, before).await
}

async fn reset(app: &TestApp, phone: &str, code: &str, password: &str) -> (StatusCode, Value) {
    app.post(
        "/v1/auth/password-reset/complete",
        json!({ "phone": phone, "code": code, "new_password": password }),
    )
    .await
}

// ---------------------------------------------------------------------------------------------
// S01: alarm teslimi
// ---------------------------------------------------------------------------------------------

/// Sağlayıcı hatası teslimi kaybettirmez: iş yeniden denenir; süreç gönderim sırasında kesilirse
/// süre dolunca iş yeniden alınır; deneme hakkı bitince kalıcı hata olarak kapanır.
#[sqlx::test(migrations = "../../migrations")]
async fn push_retries_failures_and_recovers_lost_work(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let d = demo(&app, &owner, &org).await;
    set_token(&app, &owner, "tok-owner").await;
    let org_id: Uuid = org.parse().expect("uuid");

    // Geçici hata: gönderilmedi ama iş bekliyor.
    let first = event_id(&simulate(&app, &owner, &d, 3).await);
    app.push.fail_next(1);
    assert_eq!(
        push::dispatch(&app.state, org_id, first)
            .await
            .expect("dağıtım"),
        0
    );
    assert_eq!(delivery(&app, first).await, ("pending".to_owned(), 1));
    assert!(app.push.messages().is_empty());
    // Zamanı gelince tarama yeniden dener.
    sqlx::query("UPDATE push_deliveries SET next_attempt_at = now() WHERE panel_event_id = $1")
        .bind(first)
        .execute(&app.admin)
        .await
        .expect("güncelleme");
    push::sweep_pending(&app.state).await;
    assert_eq!(delivery(&app, first).await, ("sent".to_owned(), 2));
    let sent = app.push.messages();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].collapse_key, format!("shedu-event-{first}"));

    // Süreç gönderirken kesildi: iş alınmış ama sonucu yazılmamış. Süre dolunca yeniden alınır.
    let second = event_id(&simulate(&app, &owner, &d, 4).await);
    app.push.fail_next(1);
    push::dispatch(&app.state, org_id, second)
        .await
        .expect("dağıtım");
    sqlx::query(
        "UPDATE push_deliveries
            SET status = 'sending', lease_until = now() - interval '1 second',
                next_attempt_at = now() + interval '1 hour'
          WHERE panel_event_id = $1",
    )
    .bind(second)
    .execute(&app.admin)
    .await
    .expect("güncelleme");
    push::sweep_pending(&app.state).await;
    assert_eq!(delivery(&app, second).await.0, "sent");

    // Deneme hakkı biter: kalıcı hata, artık denenmez.
    let third = event_id(&simulate(&app, &owner, &d, 3).await);
    app.push.fail_next(10);
    push::dispatch(&app.state, org_id, third)
        .await
        .expect("dağıtım");
    sqlx::query(
        "UPDATE push_deliveries SET attempts = 5, next_attempt_at = now() WHERE panel_event_id = $1",
    )
    .bind(third)
    .execute(&app.admin)
    .await
    .expect("güncelleme");
    push::sweep_pending(&app.state).await;
    assert_eq!(delivery(&app, third).await, ("failed".to_owned(), 6));
    push::sweep_pending(&app.state).await;
    assert_eq!(delivery(&app, third).await, ("failed".to_owned(), 6));
    app.push.fail_next(0);
}

/// Sağlayıcının kalıcı reddi (bozuk yük, yanlış yapılandırma, sağlayıcısı olmayan platform)
/// yeniden denenmez ve cihazın token'ını silmez; iş kalıcı hata olarak kapanır.
#[sqlx::test(migrations = "../../migrations")]
async fn rejected_push_is_not_retried_and_keeps_the_token(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let d = demo(&app, &owner, &org).await;
    set_token(&app, &owner, "tok-owner").await;
    let org_id: Uuid = org.parse().expect("uuid");

    let event = event_id(&simulate(&app, &owner, &d, 3).await);
    app.push.fail_next_with(1, push::PushError::Rejected);
    assert_eq!(
        push::dispatch(&app.state, org_id, event)
            .await
            .expect("dağıtım"),
        0
    );
    assert_eq!(delivery(&app, event).await, ("failed".to_owned(), 1));
    push::sweep_pending(&app.state).await;
    assert_eq!(delivery(&app, event).await, ("failed".to_owned(), 1));
    assert!(app.push.messages().is_empty());
    let (tokens,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM user_devices WHERE push_token = 'tok-owner'")
            .fetch_one(&app.admin)
            .await
            .expect("sayım");
    assert_eq!(tokens, 1);
}

// ---------------------------------------------------------------------------------------------
// S02, S05: oturum kuralı ve kimlik bilgisi sürümü
// ---------------------------------------------------------------------------------------------

/// Parola sıfırlanınca, sıfırlamadan önce açılmış ikinci adım bileti oturum açamaz.
#[sqlx::test(migrations = "../../migrations")]
async fn password_reset_voids_pending_second_step(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (access, _, _) = app.user(PHONE).await;
    let secret = app.enable_mfa(&access).await;

    let (status, challenge) = app.login(PHONE, PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
    let mfa_token = s(&challenge, "mfa_token");

    let code = reset_code(&app, PHONE).await;
    assert_eq!(
        reset(&app, PHONE, &code, NEW_PASSWORD).await.0,
        StatusCode::NO_CONTENT
    );
    let (status, _) = app
        .post(
            "/v1/auth/mfa/verify",
            json!({ "mfa_token": mfa_token, "code": totp_code(&secret, 1) }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "eski bilet geçersiz olmalı"
    );

    // Yeni parolayla yeni bilet çalışır.
    let (_, challenge) = app.login(PHONE, NEW_PASSWORD).await;
    let (status, body) = app
        .post(
            "/v1/auth/mfa/verify",
            json!({ "mfa_token": s(&challenge, "mfa_token"), "code": totp_code(&secret, 1) }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// 90 günü dolmuş oturumun cihazına push gitmez ve oturum listesinde görünmez.
#[sqlx::test(migrations = "../../migrations")]
async fn expired_sessions_get_no_push_and_are_not_listed(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let d = demo(&app, &owner, &org).await;
    let (_, old) = app.login(PHONE, PASSWORD).await;
    set_token(&app, &s(&old, "access_token"), "tok-old").await;
    let (_, sessions) = app.get("/v1/auth/sessions", &owner).await;
    assert_eq!(sessions.as_array().map(Vec::len), Some(2));

    sqlx::query(
        "UPDATE session_families SET created_at = now() - interval '91 days' WHERE id = $1::uuid",
    )
    .bind(s(&old, "session_id"))
    .execute(&app.admin)
    .await
    .expect("yaşlandırma");
    let (_, sessions) = app.get("/v1/auth/sessions", &owner).await;
    assert_eq!(sessions.as_array().map(Vec::len), Some(1));

    let event = event_id(&simulate(&app, &owner, &d, 3).await);
    let org_id: Uuid = org.parse().expect("uuid");
    assert_eq!(
        push::dispatch(&app.state, org_id, event)
            .await
            .expect("dağıtım"),
        0
    );
    assert!(
        app.push.messages().is_empty(),
        "süresi dolmuş oturuma alarm gitmemeli"
    );
}

// ---------------------------------------------------------------------------------------------
// S03, S12: parola sıfırlama
// ---------------------------------------------------------------------------------------------

/// Numara değişince eski numaraya gönderilmiş sıfırlama kodu parolayı değiştiremez.
#[sqlx::test(migrations = "../../migrations")]
async fn phone_change_voids_reset_codes_of_the_old_number(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (access, _, _) = app.user(PHONE).await;
    let old_code = reset_code(&app, PHONE).await;

    let before = app.sms.messages_to(NEW_NUMBER).len();
    let (status, body) = app
        .post_auth(
            "/v1/me/phone/start",
            json!({ "new_phone": NEW_NUMBER, "password": PASSWORD }),
            &access,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let code = app.last_code(NEW_NUMBER, before).await;
    let (status, body) = app
        .post_auth(
            "/v1/me/phone/complete",
            json!({ "new_phone": NEW_NUMBER, "code": code }),
            &access,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = reset(&app, PHONE, &old_code, NEW_PASSWORD).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_code"))
    );
    assert_eq!(app.login(NEW_NUMBER, PASSWORD).await.0, StatusCode::OK);
}

/// Hesaba bağlı parola kuralı kod doğrulandıktan sonra uygulanır: geçersiz kodla yanıt profil
/// verisine göre değişmez, kurala takılan istek kodu tüketmez.
#[sqlx::test(migrations = "../../migrations")]
async fn reset_profile_rules_follow_the_code(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    app.user(PHONE).await;
    // Kayıttaki görünen ad "Ayşe".
    let personal = "ayşe ile mavi deniz kenarı";
    let code = reset_code(&app, PHONE).await;

    let (status, body) = reset(&app, PHONE, "000000", personal).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_code")),
        "geçersiz kod, adı içeren parolayla aynı yanıtı almalı"
    );
    let (status, body) = reset(&app, PHONE, &code, personal).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("password_too_predictable"))
    );
    // Kod tüketilmedi: başka parolayla aynı kod çalışır.
    assert_eq!(
        reset(&app, PHONE, &code, NEW_PASSWORD).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(app.login(PHONE, NEW_PASSWORD).await.0, StatusCode::OK);
}

// ---------------------------------------------------------------------------------------------
// S07: hesap başına hata sınırı
// ---------------------------------------------------------------------------------------------

/// Paralel yanlış denemeler hesap başına 20 hata sınırını aşamaz.
#[sqlx::test(migrations = "../../migrations")]
async fn parallel_failures_cannot_exceed_the_account_cap(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    app.user(OTHER).await;
    reset_code(&app, OTHER).await;
    let key = shedu_api::auth::codes::rate_key(&app.state.hmac_secret, "fail:phone", OTHER);
    sqlx::query(
        "INSERT INTO rate_limit_buckets (key, window_start, hits)
         VALUES ($1, to_timestamp(floor(extract(epoch FROM now()) / 86400) * 86400), 19)",
    )
    .bind(&key)
    .execute(&app.admin)
    .await
    .expect("sayaç");

    let (a, b, c, e) = tokio::join!(
        reset(&app, OTHER, "000001", NEW_PASSWORD),
        reset(&app, OTHER, "000002", NEW_PASSWORD),
        reset(&app, OTHER, "000003", NEW_PASSWORD),
        reset(&app, OTHER, "000004", NEW_PASSWORD),
    );
    let mut statuses = [a.0, b.0, c.0, e.0];
    statuses.sort_unstable();
    assert_eq!(
        statuses,
        [
            StatusCode::BAD_REQUEST,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS
        ]
    );
    let (hits,): (i64,) = sqlx::query_as(
        "SELECT coalesce(sum(hits), 0)::bigint FROM rate_limit_buckets WHERE key = $1",
    )
    .bind(&key)
    .fetch_one(&app.admin)
    .await
    .expect("sorgu");
    assert_eq!(hits, 20, "sınır paralel isteklerle aşılmamalı");
}

// ---------------------------------------------------------------------------------------------
// S06, S09, S13: KVKK ve sahiplik
// ---------------------------------------------------------------------------------------------

/// Faktörü kurulmamış kurumsal personel, organizasyon kayıtlarını da içeren dışa aktarmayı
/// alamaz.
#[sqlx::test(migrations = "../../migrations")]
async fn staff_export_requires_the_second_factor(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (access, user, _) = app.user(PHONE).await;
    let (status, _) = app
        .post_auth(
            "/v1/me/data-export",
            json!({ "password": PASSWORD }),
            &access,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "ev kullanıcısı dışa aktarabilir");

    let business = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations (id, name, kind) VALUES ($1, 'Mağaza', 'business')")
        .bind(business)
        .execute(&app.admin)
        .await
        .expect("organizasyon");
    sqlx::query(
        "INSERT INTO memberships (user_id, organization_id, role) VALUES ($1::uuid, $2, 'admin')",
    )
    .bind(&user)
    .bind(business)
    .execute(&app.admin)
    .await
    .expect("üyelik");
    let (status, body) = app
        .post_auth(
            "/v1/me/data-export",
            json!({ "password": PASSWORD }),
            &access,
        )
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("mfa_required"))
    );
    app.enable_mfa(&access).await;
    let (status, _) = app
        .post_auth(
            "/v1/me/data-export",
            json!({ "password": PASSWORD }),
            &access,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

/// Silme talebi bekleyen hesaba sahiplik devredilemez.
#[sqlx::test(migrations = "../../migrations")]
async fn ownership_cannot_go_to_an_account_pending_deletion(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let (other, other_id, _) = app.user(OTHER).await;
    sqlx::query(
        "INSERT INTO memberships (user_id, organization_id, role) VALUES ($1::uuid, $2::uuid, 'admin')",
    )
    .bind(&other_id)
    .bind(&org)
    .execute(&app.admin)
    .await
    .expect("üyelik");

    let (status, body) = app
        .post_auth("/v1/me/delete", json!({ "password": PASSWORD }), &other)
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let (status, body) = app
        .post_auth(
            &format!("/v1/organizations/{org}/ownership-transfer"),
            json!({ "user_id": other_id, "password": PASSWORD }),
            &owner,
        )
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("target_not_active"))
    );
}

/// Silme talebi 30 günlük süre dolduktan sonra girişle geri alınamaz.
#[sqlx::test(migrations = "../../migrations")]
async fn erasure_cannot_be_cancelled_after_its_due_date(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (access, user, _) = app.user(PHONE).await;
    let (status, _) = app
        .post_auth("/v1/me/delete", json!({ "password": PASSWORD }), &access)
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    sqlx::query(
        "UPDATE users SET deletion_due_at = now() - interval '1 minute' WHERE id = $1::uuid",
    )
    .bind(&user)
    .execute(&app.admin)
    .await
    .expect("vade");

    assert_eq!(app.login(PHONE, PASSWORD).await.0, StatusCode::UNAUTHORIZED);
    let (status,): (String,) = sqlx::query_as("SELECT status FROM users WHERE id = $1::uuid")
        .bind(&user)
        .fetch_one(&app.admin)
        .await
        .expect("durum");
    assert_eq!(status, "pending_deletion");
    assert_eq!(
        privacy::erase_due_accounts(&app.state)
            .await
            .expect("silme"),
        1
    );
}

// ---------------------------------------------------------------------------------------------
// S10, S11, S15: paylaşılan zon ve sanal komutlar
// ---------------------------------------------------------------------------------------------

/// Paylaşılan zon: bypass her bölümde yetki ister, alarm her bölüme ayrı olay yazar, panel
/// ayrıntısı görünmeyen bölümün kimliğini göstermez.
#[sqlx::test(migrations = "../../migrations")]
async fn shared_zones_respect_every_partition(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let d = demo(&app, &owner, &org).await;
    let (member, member_id, _) = app.user(OTHER).await;
    grant(&app, &d, &member_id, &d.home, true).await;

    let bypass = |zone: i16| {
        json!({
            "partition_id": d.home, "kind": "bypass_zones", "zones": [zone],
            "idempotency_key": format!("test-{}", Uuid::new_v4().simple()),
        })
    };
    let path = format!("/v1/organizations/{}/panels/{}/commands", d.org, d.panel);
    // Yalnızca evde olan zon: bypass yetkisi yeter.
    let (status, body) = app.post_auth(&path, bypass(4), &member).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    tokio::time::sleep(Duration::from_millis(1200)).await;

    // Mutfak dumanı garajla da paylaşılıyor: garajda yetkisi olmayan bypass edemez.
    share_zone(&app, &d, 3, &d.garage).await;
    let (status, body) = app.post_auth(&path, bypass(3), &member).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("not_permitted"))
    );

    // Panel ayrıntısı: paylaşılan zonda yalnızca görünen bölüm.
    let (_, detail) = app
        .get(
            &format!("/v1/organizations/{}/panels/{}", d.org, d.panel),
            &member,
        )
        .await;
    let zone = detail["zones"]
        .as_array()
        .and_then(|z| z.iter().find(|z| z["number"] == 3))
        .expect("zon");
    assert_eq!(zone["partitions"], json!([d.home]));

    // Alarm iki bölüme de ayrı kritik olay olarak yazılır.
    let alarm = simulate(&app, &owner, &d, 3).await;
    let ids: Vec<i64> = alarm["event_ids"]
        .as_array()
        .expect("olaylar")
        .iter()
        .filter_map(Value::as_i64)
        .collect();
    let partitions: Vec<(i16,)> = sqlx::query_as(
        "SELECT partition_number FROM panel_events WHERE id = ANY($1) ORDER BY partition_number",
    )
    .bind(&ids)
    .fetch_all(&app.admin)
    .await
    .expect("olaylar");
    assert_eq!(partitions, [(1,), (2,)]);
}

/// Süreç kesilip simülatör işi kaybolursa komut beklemede kalmaz: tarama tamamlar ve bölüm
/// yeni komut alabilir.
#[sqlx::test(migrations = "../../migrations")]
async fn stale_simulated_commands_are_recovered(_: PgPoolOptions, connect: PgConnectOptions) {
    // Simülatör gecikmesi çok uzun: süreç içi iş hiç tamamlanmaz (süreç kesilmiş gibi).
    let app = app_with(connect, Duration::from_secs(3600)).await;
    let (owner, _, org) = app.user(PHONE).await;
    let d = demo(&app, &owner, &org).await;
    let path = format!("/v1/organizations/{}/panels/{}/commands", d.org, d.panel);
    let command = || {
        json!({
            "partition_id": d.home, "kind": "arm_away",
            "idempotency_key": format!("test-{}", Uuid::new_v4().simple()),
        })
    };
    let (status, first) = app.post_auth(&path, command(), &owner).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{first}");
    let (status, body) = app.post_auth(&path, command(), &owner).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("command_in_progress"))
    );

    assert_eq!(
        simulator::recover_stale(&app.state, 30)
            .await
            .expect("tarama"),
        0,
        "yeni komuta dokunulmaz"
    );
    sqlx::query(
        "UPDATE commands SET requested_at = now() - interval '1 minute' WHERE id = $1::uuid",
    )
    .bind(s(&first, "id"))
    .execute(&app.admin)
    .await
    .expect("yaşlandırma");
    assert_eq!(
        simulator::recover_stale(&app.state, 30)
            .await
            .expect("tarama"),
        1
    );
    let (_, view) = app
        .get(
            &format!("/v1/organizations/{}/commands/{}", d.org, s(&first, "id")),
            &owner,
        )
        .await;
    assert_eq!(view["status"], "succeeded");
    let disarm = json!({
        "partition_id": d.home, "kind": "disarm",
        "idempotency_key": format!("test-{}", Uuid::new_v4().simple()),
    });
    let (status, body) = app.post_auth(&path, disarm, &owner).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
}

// ---------------------------------------------------------------------------------------------
// Y01, Y03: kuyruktaki bildirim
// ---------------------------------------------------------------------------------------------

async fn delivery_statuses(app: &TestApp, event: i64) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT u.phone, d.status FROM push_deliveries d JOIN users u ON u.id = d.user_id
          WHERE d.panel_event_id = $1 ORDER BY u.phone",
    )
    .bind(event)
    .fetch_all(&app.admin)
    .await
    .expect("teslimler")
}

/// Kuyrukta bekleyen bildirim gönderilmeden önce alıcı yeniden denetlenir: arada yetkisi kalkan
/// kişiye gitmez ve işi iptal edilir; yetkisi süren kişiye gider (Y01).
#[sqlx::test(migrations = "../../migrations")]
async fn queued_push_rechecks_the_recipient(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let d = demo(&app, &owner, &org).await;
    let (member, member_id, _) = app.user(OTHER).await;
    grant(&app, &d, &member_id, &d.home, false).await;
    set_token(&app, &owner, "tok-owner").await;
    set_token(&app, &member, "tok-member").await;
    let org_id: Uuid = org.parse().expect("uuid");

    // İlk denemede iki gönderim de geçici hata alır: iki iş kuyrukta bekler.
    let event = event_id(&simulate(&app, &owner, &d, 3).await);
    app.push.fail_next(2);
    assert_eq!(
        push::dispatch(&app.state, org_id, event)
            .await
            .expect("dağıtım"),
        0
    );
    assert_eq!(
        delivery_statuses(&app, event).await,
        vec![
            (PHONE.to_owned(), "pending".to_owned()),
            (OTHER.to_owned(), "pending".to_owned())
        ]
    );

    // Kuyrukta beklerken üyenin yetkisi kaldırılır.
    sqlx::query("DELETE FROM access_grants WHERE user_id = $1::uuid")
        .bind(&member_id)
        .execute(&app.admin)
        .await
        .expect("yetki silme");
    sqlx::query("UPDATE push_deliveries SET next_attempt_at = now() WHERE panel_event_id = $1")
        .bind(event)
        .execute(&app.admin)
        .await
        .expect("güncelleme");
    push::sweep_pending(&app.state).await;
    assert_eq!(
        delivery_statuses(&app, event).await,
        vec![
            (PHONE.to_owned(), "sent".to_owned()),
            (OTHER.to_owned(), "cancelled".to_owned())
        ]
    );
    let tokens: Vec<String> = app.push.messages().into_iter().map(|m| m.token).collect();
    assert_eq!(tokens, vec!["tok-owner".to_owned()]);
}

/// Uzun kesintiden sonra hiçbir iş yarı yolda kalmaz ve eski alarm gönderilmez: eski olayın bekleyen
/// işi, deneme hakkı bitmiş süresi dolmuş iş kapanır; geç dağıtılan eski olay için iş yazılmaz
/// (Y03).
#[sqlx::test(migrations = "../../migrations")]
async fn old_push_work_is_closed_not_sent(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let d = demo(&app, &owner, &org).await;
    set_token(&app, &owner, "tok-owner").await;
    let org_id: Uuid = org.parse().expect("uuid");
    let age = |event: i64| {
        sqlx::query(
            "UPDATE panel_events SET received_at = now() - interval '2 hours' WHERE id = $1",
        )
        .bind(event)
        .execute(&app.admin)
    };

    // Bekleyen işin olayı eskidi (iş yeni yazılmış olsa da yaş olaydan ölçülür).
    let first = event_id(&simulate(&app, &owner, &d, 3).await);
    app.push.fail_next(1);
    push::dispatch(&app.state, org_id, first)
        .await
        .expect("dağıtım");
    age(first).await.expect("yaşlandırma");
    sqlx::query("UPDATE push_deliveries SET next_attempt_at = now() WHERE panel_event_id = $1")
        .bind(first)
        .execute(&app.admin)
        .await
        .expect("güncelleme");
    push::sweep_pending(&app.state).await;
    assert_eq!(delivery(&app, first).await, ("failed".to_owned(), 1));

    // Geç dağıtılan eski olay: iş yazılmaz, olay dağıtıldı sayılır.
    let second = event_id(&simulate(&app, &owner, &d, 4).await);
    age(second).await.expect("yaşlandırma");
    assert_eq!(
        push::dispatch(&app.state, org_id, second)
            .await
            .expect("dağıtım"),
        0
    );
    let (jobs, notified): (i64, bool) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM push_deliveries WHERE panel_event_id = $1),
                (SELECT notified_at IS NOT NULL FROM panel_events WHERE id = $1)",
    )
    .bind(second)
    .fetch_one(&app.admin)
    .await
    .expect("sayım");
    assert_eq!((jobs, notified), (0, true));

    // Deneme hakkı bitmiş, süresi dolmuş alınmış iş yeniden alınmaz; tarama onu kapatır.
    let third = event_id(&simulate(&app, &owner, &d, 3).await);
    app.push.fail_next(1);
    push::dispatch(&app.state, org_id, third)
        .await
        .expect("dağıtım");
    sqlx::query(
        "UPDATE push_deliveries SET status = 'sending', attempts = 6,
                lease_until = now() - interval '1 second'
          WHERE panel_event_id = $1",
    )
    .bind(third)
    .execute(&app.admin)
    .await
    .expect("güncelleme");
    push::sweep_pending(&app.state).await;
    assert_eq!(delivery(&app, third).await, ("failed".to_owned(), 6));
    assert!(
        app.push.messages().is_empty(),
        "eski bildirim gönderilmemeli"
    );
}

// ---------------------------------------------------------------------------------------------
// Y04: kimlik kanıtının nesli
// ---------------------------------------------------------------------------------------------

/// Yönetici hesabı kapatıp yeniden açarsa kapatmadan önce açılmış ikinci adım bileti oturum
/// açamaz; yeni giriş çalışır (Y04).
#[sqlx::test(migrations = "../../migrations")]
async fn admin_disable_voids_pending_second_step(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect.clone()).await;
    let (access, _, _) = app.user(PHONE).await;
    let secret = app.enable_mfa(&access).await;
    let (_, challenge) = app.login(PHONE, PASSWORD).await;
    let stale = s(&challenge, "mfa_token");

    let pool = db::pool_options(Some(admin::ADMIN_ROLE.into()))
        .max_connections(1)
        .connect_with(connect)
        .await
        .expect("yönetici bağlantısı");
    let op = Operator::new("pilot-ops", "Hesap incelemesi, kayıt 7").expect("işlemci");
    admin::set_user_active(&pool, &op, PHONE, false)
        .await
        .expect("kapatma");
    admin::set_user_active(&pool, &op, PHONE, true)
        .await
        .expect("açma");

    let (status, _) = app
        .post(
            "/v1/auth/mfa/verify",
            json!({ "mfa_token": stale, "code": totp_code(&secret, 1) }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "eski bilet geçersiz olmalı"
    );

    let (_, challenge) = app.login(PHONE, PASSWORD).await;
    let (status, body) = app
        .post(
            "/v1/auth/mfa/verify",
            json!({ "mfa_token": s(&challenge, "mfa_token"), "code": totp_code(&secret, 1) }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Bilet açıldıktan sonra kimlik bilgisi sürümü değiştiyse faktör denetlenmeden reddedilir: aynı
/// TOTP adımı yeni biletle hâlâ kullanılabilir (boşa harcanmaz) (Y04).
#[sqlx::test(migrations = "../../migrations")]
async fn version_mismatch_does_not_spend_the_factor(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (access, user_id, _) = app.user(PHONE).await;
    let secret = app.enable_mfa(&access).await;
    let (_, challenge) = app.login(PHONE, PASSWORD).await;
    let stale = s(&challenge, "mfa_token");
    // Yarışın sonucu: sürüm arttı ama bilet henüz tüketilmedi.
    sqlx::query("UPDATE users SET credential_version = credential_version + 1 WHERE id = $1::uuid")
        .bind(&user_id)
        .execute(&app.admin)
        .await
        .expect("sürüm");
    let code = totp_code(&secret, 1);
    let (status, _) = app
        .post(
            "/v1/auth/mfa/verify",
            json!({ "mfa_token": stale, "code": code }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (_, challenge) = app.login(PHONE, PASSWORD).await;
    let (status, body) = app
        .post(
            "/v1/auth/mfa/verify",
            json!({ "mfa_token": s(&challenge, "mfa_token"), "code": code }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "aynı TOTP adımı harcanmamış olmalı: {body}"
    );
}

// ---------------------------------------------------------------------------------------------
// Y05: eşzamanlılık hatası
// ---------------------------------------------------------------------------------------------

/// Kilitlenme ve serileştirme çakışması genel 500 değil, yeniden denenebilir 409 olur (Y05).
#[sqlx::test(migrations = "../../migrations")]
async fn deadlocks_become_retryable_conflicts(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    for (code, sql) in [
        (
            "40P01",
            "DO $$ BEGIN RAISE EXCEPTION 'çakışma' USING ERRCODE = '40P01'; END $$",
        ),
        (
            "40001",
            "DO $$ BEGIN RAISE EXCEPTION 'çakışma' USING ERRCODE = '40001'; END $$",
        ),
    ] {
        let error = sqlx::query(sql)
            .execute(&app.pool)
            .await
            .expect_err("hata bekleniyordu");
        assert!(
            matches!(
                ApiError::from(error),
                ApiError::Conflict("concurrent_update")
            ),
            "{code}"
        );
    }
    let error = sqlx::query("DO $$ BEGIN RAISE EXCEPTION 'başka' USING ERRCODE = '22023'; END $$")
        .execute(&app.pool)
        .await
        .expect_err("hata bekleniyordu");
    assert!(matches!(ApiError::from(error), ApiError::Internal));
}

// ---------------------------------------------------------------------------------------------
// Komut tekrarı
// ---------------------------------------------------------------------------------------------

/// İş kuralıyla reddedilen komutun aynı anahtarla tekrarı ilk yanıtla aynı sonucu verir (409 ve
/// aynı kod): ağ kesintisinden sonra yeniden gönderen istemci sonucu farklı yorumlamaz.
#[sqlx::test(migrations = "../../migrations")]
async fn rejected_command_replays_the_same_conflict(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let d = demo(&app, &owner, &org).await;
    let path = format!("/v1/organizations/{}/panels/{}/commands", d.org, d.panel);
    // Bölüm zaten kapalı: kapatma komutu reddedilir.
    let request = json!({
        "partition_id": d.home, "kind": "disarm",
        "idempotency_key": format!("test-{}", Uuid::new_v4().simple()),
    });
    let first = app.post_auth(&path, request.clone(), &owner).await;
    let again = app.post_auth(&path, request, &owner).await;
    assert_eq!(first.0, StatusCode::CONFLICT, "{}", first.1);
    assert_eq!((again.0, &again.1), (first.0, &first.1));
    let (count,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM commands WHERE status = 'rejected'")
            .fetch_one(&app.admin)
            .await
            .expect("sayım");
    assert_eq!(count, 1, "tekrar yeni komut yazmaz");
}
