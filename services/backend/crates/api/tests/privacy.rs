//! Kişisel veri (KVKK) entegrasyon testleri: dışa aktarma, silme, düzeltme (DAT-02, AZ-03,
//! AUT-04, RES-01, LOG-01).
#![cfg(feature = "db-tests")]

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use uuid::Uuid;

const MEMBER: &str = "+905557776655";
const TAKEN: &str = "+905554443322";
const THIRD: &str = "+905556665544";
const NEW: &str = "+905553332211";
const NEW2: &str = "+905552221100";
const NEW3: &str = "+905551119988";
const NEW4: &str = "+905550001122";

fn key() -> String {
    format!("test-{}", Uuid::new_v4().simple())
}

async fn count(app: &TestApp, sql: &'static str, bind: &str) -> i64 {
    sqlx::query_as::<_, (i64,)>(sql)
        .bind(bind)
        .fetch_one(&app.admin)
        .await
        .expect("sorgu")
        .0
}

async fn audit_count(app: &TestApp, action: &str) -> i64 {
    count(
        app,
        "SELECT count(*) FROM audit_log WHERE action = $1 AND outcome = 'success'",
        action,
    )
    .await
}

/// Davet eder, kişi kayıt olur ve kabul eder; (access token, kullanıcı kimliği, ev org) döner.
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

/// Komut verir ve tamamlanmasını bekler; komut kimliğini döner.
async fn run(app: &TestApp, access: &str, org: &str, panel: &str, partition: &str) -> String {
    let (status, body) = app
        .post_auth(
            &format!("/v1/organizations/{org}/panels/{panel}/commands"),
            json!({ "partition_id": partition, "kind": "arm_away", "idempotency_key": key() }),
            access,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let id = s(&body, "id");
    for _ in 0..100 {
        let (_, c) = app
            .get(&format!("/v1/organizations/{org}/commands/{id}"), access)
            .await;
        if c["status"] == "succeeded" {
            return id;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("komut tamamlanmadı");
}

async fn grant_garage(
    app: &TestApp,
    owner: &str,
    org: &str,
    member: &str,
    panel: &str,
    garage: &str,
) {
    let (status, body) = app
        .post_auth(
            &format!("/v1/organizations/{org}/members/{member}/grants"),
            json!({
                "panel_id": panel, "partition_id": garage,
                "can_view_events": true, "can_arm": true, "can_disarm": true, "can_bypass": false,
                "always_open": true
            }),
            owner,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

async fn export(app: &TestApp, access: &str, password: &str) -> (StatusCode, Value) {
    app.post_auth(
        "/v1/me/data-export",
        json!({ "password": password }),
        access,
    )
    .await
}

async fn sms_containing(app: &TestApp, phone: &str, needle: &str) -> usize {
    for _ in 0..500 {
        let n = app
            .sms
            .messages_to(phone)
            .iter()
            .filter(|m| m.contains(needle))
            .count();
        if n > 0 {
            return n;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    0
}

// ---------------------------------------------------------------------------------------------
// Dışa aktarma
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn export_returns_only_own_data_and_is_limited(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (owner, owner_id, org) = app.user(PHONE).await;
    let (panel, home, garage) = demo(&app, &owner, &org).await;
    let (member, member_id, _) = join(&app, &owner, &org, MEMBER).await;
    grant_garage(&app, &owner, &org, &member_id, &panel, &garage).await;
    run(&app, &member, &org, &panel, &garage).await;
    run(&app, &owner, &org, &panel, &home).await;

    // Yanlış parola ve fazladan alan reddedilir.
    let (status, body) = export(&app, &member, NEW_PASSWORD).await;
    assert_eq!(
        (status, s(&body, "error")),
        (StatusCode::FORBIDDEN, "reauth_failed".into())
    );
    let (status, _) = app
        .post_auth(
            "/v1/me/data-export",
            json!({ "password": PASSWORD, "user_id": owner_id }),
            &member,
        )
        .await;
    assert!(status.is_client_error());

    let (status, data) = export(&app, &member, PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "{data}");
    assert_eq!(data["format"], "shedu-personal-data/v1");
    assert_eq!(data["user"]["id"], member_id.as_str());
    assert_eq!(data["user"]["phone"], MEMBER);
    assert_eq!(data["organizations"].as_array().map(Vec::len), Some(2));
    assert_eq!(data["access_grants"].as_array().map(Vec::len), Some(1));
    assert_eq!(data["access_grants"][0]["partition_id"], garage.as_str());
    let commands = data["commands"].as_array().expect("komutlar");
    assert_eq!(commands.len(), 1, "yalnızca kendi komutu");
    assert_eq!(commands[0]["partition_id"], garage.as_str());
    let events = data["security_events"].as_array().expect("olaylar");
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "invitation.accepted" && e["by_me"] == true)
    );
    let device = &data["devices"][0];
    assert!(
        device.get("push_token").is_none(),
        "push token dışarı çıkmamalı"
    );
    assert_eq!(data["mfa"]["totp"], "none");

    // Başka kişinin kişisel verisi girmez (AZ-03).
    let text = data.to_string();
    assert!(!text.contains(PHONE), "sahibin numarası olmamalı");
    assert!(!text.contains(&owner_id), "sahibin kimliği olmamalı");

    // Ayrıldıktan sonra da kendi komutu dışa aktarılır; yetkisi artık yoktur.
    let (status, _) = app
        .delete(
            &format!("/v1/organizations/{org}/members/{member_id}"),
            &member,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, data) = export(&app, &member, PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(data["commands"].as_array().map(Vec::len), Some(1));
    assert_eq!(data["access_grants"].as_array().map(Vec::len), Some(0));
    assert_eq!(data["organizations"].as_array().map(Vec::len), Some(1));

    // Günde 3 kez.
    let (status, _) = export(&app, &member, PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = export(&app, &member, PASSWORD).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(audit_count(&app, "privacy.exported").await, 3);
}

#[sqlx::test(migrations = "../../migrations")]
async fn privacy_actions_need_a_verified_session_when_mfa_is_on(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (verified, user_id, _) = app.user(PHONE).await;
    let (_, password_only) = app.login(PHONE, PASSWORD).await;
    let password_only = s(&password_only, "access_token");
    app.enable_mfa(&verified).await;

    for (path, body) in [
        ("/v1/me/data-export", json!({ "password": PASSWORD })),
        ("/v1/me/delete", json!({ "password": PASSWORD })),
        (
            "/v1/me/phone/start",
            json!({ "new_phone": NEW, "password": PASSWORD }),
        ),
    ] {
        let (status, response) = app.post_auth(path, body, &password_only).await;
        assert_eq!(
            (status, s(&response, "error")),
            (StatusCode::FORBIDDEN, "mfa_required".into()),
            "{path}"
        );
    }
    let status: String =
        sqlx::query_as::<_, (String,)>("SELECT status FROM users WHERE id = $1::uuid")
            .bind(&user_id)
            .fetch_one(&app.admin)
            .await
            .expect("sorgu")
            .0;
    assert_eq!(status, "active");
    let (status, _) = export(&app, &verified, PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------------------------
// Silme
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn account_deletion_anonymizes_and_keeps_shared_security_records(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let (panel, _, garage) = demo(&app, &owner, &org).await;
    let (member, member_id, member_home) = join(&app, &owner, &org, MEMBER).await;
    grant_garage(&app, &owner, &org, &member_id, &panel, &garage).await;
    let shared_command = run(&app, &member, &org, &panel, &garage).await;
    // Üyenin kendi evi: tek üyeli, paneli ve komutu var.
    let (home_panel, home_partition, _) = demo(&app, &member, &member_home).await;
    run(&app, &member, &member_home, &home_panel, &home_partition).await;
    // Başka bir organizasyondan üyeye açık davet.
    let (third, _, third_org) = app.user(THIRD).await;
    let (status, _) = app
        .post_auth(
            &format!("/v1/organizations/{third_org}/invitations"),
            json!({ "phone": MEMBER, "role": "member" }),
            &third,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = app
        .put(
            "/v1/devices/current/push-token",
            json!({ "token": "member-device" }),
            &member,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Başka üyesi olan organizasyonun sahibi önce devretmeli; hangi organizasyon olduğu söylenir.
    let (status, body) = app
        .post_auth("/v1/me/delete", json!({ "password": PASSWORD }), &owner)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "transfer_ownership_first");
    assert_eq!(body["organizations"], json!([org]));

    let (status, _) = app
        .post_auth(
            "/v1/me/delete",
            json!({ "password": NEW_PASSWORD }),
            &member,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = app
        .post_auth("/v1/me/delete", json!({ "password": PASSWORD }), &member)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Oturum ve giriş kapandı.
    let (status, _) = app.get("/v1/me", &member).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = app.login(MEMBER, PASSWORD).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Kişi kimliksiz; kendi evi bütün verisiyle silindi; ortak organizasyondaki komut kaldı.
    let (state, phone, name, hash): (String, Option<String>, String, Option<String>) =
        sqlx::query_as(
            "SELECT status, phone, display_name, password_hash FROM users WHERE id = $1::uuid",
        )
        .bind(&member_id)
        .fetch_one(&app.admin)
        .await
        .expect("kullanıcı");
    assert_eq!(
        (state.as_str(), phone, name.as_str(), hash),
        ("deleted", None, "Silinmiş kullanıcı", None)
    );
    let q = |sql: &'static str| count(&app, sql, &member_id);
    assert_eq!(
        q("SELECT count(*) FROM commands WHERE user_id = $1::uuid").await,
        1
    );
    assert_eq!(
        q("SELECT count(*) FROM memberships WHERE user_id = $1::uuid").await,
        0
    );
    assert_eq!(
        q("SELECT count(*) FROM access_grants WHERE user_id = $1::uuid").await,
        0
    );
    assert_eq!(
        q("SELECT count(*) FROM user_devices WHERE user_id = $1::uuid").await,
        0
    );
    assert_eq!(
        q("SELECT count(*) FROM refresh_tokens WHERE user_id = $1::uuid").await,
        0
    );
    assert!(q("SELECT count(*) FROM audit_log WHERE actor_user_id = $1::uuid").await > 0);
    assert_eq!(
        count(
            &app,
            "SELECT count(*) FROM organizations WHERE id = $1::uuid",
            &member_home
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &app,
            "SELECT count(*) FROM panels WHERE organization_id = $1::uuid",
            &member_home
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &app,
            "SELECT count(*) FROM invitations WHERE phone = $1",
            MEMBER
        )
        .await,
        0
    );

    // Organizasyon tarafı: üye listede yok, komut kaydı duruyor.
    let (_, members) = app
        .get(&format!("/v1/organizations/{org}/members"), &owner)
        .await;
    assert_eq!(members["members"].as_array().map(Vec::len), Some(1));
    let (status, _) = app
        .get(
            &format!("/v1/organizations/{org}/commands/{shared_command}"),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (details,): (Value,) = sqlx::query_as(
        "SELECT details FROM audit_log WHERE action = 'privacy.account_erased' AND outcome = 'success'",
    )
    .fetch_one(&app.admin)
    .await
    .expect("denetim");
    assert_eq!(details["organizations_deleted"], 1);
    assert_eq!(details["memberships_removed"], 1);
    assert!(!details.to_string().contains(MEMBER));
    assert_eq!(sms_containing(&app, MEMBER, "silindi").await, 1);

    // Aynı numarayla yeniden kayıt olunabilir; yeni bir hesaptır.
    let (_, again, _) = app.user(MEMBER).await;
    assert_ne!(again, member_id);
}

// ---------------------------------------------------------------------------------------------
// Düzeltme
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn profile_and_phone_can_be_corrected_safely(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (access, user_id, _) = app.user(PHONE).await;
    app.user(TAKEN).await;

    // Görünen ad.
    let (status, _) = app
        .patch("/v1/me", json!({ "display_name": "  Ali Veli " }), &access)
        .await;
    assert_eq!(status, StatusCode::OK);
    for bad in [
        json!({ "display_name": " " }),
        json!({ "display_name": "x".repeat(101) }),
    ] {
        let (status, _) = app.patch("/v1/me", bad, &access).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (status, _) = app
        .patch(
            "/v1/me",
            json!({ "display_name": "Ali", "phone": NEW }),
            &access,
        )
        .await;
    assert!(status.is_client_error(), "numara bu yoldan değişmemeli");
    let (_, me) = app.get("/v1/me", &access).await;
    assert_eq!(
        (me["display_name"].as_str(), me["phone"].as_str()),
        (Some("Ali Veli"), Some(PHONE))
    );

    // Numara: aynı numara, yanlış parola.
    let start = |phone: &str, password: &str| json!({ "new_phone": phone, "password": password });
    let (status, _) = app
        .post_auth("/v1/me/phone/start", start(PHONE, PASSWORD), &access)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = app
        .post_auth("/v1/me/phone/start", start(NEW, NEW_PASSWORD), &access)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Başka hesaba ait numara: yanıt aynı, kod gönderilmez, tamamlanamaz.
    let before = app.sms.messages_to(TAKEN).len();
    let (status, _) = app
        .post_auth("/v1/me/phone/start", start(TAKEN, PASSWORD), &access)
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        app.sms.messages_to(TAKEN).len(),
        before,
        "kayıtlı numaraya kod gitmemeli"
    );
    let (status, _) = app
        .post_auth(
            "/v1/me/phone/complete",
            json!({ "new_phone": TAKEN, "code": "123456" }),
            &access,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Başkasının değişim kodu işe yaramaz.
    let (other, _, _) = app.user(THIRD).await;
    let (status, _) = app
        .post_auth("/v1/me/phone/start", start(NEW2, PASSWORD), &other)
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let others_code = app.last_code(NEW2, 0).await;
    let (status, _) = app
        .post_auth(
            "/v1/me/phone/complete",
            json!({ "new_phone": NEW2, "code": others_code }),
            &access,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Doğru akış: yeni numaraya kod, yanlış kod reddi, sonra değişim ve eski numaraya bildirim.
    let (status, _) = app
        .post_auth("/v1/me/phone/start", start(NEW, PASSWORD), &access)
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let code = app.last_code(NEW, 0).await;
    let (status, _) = app
        .post_auth(
            "/v1/me/phone/complete",
            json!({ "new_phone": NEW, "code": "000000" }),
            &access,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = app
        .post_auth(
            "/v1/me/phone/complete",
            json!({ "new_phone": NEW, "code": code }),
            &access,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, me) = app.get("/v1/me", &access).await;
    assert_eq!(me["phone"], NEW);
    let (status, _) = app.login(NEW, PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = app.login(PHONE, PASSWORD).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        sms_containing(&app, PHONE, "numarası değiştirildi").await,
        1
    );

    // Günde 3 değişim başlatma (bu kullanıcı TAKEN ve NEW ile 2 kez başlattı).
    let (status, _) = app
        .post_auth("/v1/me/phone/start", start(NEW3, PASSWORD), &access)
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, _) = app
        .post_auth("/v1/me/phone/start", start(NEW4, PASSWORD), &access)
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    assert_eq!(audit_count(&app, "profile.updated").await, 1);
    assert_eq!(audit_count(&app, "profile.phone_changed").await, 1);
    let details: Vec<(Value,)> =
        sqlx::query_as("SELECT details FROM audit_log WHERE actor_user_id = $1::uuid")
            .bind(&user_id)
            .fetch_all(&app.admin)
            .await
            .expect("denetim");
    assert!(
        details
            .iter()
            .all(|(d,)| !d.to_string().contains(NEW) && !d.to_string().contains(PHONE)),
        "denetim kaydına numara yazılmamalı"
    );
}
