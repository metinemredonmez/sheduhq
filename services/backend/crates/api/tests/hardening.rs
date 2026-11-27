//! Denetim bulgularına karşı sertleştirme testleri (27 Kasım 2026 backend denetimi).
#![cfg(feature = "db-tests")]

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use serde_json::{Value, json};
use shedu_api::db;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use uuid::Uuid;

const OTHER: &str = "+905554443322";

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
    let panel = panels
        .as_array()
        .and_then(|l| l.iter().find(|p| p["simulated"] == true))
        .expect("panel");
    let home = panel["partitions"]
        .as_array()
        .and_then(|l| l.iter().find(|p| p["number"] == 1))
        .map(|p| s(p, "id"))
        .expect("bölüm");
    (s(panel, "id"), home)
}

/// Bulgu 1: API RLS'yi aşan bir rolle bağlanırsa açılış reddedilir.
#[sqlx::test(migrations = "../../migrations")]
async fn startup_refuses_a_role_that_bypasses_rls(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect.clone()).await;
    db::verify_least_privilege(&app.pool, db::Service::Api)
        .await
        .expect("uygulama rolü kabul edilmeli");
    let superuser = db::pool_options(None)
        .max_connections(1)
        .connect_with(connect.clone())
        .await
        .expect("bağlantı");
    let error = db::verify_least_privilege(&superuser, db::Service::Api)
        .await
        .expect_err("süper kullanıcı reddedilmeli");
    assert!(error.to_string().contains("RLS"), "{error}");

    // Her ikili yalnızca kendi rolüyle başlar (AZ-05): API yönetim rolüyle, yönetim aracı
    // uygulama rolüyle çalışmaz.
    db::verify_least_privilege(&app.pool, db::Service::Admin)
        .await
        .expect_err("uygulama rolü yönetim aracında reddedilmeli");
    let admin = db::pool_options(Some("shedu_admin".to_owned()))
        .max_connections(1)
        .connect_with(connect)
        .await
        .expect("bağlantı");
    db::verify_least_privilege(&admin, db::Service::Admin)
        .await
        .expect("yönetim rolü yönetim aracında kabul edilmeli");
    let error = db::verify_least_privilege(&admin, db::Service::Api)
        .await
        .expect_err("yönetim rolü API'de reddedilmeli");
    assert!(error.to_string().contains("uygulama rolü"), "{error}");
}

/// Bulgu 1 (ikinci bariyer): RLS devre dışı olsa bile kiracı filtreleri sorgularda açıkça var.
#[sqlx::test(migrations = "../../migrations")]
async fn tenant_filters_hold_without_rls(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app_bypassing_rls(connect).await;
    let (a, _, org_a) = app.user(PHONE).await;
    let (b, _, org_b) = app.user(OTHER).await;
    demo(&app, &a, &org_a).await;
    let (panel_b, home_b) = demo(&app, &b, &org_b).await;
    let (status, command) = app
        .post_auth(
            &format!("/v1/organizations/{org_b}/panels/{panel_b}/commands"),
            json!({ "partition_id": home_b, "kind": "arm_away",
                    "idempotency_key": format!("test-{}", Uuid::new_v4().simple()) }),
            &b,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{command}");
    let command_b = s(&command, "id");
    // B'nin olayı oluşsun.
    for _ in 0..100 {
        let (n,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM panel_events WHERE organization_id = $1::uuid")
                .bind(&org_b)
                .fetch_one(&app.admin)
                .await
                .expect("sorgu");
        if n > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    let (_, panels) = app
        .get(&format!("/v1/organizations/{org_a}/panels"), &a)
        .await;
    assert_eq!(
        panels.as_array().map(Vec::len),
        Some(1),
        "yalnızca kendi paneli"
    );
    for path in [
        format!("/v1/organizations/{org_a}/panels/{panel_b}"),
        format!("/v1/organizations/{org_a}/panels/{panel_b}/events"),
        format!("/v1/organizations/{org_a}/commands/{command_b}"),
    ] {
        let (status, _) = app.get(&path, &a).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path} → {status}");
    }
    let (status, _) = app
        .post_auth(
            &format!("/v1/organizations/{org_a}/panels/{panel_b}/commands"),
            json!({ "partition_id": home_b, "kind": "disarm",
                    "idempotency_key": format!("test-{}", Uuid::new_v4().simple()) }),
            &a,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "başka kiracının paneline komut"
    );
    let (_, inbox) = app.get("/v1/notifications", &a).await;
    let leaked: Vec<&Value> = inbox["notifications"]
        .as_array()
        .expect("liste")
        .iter()
        .filter(|n| n["panel_id"] == panel_b.as_str())
        .collect();
    assert!(
        leaked.is_empty(),
        "başka kiracının olayı bildirimde: {leaked:?}"
    );
}

/// Bulgu 3a: MFA açılınca o anki oturum dışındaki bütün oturumlar kapanır.
#[sqlx::test(migrations = "../../migrations")]
async fn enabling_mfa_ends_other_sessions(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (current, _, _) = app.user(PHONE).await;
    let (status, other) = app.login(PHONE, PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
    let other_access = s(&other, "access_token");
    let other_refresh = s(&other, "refresh_token");
    let (status, _) = app
        .put(
            "/v1/devices/current/push-token",
            json!({ "token": "old-device" }),
            &other_access,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    app.enable_mfa(&current).await;
    assert_eq!(
        app.get("/v1/me", &other_access).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, _) = app
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": other_refresh }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(app.get("/v1/me", &current).await.0, StatusCode::OK);
    let (tokens,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM user_devices WHERE push_token = 'old-device'")
            .fetch_one(&app.admin)
            .await
            .expect("sorgu");
    assert_eq!(tokens, 0, "kapanan oturumun cihazına bildirim gitmemeli");
}

/// Bulgu 3b: oturumun yenilemeyle uzamayan mutlak bir ömrü var (90 gün).
#[sqlx::test(migrations = "../../migrations")]
async fn sessions_have_an_absolute_lifetime(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    app.user(PHONE).await;
    let (_, login) = app.login(PHONE, PASSWORD).await;
    let session = s(&login, "session_id");
    let (status, refreshed) = app
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": s(&login, "refresh_token") }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "yeni oturum yenilenebilmeli");
    sqlx::query(
        "UPDATE session_families SET created_at = now() - interval '91 days' WHERE id = $1::uuid",
    )
    .bind(&session)
    .execute(&app.admin)
    .await
    .expect("yaşlandırma");
    let access = s(&refreshed, "access_token");
    assert_eq!(app.get("/v1/me", &access).await.0, StatusCode::UNAUTHORIZED);
    let (status, _) = app
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": s(&refreshed, "refresh_token") }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "90 günden eski oturum yenilenmemeli"
    );
}

/// Bulgu 4: silme talebi gönderilmiş davetleri iptal eder; etkin olmayan kişinin daveti kabul
/// edilemez; kalıcı silme takılmaz.
#[sqlx::test(migrations = "../../migrations")]
async fn pending_deletion_voids_sent_invitations(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (owner, owner_id, org) = app.user(PHONE).await;
    let (status, invitation) = app
        .post_auth(
            &format!("/v1/organizations/{org}/invitations"),
            json!({ "phone": OTHER, "role": "member" }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let invitation_id = s(&invitation, "id");
    let (status, _) = app
        .post_auth("/v1/me/delete", json!({ "password": PASSWORD }), &owner)
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let (invitee, _, _) = app.user(OTHER).await;
    let (_, mine) = app.get("/v1/invitations", &invitee).await;
    assert_eq!(
        mine["invitations"],
        json!([]),
        "silme talebi davetleri iptal etmeli"
    );

    // İkinci bariyer: davet bir şekilde açık kalsa da etkin olmayan kişinin daveti kabul edilmez.
    sqlx::query("UPDATE invitations SET revoked_at = NULL WHERE id = $1::uuid")
        .bind(&invitation_id)
        .execute(&app.admin)
        .await
        .expect("yeniden açma");
    let (status, _) = app
        .post_auth(
            &format!("/v1/invitations/{invitation_id}/accept"),
            json!({}),
            &invitee,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    sqlx::query(
        "UPDATE users SET deletion_due_at = now() - interval '1 minute' WHERE id = $1::uuid",
    )
    .bind(&owner_id)
    .execute(&app.admin)
    .await
    .expect("süre");
    assert_eq!(
        shedu_api::privacy::erase_due_accounts(&app.state)
            .await
            .expect("iş"),
        1,
        "kalıcı silme takılmamalı"
    );
}

/// Bir sayaç penceresini doldurur (test kurulumu).
async fn exhaust(app: &TestApp, scope: &str, value: &str, window_secs: i32, hits: i32) {
    let key = shedu_api::auth::codes::rate_key(&app.state.hmac_secret, scope, value);
    sqlx::query(
        "INSERT INTO rate_limit_buckets (key, window_start, hits)
         VALUES ($1, to_timestamp(floor(extract(epoch FROM now()) / $2) * $2), $3)
         ON CONFLICT (key, window_start) DO UPDATE SET hits = EXCLUDED.hits",
    )
    .bind(key)
    .bind(window_secs)
    .bind(hits)
    .execute(&app.admin)
    .await
    .expect("sayaç");
}

async fn hits(app: &TestApp, scope: &str, value: &str) -> i64 {
    let key = shedu_api::auth::codes::rate_key(&app.state.hmac_secret, scope, value);
    sqlx::query_as::<_, (i64,)>(
        "SELECT coalesce(sum(hits), 0)::bigint FROM rate_limit_buckets WHERE key = $1",
    )
    .bind(key)
    .fetch_one(&app.admin)
    .await
    .expect("sorgu")
    .0
}

/// Bulgu 5: kod başına 5 denemeye ek olarak hesap başına 24 saatte en fazla 20 başarısız
/// doğrulama; dolunca doğru kod da kabul edilmez.
#[sqlx::test(migrations = "../../migrations")]
async fn failed_verifications_are_capped_per_account(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    app.user(PHONE).await;
    app.user(OTHER).await;

    // Başarısız deneme sayılır.
    let before = app.sms.messages_to(OTHER).len();
    app.post("/v1/auth/password-reset/start", json!({ "phone": OTHER }))
        .await;
    app.last_code(OTHER, before).await;
    let (status, _) = app
        .post(
            "/v1/auth/password-reset/complete",
            json!({ "phone": OTHER, "code": "000000", "new_password": NEW_PASSWORD }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(hits(&app, "fail:phone", OTHER).await, 1);

    // Sınır doluysa doğru SMS kodu da reddedilir.
    exhaust(&app, "fail:phone", PHONE, 24 * 60 * 60, 20).await;
    let before = app.sms.messages_to(PHONE).len();
    app.post("/v1/auth/password-reset/start", json!({ "phone": PHONE }))
        .await;
    let code = app.last_code(PHONE, before).await;
    let (status, _) = app
        .post(
            "/v1/auth/password-reset/complete",
            json!({ "phone": PHONE, "code": code, "new_password": NEW_PASSWORD }),
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // İkinci adımda da: sınır doluysa doğru TOTP kodu kabul edilmez.
    let (access, user_id, _) = app.user("+905551119988").await;
    let secret = app.enable_mfa(&access).await;
    exhaust(&app, "fail:mfa-user", &user_id, 24 * 60 * 60, 20).await;
    let (_, login) = app.login("+905551119988", PASSWORD).await;
    let (status, _) = app
        .post(
            "/v1/auth/mfa/verify",
            json!({ "mfa_token": s(&login, "mfa_token"), "code": totp_code(&secret, 1) }),
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}
