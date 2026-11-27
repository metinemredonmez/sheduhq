//! İki adımlı doğrulama entegrasyon testleri (AUT-01, AUT-04, KEY-04).
#![cfg(feature = "db-tests")]

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use serde_json::{Value, json};
use shedu_api::auth::totp;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

const OTHER: &str = "+905557776655";
const STAFF: &str = "+905552221100";

async fn audit_count(app: &TestApp, action: &str, outcome: &str) -> i64 {
    sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM audit_log WHERE action = $1 AND outcome = $2")
        .bind(action)
        .bind(outcome)
        .fetch_one(&app.admin)
        .await
        .expect("sorgu")
        .0
}

async fn status(app: &TestApp, access: &str) -> Value {
    let (code, body) = app.get("/v1/auth/mfa", access).await;
    assert_eq!(code, StatusCode::OK);
    body
}

/// Arka planda gönderilen, kod taşımayan güvenlik bildirimlerini sayar.
async fn notices(app: &TestApp, phone: &str, expected: usize) -> Vec<String> {
    for _ in 0..100 {
        let found: Vec<String> = app
            .sms
            .messages_to(phone)
            .into_iter()
            .filter(|m| m.contains("iki adımlı") || m.contains("kurtarma"))
            .collect();
        if found.len() >= expected {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Vec::new()
}

async fn verify(app: &TestApp, token: &str, factor: Value) -> (StatusCode, Value) {
    let mut body = json!({ "mfa_token": token });
    for (k, v) in factor.as_object().expect("nesne") {
        body[k] = v.clone();
    }
    app.post("/v1/auth/mfa/verify", body).await
}

async fn sessions(app: &TestApp) -> i64 {
    sqlx::query_as::<_, (i64,)>("SELECT count(DISTINCT family_id) FROM refresh_tokens")
        .fetch_one(&app.admin)
        .await
        .expect("sorgu")
        .0
}

#[sqlx::test(migrations = "../../migrations")]
async fn enrollment_requires_password_and_a_valid_code(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (access, user_id, _) = app.user(PHONE).await;
    assert_eq!(status(&app, &access).await["totp"], "none");

    let (code, body) = app
        .post_auth(
            "/v1/auth/mfa/totp/setup",
            json!({ "password": NEW_PASSWORD }),
            &access,
        )
        .await;
    assert_eq!(
        (code, s(&body, "error")),
        (StatusCode::FORBIDDEN, "reauth_failed".into())
    );

    let (code, setup) = app
        .post_auth(
            "/v1/auth/mfa/totp/setup",
            json!({ "password": PASSWORD }),
            &access,
        )
        .await;
    assert_eq!(code, StatusCode::OK, "{setup}");
    let secret = totp::base32_decode(&s(&setup, "secret")).expect("sır");
    assert_eq!(secret.len(), totp::SECRET_LEN);
    let uri = s(&setup, "otpauth_uri");
    assert!(uri.starts_with("otpauth://totp/Shedu:") && uri.contains("issuer=Shedu"));
    assert!(!uri.contains(PHONE), "adreste numaranın tamamı olmamalı");
    assert_eq!(status(&app, &access).await["totp"], "pending");

    // Sır veritabanında şifreli ve kullanıcıya bağlı (KEY-04).
    let (version, ciphertext): (i16, Vec<u8>) =
        sqlx::query_as("SELECT key_version, secret_ct FROM user_totp WHERE user_id = $1::uuid")
            .bind(&user_id)
            .fetch_one(&app.admin)
            .await
            .expect("kayıt");
    assert_eq!(version, 1);
    assert!(
        !ciphertext
            .windows(secret.len())
            .any(|w| w == secret.as_slice()),
        "sır düz metin saklanmamalı"
    );

    // Onaylanmamış kurulum girişte istenmez.
    let (code, login) = app.login(PHONE, PASSWORD).await;
    assert_eq!(code, StatusCode::OK);
    assert!(login.get("access_token").is_some());

    let (code, body) = app
        .post_auth(
            "/v1/auth/mfa/totp/confirm",
            json!({ "code": "000000" }),
            &access,
        )
        .await;
    assert_eq!(
        (code, s(&body, "error")),
        (StatusCode::BAD_REQUEST, "invalid_code".into())
    );
    let (code, confirmed) = app
        .post_auth(
            "/v1/auth/mfa/totp/confirm",
            json!({ "code": totp_code(&secret, 0) }),
            &access,
        )
        .await;
    assert_eq!(code, StatusCode::OK, "{confirmed}");
    let codes = confirmed["recovery_codes"].as_array().expect("kodlar");
    assert_eq!(codes.len(), 10);
    let (hashes,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM recovery_codes WHERE user_id = $1::uuid AND used_at IS NULL",
    )
    .bind(&user_id)
    .fetch_one(&app.admin)
    .await
    .expect("sorgu");
    assert_eq!(hashes, 10);
    let stored: Vec<(Vec<u8>,)> = sqlx::query_as("SELECT code_hash FROM recovery_codes")
        .fetch_all(&app.admin)
        .await
        .expect("sorgu");
    let first = codes[0].as_str().expect("kod").replace('-', "");
    assert!(
        stored
            .iter()
            .all(|(h,)| h.len() == 32 && h.as_slice() != first.as_bytes()),
        "kurtarma kodu düz saklanmamalı"
    );

    let current = status(&app, &access).await;
    assert_eq!(current["totp"], "enabled");
    assert_eq!(current["session_verified"], true);
    assert_eq!(current["recovery_codes_remaining"], 10);

    // Açıkken yeniden kurulamaz; kullanıcıya bildirim gider; denetim kaydı tutulur.
    let (code, _) = app
        .post_auth(
            "/v1/auth/mfa/totp/setup",
            json!({ "password": PASSWORD }),
            &access,
        )
        .await;
    assert_eq!(code, StatusCode::CONFLICT);
    assert_eq!(notices(&app, PHONE, 1).await.len(), 1);
    assert_eq!(audit_count(&app, "mfa.enabled", "success").await, 1);
    assert_eq!(audit_count(&app, "mfa.reauth", "failure").await, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn login_requires_the_second_factor_and_codes_are_single_use(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (access, _, _) = app.user(PHONE).await;
    let (_, setup) = app
        .post_auth(
            "/v1/auth/mfa/totp/setup",
            json!({ "password": PASSWORD }),
            &access,
        )
        .await;
    let secret = totp::base32_decode(&s(&setup, "secret")).expect("sır");
    let used_code = totp_code(&secret, 0);
    let (code, confirmed) = app
        .post_auth(
            "/v1/auth/mfa/totp/confirm",
            json!({ "code": used_code }),
            &access,
        )
        .await;
    assert_eq!(code, StatusCode::OK, "{confirmed}");
    let recovery: Vec<String> = confirmed["recovery_codes"]
        .as_array()
        .expect("kodlar")
        .iter()
        .map(|c| c.as_str().expect("kod").to_owned())
        .collect();
    assert_eq!(recovery.len(), 10);

    // Parola doğru: oturum açılmaz, yalnızca ikinci adım bileti gelir.
    let before = sessions(&app).await;
    let (code, login) = app.login(PHONE, PASSWORD).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(login["mfa_required"], true);
    assert!(login.get("access_token").is_none());
    assert_eq!(sessions(&app).await, before, "bilet oturum açmamalı");
    let token = s(&login, "mfa_token");

    // Kullanılmış adımın kodu (tekrar oynatma), yanlış kod ve iki faktör birden reddedilir.
    let (code, _) = verify(&app, &token, json!({ "code": used_code })).await;
    assert_eq!(
        code,
        StatusCode::BAD_REQUEST,
        "kullanılmış kod reddedilmeli"
    );
    let (code, _) = verify(&app, &token, json!({ "code": "123456" })).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    let (code, _) = verify(
        &app,
        &token,
        json!({ "code": "123456", "recovery_code": recovery[0] }),
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);

    // Kurtarma koduyla giriş; aynı bilet ve aynı kod ikinci kez kullanılamaz.
    let (code, tokens) = verify(&app, &token, json!({ "recovery_code": recovery[0] })).await;
    assert_eq!(code, StatusCode::OK, "{tokens}");
    let session = s(&tokens, "access_token");
    assert_eq!(status(&app, &session).await["session_verified"], true);
    assert_eq!(status(&app, &session).await["recovery_codes_remaining"], 9);
    let (code, _) = verify(&app, &token, json!({ "recovery_code": recovery[1] })).await;
    assert_eq!(code, StatusCode::UNAUTHORIZED, "bilet tek kullanımlık");
    let (_, login) = app.login(PHONE, PASSWORD).await;
    let token = s(&login, "mfa_token");
    let (code, _) = verify(&app, &token, json!({ "recovery_code": recovery[0] })).await;
    assert_eq!(
        code,
        StatusCode::BAD_REQUEST,
        "kurtarma kodu tek kullanımlık"
    );
    assert_eq!(
        notices(&app, PHONE, 2).await.len(),
        2,
        "kurtarma kodu bildirilmeli"
    );

    // Bir sonraki adımın TOTP kodu kabul edilir.
    let (code, tokens) = verify(&app, &token, json!({ "code": totp_code(&secret, 1) })).await;
    assert_eq!(code, StatusCode::OK, "{tokens}");

    // Beş yanlış denemede bilet tükenir; doğru faktör artık işe yaramaz (ayrı kullanıcı: kişi
    // başına 15 dakikada 10 deneme sınırı bu kullanıcıda dolmak üzere).
    let (other, _, _) = app.user(OTHER).await;
    let other_secret = app.enable_mfa(&other).await;
    let (_, login) = app.login(OTHER, PASSWORD).await;
    let token = s(&login, "mfa_token");
    for _ in 0..5 {
        let (code, _) = verify(&app, &token, json!({ "code": "000000" })).await;
        assert_eq!(code, StatusCode::BAD_REQUEST);
    }
    let (code, _) = verify(&app, &token, json!({ "code": totp_code(&other_secret, 1) })).await;
    assert_eq!(code, StatusCode::UNAUTHORIZED);
    let (code, _) = verify(&app, "uydurma-bilet", json!({ "code": "000000" })).await;
    assert_eq!(code, StatusCode::UNAUTHORIZED);

    // Kişi başına sınır: ilk kullanıcının kalan denemeleri bitince 429.
    let (_, login) = app.login(PHONE, PASSWORD).await;
    let token = s(&login, "mfa_token");
    let mut limited = false;
    for _ in 0..10 {
        let (code, _) = verify(&app, &token, json!({ "code": "000000" })).await;
        if code == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
    }
    assert!(limited, "kişi başına deneme sınırı uygulanmalı");
    assert!(audit_count(&app, "auth.mfa_failed", "failure").await >= 7);
}

#[sqlx::test(migrations = "../../migrations")]
async fn business_staff_need_a_verified_session_everywhere(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    app.start_background().await;
    let (owner, _, org) = app.user(PHONE).await;
    // MFA açmamış ikinci personel (yönetici): yalnızca parolalı oturum.
    let (second, staff_id, _) = app.user(STAFF).await;
    sqlx::query(
        "INSERT INTO memberships (user_id, organization_id, role) VALUES ($1::uuid, $2::uuid, 'admin')",
    )
    .bind(&staff_id)
    .bind(&org)
    .execute(&app.admin)
    .await
    .expect("üyelik");
    let (home_user, _, home_org) = app.user(OTHER).await;

    sqlx::query("UPDATE organizations SET kind = 'business' WHERE id = $1::uuid")
        .bind(&org)
        .execute(&app.admin)
        .await
        .expect("tür");
    let panels = format!("/v1/organizations/{org}/panels");
    let (code, body) = app.get(&panels, &owner).await;
    assert_eq!(
        (code, s(&body, "error")),
        (StatusCode::FORBIDDEN, "mfa_required".into())
    );
    // Ev kullanıcısı etkilenmez.
    let (code, _) = app
        .get(&format!("/v1/organizations/{home_org}/panels"), &home_user)
        .await;
    assert_eq!(code, StatusCode::OK);

    // MFA'yı açan oturum erişir; MFA'sız personelin parolalı oturumu erişemez.
    let secret = app.enable_mfa(&owner).await;
    let (code, _) = app.get(&panels, &owner).await;
    assert_eq!(code, StatusCode::OK);
    let (code, _) = app.get(&panels, &second).await;
    assert_eq!(
        code,
        StatusCode::FORBIDDEN,
        "parolalı oturum yetkisiz kalmalı"
    );

    // Push: alarm yalnızca doğrulanmış oturumun cihazına gider.
    for (access, token) in [
        (&owner, "verified-device"),
        (&second, "password-only-device"),
    ] {
        let (code, _) = app
            .put(
                "/v1/devices/current/push-token",
                json!({ "token": token }),
                access,
            )
            .await;
        assert_eq!(code, StatusCode::NO_CONTENT);
    }
    let (code, _) = app
        .post_auth(
            &format!("/v1/organizations/{org}/demo-panel"),
            json!({}),
            &owner,
        )
        .await;
    assert_eq!(code, StatusCode::CREATED);
    let (_, list) = app.get(&panels, &owner).await;
    let panel = s(&list[0], "id");
    let (code, alarm) = app
        .post_auth(
            &format!("/v1/organizations/{org}/panels/{panel}/simulate-alarm"),
            json!({ "zone_number": 3 }),
            &owner,
        )
        .await;
    assert_eq!(code, StatusCode::ACCEPTED, "{alarm}");
    let event_id = alarm["event_id"].as_i64().expect("olay");
    for _ in 0..150 {
        if app.push.messages().iter().any(|m| m.event_id == event_id) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let tokens: Vec<String> = app
        .push
        .messages()
        .into_iter()
        .filter(|m| m.event_id == event_id)
        .map(|m| m.token)
        .collect();
    assert_eq!(tokens, vec!["verified-device".to_owned()]);

    // Kapatma: parola ve faktör ister; kapatınca bütün oturumların doğrulaması düşer.
    let (code, _) = app
        .post_auth(
            "/v1/auth/mfa/totp/disable",
            json!({ "password": NEW_PASSWORD, "code": totp_code(&secret, 1) }),
            &owner,
        )
        .await;
    assert_eq!(code, StatusCode::FORBIDDEN);
    let (code, _) = app
        .post_auth(
            "/v1/auth/mfa/totp/disable",
            json!({ "password": PASSWORD, "code": "000000" }),
            &owner,
        )
        .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    let (code, _) = app
        .post_auth(
            "/v1/auth/mfa/totp/disable",
            json!({ "password": PASSWORD, "code": totp_code(&secret, 1) }),
            &owner,
        )
        .await;
    assert_eq!(code, StatusCode::NO_CONTENT);
    let (code, _) = app.get(&panels, &owner).await;
    assert_eq!(
        code,
        StatusCode::FORBIDDEN,
        "kapatınca personel erişimi kalkmalı"
    );
    assert_eq!(status(&app, &owner).await["totp"], "none");
    let (code, login) = app.login(PHONE, PASSWORD).await;
    assert_eq!(code, StatusCode::OK);
    assert!(
        login.get("access_token").is_some(),
        "kapalıyken ikinci adım istenmez"
    );
    assert_eq!(notices(&app, PHONE, 2).await.len(), 2);
    assert_eq!(audit_count(&app, "mfa.disabled", "success").await, 1);
    assert_eq!(audit_count(&app, "mfa.disable", "failure").await, 1);
}
