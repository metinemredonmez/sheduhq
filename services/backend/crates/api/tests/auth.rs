//! Giriş ve oturum entegrasyon testleri. Gerçek PostgreSQL ister:
//!
//! ```bash
//! DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres cargo test -p shedu-api --features db-tests
//! ```
//!
//! Her test kendi boş veritabanında, bütün migration'lar uygulanmış olarak çalışır. Uygulama,
//! üretimdeki gibi RLS'yi aşamayan `shedu_app` rolüyle bağlanır.
#![cfg(feature = "db-tests")]

mod common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

// ---------------------------------------------------------------------------------------------
// Kayıt
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn register_creates_user_home_and_working_session(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let tokens = app.register(PHONE).await;

    let (status, me) = app
        .call(
            Method::GET,
            "/v1/me",
            None,
            Some(&s(&tokens, "access_token")),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["phone"], PHONE);
    assert_eq!(me["organizations"][0]["role"], "owner");
    assert_eq!(me["organizations"][0]["kind"], "home");

    let (status, _) = app.login(PHONE, PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
}

#[sqlx::test(migrations = "../../migrations")]
async fn register_start_does_not_reveal_existing_phone(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    app.register(PHONE).await;
    let before = app.sms.messages_to(PHONE).len();

    let (status, body) = app
        .post("/v1/auth/register/start", json!({ "phone": PHONE }))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body, Value::Null, "yanıt gövdesi boş olmalı");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        app.sms.messages_to(PHONE).len(),
        before,
        "kayıtlı numaraya kod gönderilmemeli"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn code_dies_after_five_wrong_attempts(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    app.post("/v1/auth/register/start", json!({ "phone": PHONE }))
        .await;
    let code = app.last_code(PHONE, 0).await;
    let wrong = if code == "000000" { "111111" } else { "000000" };

    let attempt = |code: String| {
        let app = &app;
        async move {
            app.post(
                "/v1/auth/register/complete",
                json!({
                    "phone": PHONE, "code": code, "display_name": "Ayşe",
                    "password": PASSWORD, "device": { "platform": "ios" }
                }),
            )
            .await
        }
    };
    for _ in 0..5 {
        let (status, body) = attempt(wrong.to_owned()).await;
        assert_eq!(
            (status, s(&body, "error")),
            (StatusCode::BAD_REQUEST, "invalid_code".into())
        );
    }
    let (status, _) = attempt(code).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "5 yanlış denemeden sonra doğru kod da geçmemeli"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn code_is_single_use_and_bound_to_purpose(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    app.post("/v1/auth/register/start", json!({ "phone": PHONE }))
        .await;
    let code = app.last_code(PHONE, 0).await;
    let body = |code: &str, phone: &str| {
        json!({
            "phone": phone, "code": code, "display_name": "Ayşe",
            "password": PASSWORD, "device": { "platform": "ios" }
        })
    };

    // Kayıt kodu parola sıfırlamada çalışmaz.
    let (status, _) = app
        .post(
            "/v1/auth/password-reset/complete",
            json!({ "phone": PHONE, "code": code, "new_password": NEW_PASSWORD }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = app
        .post("/v1/auth/register/complete", body(&code, PHONE))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = app
        .post("/v1/auth/register/complete", body(&code, PHONE))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "kod ikinci kez kullanılamamalı"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn weak_passwords_are_rejected_before_the_code_is_used(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    app.post("/v1/auth/register/start", json!({ "phone": PHONE }))
        .await;
    let code = app.last_code(PHONE, 0).await;

    for (password, error) in [
        ("Kx9#mvTq2Lp4Zr", "password_too_short"),
        ("123456789012345", "password_too_predictable"),
        ("ayse 5551112233 parolam", "password_too_predictable"),
    ] {
        let (status, body) = app
            .post(
                "/v1/auth/register/complete",
                json!({
                    "phone": PHONE, "code": code, "display_name": "Ayşe",
                    "password": password, "device": { "platform": "ios" }
                }),
            )
            .await;
        assert_eq!(
            (status, s(&body, "error")),
            (StatusCode::BAD_REQUEST, error.into()),
            "{password}"
        );
    }
    // Zayıf parola denemeleri kodu yakmaz.
    let (status, _) = app
        .post(
            "/v1/auth/register/complete",
            json!({
                "phone": PHONE, "code": code, "display_name": "Ayşe",
                "password": PASSWORD, "device": { "platform": "ios" }
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn unknown_fields_are_rejected(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (status, _) = app
        .post(
            "/v1/auth/register/start",
            json!({ "phone": PHONE, "role": "admin" }),
        )
        .await;
    assert!(status.is_client_error(), "{status}");
}

// ---------------------------------------------------------------------------------------------
// Giriş ve deneme sınırı
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn wrong_password_and_unknown_user_look_the_same(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    app.register(PHONE).await;

    let wrong = app.login(PHONE, "yanlis ama uzun bir parola").await;
    let unknown = app.login("+905559998877", PASSWORD).await;
    assert_eq!(wrong.0, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong, unknown);
}

#[sqlx::test(migrations = "../../migrations")]
async fn login_is_throttled_per_account_without_locking_others_or_recovery(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    app.register(PHONE).await;
    app.register("+905557776655").await;

    for _ in 0..10 {
        assert_eq!(
            app.login(PHONE, "yanlis ama uzun bir parola").await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        app.login(PHONE, PASSWORD).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Başka hesap etkilenmez.
    assert_eq!(app.login("+905557776655", PASSWORD).await.0, StatusCode::OK);
    // Meşru kurtarma (parola sıfırlama) çalışmaya devam eder.
    let (status, _) = app
        .post("/v1/auth/password-reset/start", json!({ "phone": PHONE }))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn failed_logins_are_audited_without_secrets(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    app.register(PHONE).await;
    app.login(PHONE, "yanlis ama uzun bir parola").await;

    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT row_to_json(a)::text FROM audit_log a WHERE action = 'auth.login_failed'",
    )
    .fetch_all(&app.admin)
    .await
    .expect("sorgu");
    assert_eq!(rows.len(), 1);
    let row = &rows[0].0;
    assert!(
        !row.contains("yanlis") && !row.contains(PHONE) && !row.contains("5551112233"),
        "{row}"
    );

    // Uygulama rolü kiracısız denetim kayıtlarını okuyamaz (RLS).
    let visible: Vec<(String,)> =
        sqlx::query_as("SELECT action FROM audit_log WHERE action = 'auth.login_failed'")
            .fetch_all(&app.pool)
            .await
            .expect("sorgu");
    assert!(visible.is_empty());
}

// ---------------------------------------------------------------------------------------------
// Token yenileme, çıkış, oturumlar
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn refresh_rotates_and_reuse_revokes_the_whole_family(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let first = app.register(PHONE).await;

    let (status, second) = app
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": s(&first, "refresh_token") }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(s(&second, "refresh_token"), s(&first, "refresh_token"));
    assert_eq!(second["session_id"], first["session_id"]);

    // Eski token yeniden gelir: çalınmış sayılır.
    let (status, _) = app
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": s(&first, "refresh_token") }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Bütün aile iptal: yeni refresh de, access token da geçmez.
    let (status, _) = app
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": s(&second, "refresh_token") }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = app
        .call(
            Method::GET,
            "/v1/me",
            None,
            Some(&s(&second, "access_token")),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn logout_invalidates_access_and_refresh_immediately(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let tokens = app.register(PHONE).await;
    let access = s(&tokens, "access_token");

    let (status, _) = app
        .call(Method::POST, "/v1/auth/logout", None, Some(&access))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = app.call(Method::GET, "/v1/me", None, Some(&access)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = app
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": s(&tokens, "refresh_token") }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn sessions_can_be_listed_and_closed_but_not_someone_elses(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let phone_session = app.register(PHONE).await;
    let (_, tablet_session) = app.login(PHONE, PASSWORD).await;
    let other_user = app.register("+905557776655").await;

    let access = s(&phone_session, "access_token");
    let (status, sessions) = app
        .call(Method::GET, "/v1/auth/sessions", None, Some(&access))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sessions.as_array().map(Vec::len), Some(2));
    assert_eq!(
        sessions
            .as_array()
            .map(|list| list.iter().filter(|s| s["current"] == true).count()),
        Some(1)
    );

    // Başka bir kullanıcının oturumu kapatılamaz.
    let foreign = format!("/v1/auth/sessions/{}", s(&other_user, "session_id"));
    let (status, _) = app
        .call(Method::DELETE, &foreign, None, Some(&access))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = app
        .call(
            Method::GET,
            "/v1/me",
            None,
            Some(&s(&other_user, "access_token")),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "diğer kullanıcının oturumu sürmeli");

    // Kendi tablet oturumunu kapatır.
    let own = format!("/v1/auth/sessions/{}", s(&tablet_session, "session_id"));
    let (status, _) = app.call(Method::DELETE, &own, None, Some(&access)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = app
        .call(
            Method::GET,
            "/v1/me",
            None,
            Some(&s(&tablet_session, "access_token")),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn me_shows_only_own_organizations(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let first = app.register(PHONE).await;
    app.register("+905557776655").await;

    let (_, me) = app
        .call(
            Method::GET,
            "/v1/me",
            None,
            Some(&s(&first, "access_token")),
        )
        .await;
    assert_eq!(me["organizations"].as_array().map(Vec::len), Some(1));
}

#[sqlx::test(migrations = "../../migrations")]
async fn bad_tokens_are_rejected(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let tokens = app.register(PHONE).await;
    let access = s(&tokens, "access_token");

    for bad in [
        "",
        "abc.def.ghi",
        &format!("{access}x"),
        // Refresh token access token yerine geçmez.
        &s(&tokens, "refresh_token"),
    ] {
        let (status, _) = app.call(Method::GET, "/v1/me", None, Some(bad)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{bad}");
    }
    let (status, _) = app.call(Method::GET, "/v1/me", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------------------------
// Parola sıfırlama
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn password_reset_changes_password_and_closes_all_sessions(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let tokens = app.register(PHONE).await;
    let before = app.sms.messages_to(PHONE).len();

    let (status, _) = app
        .post("/v1/auth/password-reset/start", json!({ "phone": PHONE }))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let code = app.last_code(PHONE, before).await;
    let (status, _) = app
        .post(
            "/v1/auth/password-reset/complete",
            json!({ "phone": PHONE, "code": code, "new_password": NEW_PASSWORD }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = app
        .call(
            Method::GET,
            "/v1/me",
            None,
            Some(&s(&tokens, "access_token")),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "eski oturum kapanmalı");
    assert_eq!(app.login(PHONE, PASSWORD).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(app.login(PHONE, NEW_PASSWORD).await.0, StatusCode::OK);
}

#[sqlx::test(migrations = "../../migrations")]
async fn password_reset_start_does_not_reveal_unknown_phone(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (status, _) = app
        .post("/v1/auth/password-reset/start", json!({ "phone": PHONE }))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(app.sms.messages_to(PHONE).is_empty());
}

#[sqlx::test(migrations = "../../migrations")]
async fn sms_sending_is_rate_limited_per_phone(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    for _ in 0..3 {
        assert_eq!(
            app.post("/v1/auth/register/start", json!({ "phone": PHONE }))
                .await
                .0,
            StatusCode::ACCEPTED
        );
    }
    assert_eq!(
        app.post("/v1/auth/register/start", json!({ "phone": PHONE }))
            .await
            .0,
        StatusCode::TOO_MANY_REQUESTS
    );
}
