//! Zorunlu güncelleme kontrolü entegrasyon testleri.
#![cfg(feature = "db-tests")]

mod common;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use common::*;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use shedu_api::{
    admin::{self, AdminError, Operator},
    db,
};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use tower::ServiceExt;

const STORE: &str = "https://apps.apple.com/tr/app/shedu/id000";

async fn admin_pool(connect: PgConnectOptions) -> PgPool {
    db::pool_options(Some(admin::ADMIN_ROLE.into()))
        .max_connections(2)
        .connect_with(connect)
        .await
        .expect("yönetici bağlantısı")
}

fn operator() -> Operator {
    Operator::new("pilot-ops", "1.1 sürümünde giriş hatası var").expect("işlemci")
}

/// İstemci sürüm başlığıyla istek.
async fn call(
    app: &TestApp,
    method: Method,
    path: &str,
    client: Option<&str>,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(client) = client {
        request = request.header("x-shedu-app", client);
    }
    if let Some(token) = bearer {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = match body {
        Some(json) => request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json.to_string())),
        None => request.body(Body::empty()),
    }
    .expect("istek");
    let response = app.router.clone().oneshot(request).await.expect("yanıt");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("gövde")
        .to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn check(app: &TestApp, platform: &str, version: &str) -> (StatusCode, Value) {
    call(
        app,
        Method::GET,
        &format!("/v1/app-version?platform={platform}&version={version}"),
        None,
        None,
        None,
    )
    .await
}

#[sqlx::test(migrations = "../../migrations")]
async fn check_endpoint_reports_status_per_platform(_: PgPoolOptions, connect: PgConnectOptions) {
    let pool = admin_pool(connect.clone()).await;
    let app = app(connect).await;

    // Politika yokken her sürüm güncel; giriş gerekmez.
    let (status, body) = check(&app, "ios", "1.0.0").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "up_to_date");
    for (platform, version) in [("symbian", "1.0"), ("ios", "1.0-beta"), ("ios", "")] {
        assert_eq!(
            check(&app, platform, version).await.0,
            StatusCode::BAD_REQUEST,
            "{platform} {version}"
        );
    }
    let (status, _) = call(
        &app,
        Method::GET,
        "/v1/app-version?platform=ios&version=1.0&debug=1",
        None,
        None,
        None,
    )
    .await;
    assert!(
        status.is_client_error(),
        "bilinmeyen parametre reddedilmeli"
    );

    admin::set_app_version(&pool, &operator(), "ios", "1.2", "1.4.0", Some(STORE))
        .await
        .expect("politika");
    let expect = [
        ("1.1.9", "update_required"),
        ("1.2.0", "update_recommended"),
        ("1.10.0", "up_to_date"),
        ("1.4", "up_to_date"),
    ];
    for (version, expected) in expect {
        let (status, body) = check(&app, "ios", version).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], expected, "{version}");
        assert_eq!(body["minimum_version"], "1.2.0");
        assert_eq!(body["store_url"], STORE);
    }
    let (_, android) = check(&app, "android", "0.1").await;
    assert_eq!(
        android["status"], "up_to_date",
        "başka platform etkilenmemeli"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn old_clients_are_rejected_but_can_still_check(_: PgPoolOptions, connect: PgConnectOptions) {
    let pool = admin_pool(connect.clone()).await;
    let app = app(connect).await;
    let (access, _, _) = app.user(PHONE).await;
    admin::set_app_version(&pool, &operator(), "ios", "1.2.0", "1.4.0", Some(STORE))
        .await
        .expect("politika");
    let me = |client: Option<&'static str>| {
        let app = &app;
        let access = access.clone();
        async move { call(app, Method::GET, "/v1/me", client, Some(&access), None).await }
    };

    let (status, body) = me(Some("ios/1.0.0")).await;
    assert_eq!(status, StatusCode::UPGRADE_REQUIRED);
    assert_eq!(body["error"], "update_required");
    assert_eq!(body["store_url"], STORE);
    assert_eq!(me(Some("ios/1.3.0")).await.0, StatusCode::OK);
    assert_eq!(
        me(None).await.0,
        StatusCode::OK,
        "başlıksız istemci etkilenmez"
    );
    assert_eq!(me(Some("android/0.1")).await.0, StatusCode::OK);
    let (status, body) = me(Some("ios-1.0")).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_app_header"))
    );

    // Eski istemci giriş de yapamaz; ama sürüm kontrolüne ve sağlık ucuna ulaşır.
    let (status, _) = call(
        &app,
        Method::POST,
        "/v1/auth/login",
        Some("ios/1.0.0"),
        None,
        Some(json!({ "identifier": PHONE, "password": PASSWORD, "device": { "platform": "ios" } })),
    )
    .await;
    assert_eq!(status, StatusCode::UPGRADE_REQUIRED);
    let (status, body) = call(
        &app,
        Method::GET,
        "/v1/app-version?platform=ios&version=1.0.0",
        Some("ios/1.0.0"),
        None,
        None,
    )
    .await;
    assert_eq!(
        (status, body["status"].as_str()),
        (StatusCode::OK, Some("update_required"))
    );
    assert_eq!(
        call(&app, Method::GET, "/health", Some("ios/1.0.0"), None, None)
            .await
            .0,
        StatusCode::OK
    );

    // En düşük sürüm yükselince önceki "önerilen" istemci de reddedilir.
    admin::set_app_version(&pool, &operator(), "ios", "1.4.0", "1.4.0", Some(STORE))
        .await
        .expect("politika");
    assert_eq!(me(Some("ios/1.3.0")).await.0, StatusCode::UPGRADE_REQUIRED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn version_policy_rules_and_role_separation(_: PgPoolOptions, connect: PgConnectOptions) {
    let pool = admin_pool(connect.clone()).await;
    let app = app(connect).await;
    let op = operator();
    for (platform, minimum, latest, url) in [
        ("ios", "1.5.0", "1.4.0", None),
        ("ios", "1.2-beta", "1.4.0", None),
        ("symbian", "1.0", "1.0", None),
        (
            "ios",
            "1.0",
            "1.0",
            Some("https://evil.example/https://apps.apple.com/"),
        ),
        ("ios", "1.0", "1.0", Some("http://apps.apple.com/app")),
    ] {
        assert!(
            matches!(
                admin::set_app_version(&pool, &op, platform, minimum, latest, url).await,
                Err(AdminError::Invalid(_))
            ),
            "{platform} {minimum} {latest} {url:?}"
        );
    }
    let error = sqlx::query(
        "INSERT INTO app_versions (platform, minimum_version, latest_version) VALUES ('ios', '99', '99')",
    )
    .execute(&app.pool)
    .await
    .expect_err("uygulama rolü yazamamalı");
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501")
    );

    admin::set_app_version(&pool, &op, "android", "2.0.0", "2.1.0", None)
        .await
        .expect("politika");
    let (details,): (Value,) =
        sqlx::query_as("SELECT details FROM audit_log WHERE action = 'admin.app_version_set'")
            .fetch_one(&app.admin)
            .await
            .expect("denetim");
    assert_eq!(details["operator"], "pilot-ops");
    assert_eq!(details["minimum_version"], "2.0.0");
    let versions = admin::list_app_versions(&pool).await.expect("liste");
    assert_eq!(versions.len(), 1);
}
