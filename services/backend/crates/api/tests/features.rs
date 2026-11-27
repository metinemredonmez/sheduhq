//! Özellik bayrakları entegrasyon testleri: yönetici değiştirir, organizasyon üyesi okur.
#![cfg(feature = "db-tests")]

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::{Value, json};
use shedu_api::{
    admin::{self, AdminError, FlagChange, Operator},
    db,
};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use uuid::Uuid;

const OTHER: &str = "+905554443322";
const MEMBER: &str = "+905557776655";
const OUTSIDER: &str = "+905553332211";

async fn admin_pool(connect: PgConnectOptions) -> PgPool {
    db::pool_options(Some(admin::ADMIN_ROLE.into()))
        .max_connections(2)
        .connect_with(connect)
        .await
        .expect("yönetici bağlantısı")
}

fn operator() -> Operator {
    Operator::new("pilot-ops", "Kamera özelliği pilot denemesi").expect("işlemci")
}

async fn features(app: &TestApp, access: &str, org: &str) -> (StatusCode, Value) {
    app.get(&format!("/v1/organizations/{org}/features"), access)
        .await
}

async fn camera(app: &TestApp, access: &str, org: &str) -> bool {
    let (status, body) = features(app, access, org).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["features"]["camera_live"].as_bool().expect("bayrak")
}

fn change(enabled: bool, rollout: Option<i16>, description: Option<&str>) -> FlagChange<'_> {
    FlagChange {
        key: "camera_live",
        description,
        enabled,
        rollout_percent: rollout,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn flags_follow_overrides_rollout_and_kill_switch(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let pool = admin_pool(connect.clone()).await;
    let app = app(connect).await;
    let op = operator();
    let (a, _, org_a) = app.user(PHONE).await;
    let (b, _, org_b) = app.user(OTHER).await;
    let (org_a_id, org_b_id): (Uuid, Uuid) =
        (org_a.parse().expect("id"), org_b.parse().expect("id"));

    // Tanımsız bayrak listede yoktur.
    let (_, empty) = features(&app, &a, &org_a).await;
    assert_eq!(empty["features"], json!({}));

    // Pilot: açık ama yüzde 0; yalnızca organizasyon ayarı olanlarda açık.
    assert!(
        admin::set_flag(&pool, &op, change(true, Some(0), Some("Canlı kamera")))
            .await
            .expect("bayrak")
    );
    assert!(!camera(&app, &a, &org_a).await);
    admin::set_flag_override(&pool, &op, "camera_live", org_a_id, Some(true))
        .await
        .expect("ayar");
    assert!(camera(&app, &a, &org_a).await);
    assert!(!camera(&app, &b, &org_b).await);

    // Organizasyon üyesi aynı değeri görür; üye olmayan göremez.
    let (status, invitation) = app
        .post_auth(
            &format!("/v1/organizations/{org_a}/invitations"),
            json!({ "phone": MEMBER, "role": "member" }),
            &a,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{invitation}");
    let (member, _, _) = app.user(MEMBER).await;
    let (_, mine) = app.get("/v1/invitations", &member).await;
    let id = s(&mine["invitations"][0], "id");
    app.post_auth(&format!("/v1/invitations/{id}/accept"), json!({}), &member)
        .await;
    assert!(camera(&app, &member, &org_a).await);
    let (outsider, _, _) = app.user(OUTSIDER).await;
    assert_eq!(
        features(&app, &outsider, &org_a).await.0,
        StatusCode::NOT_FOUND
    );

    // Herkese açılınca B de görür; organizasyon ayarı kapatabilir.
    assert!(
        !admin::set_flag(&pool, &op, change(true, Some(100), None))
            .await
            .expect("bayrak")
    );
    assert!(camera(&app, &b, &org_b).await);
    admin::set_flag_override(&pool, &op, "camera_live", org_b_id, Some(false))
        .await
        .expect("ayar");
    assert!(!camera(&app, &b, &org_b).await);
    admin::set_flag_override(&pool, &op, "camera_live", org_b_id, None)
        .await
        .expect("ayar");
    assert!(camera(&app, &b, &org_b).await);

    // Acil kapatma organizasyon ayarını da ezer.
    admin::set_flag(&pool, &op, change(false, None, None))
        .await
        .expect("bayrak");
    assert!(
        !camera(&app, &a, &org_a).await,
        "kapalı bayrak pilotta da kapalı"
    );
    assert!(!camera(&app, &b, &org_b).await);

    // Liste ve denetim kaydı.
    let (flags, overrides) = admin::list_flags(&pool).await.expect("liste");
    assert_eq!(flags.len(), 1);
    assert_eq!(flags[0].rollout_percent, 100);
    assert_eq!(overrides.len(), 1);
    let count = |action: &'static str| {
        let app = &app;
        async move {
            sqlx::query_as::<_, (i64,)>(
                "SELECT count(*) FROM audit_log WHERE action = $1 AND details->>'operator' = 'pilot-ops'",
            )
            .bind(action)
            .fetch_one(&app.admin)
            .await
            .expect("sorgu")
            .0
        }
    };
    assert_eq!(count("admin.flag_updated").await, 3);
    assert_eq!(count("admin.flag_override_set").await, 3);
}

#[sqlx::test(migrations = "../../migrations")]
async fn flag_rules_and_role_separation(_: PgPoolOptions, connect: PgConnectOptions) {
    let pool = admin_pool(connect.clone()).await;
    let app = app(connect).await;
    let op = operator();
    let (_, _, org) = app.user(PHONE).await;
    let org: Uuid = org.parse().expect("id");

    let invalid = |r: Result<bool, AdminError>| matches!(r, Err(AdminError::Invalid(_)));
    assert!(
        invalid(admin::set_flag(&pool, &op, change(true, None, None)).await),
        "açıklamasız yeni bayrak"
    );
    assert!(invalid(
        admin::set_flag(&pool, &op, change(true, Some(101), Some("x"))).await
    ));
    let mut bad_key = change(true, None, Some("x"));
    bad_key.key = "Kamera-Canlı";
    assert!(invalid(admin::set_flag(&pool, &op, bad_key).await));
    assert!(matches!(
        admin::set_flag_override(&pool, &op, "camera_live", org, Some(true)).await,
        Err(AdminError::NotFound(_))
    ));
    admin::set_flag(&pool, &op, change(true, None, Some("Canlı kamera")))
        .await
        .expect("bayrak");
    assert!(matches!(
        admin::set_flag_override(&pool, &op, "camera_live", Uuid::new_v4(), Some(true)).await,
        Err(AdminError::NotFound(_))
    ));

    // API'nin rolü bayrak yazamaz, bütün organizasyon ayarlarını okuyamaz.
    for statement in [
        "INSERT INTO feature_flags (key, description, enabled) VALUES ('yeni', 'x', true)",
        "UPDATE feature_flags SET enabled = false",
        "SELECT * FROM admin_flag_overrides()",
    ] {
        let error = sqlx::query(statement)
            .execute(&app.pool)
            .await
            .expect_err(statement);
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("42501"),
            "{statement}"
        );
    }
    let (enabled,): (bool,) =
        sqlx::query_as("SELECT enabled FROM feature_flags WHERE key = 'camera_live'")
            .fetch_one(&app.admin)
            .await
            .expect("sorgu");
    assert!(enabled);
}
