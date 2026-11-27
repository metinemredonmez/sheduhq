//! Platform yöneticisi işlemleri entegrasyon testleri (AZ-05, LOG-01, SES-04). Yönetici işlemleri
//! `shedu_admin` rolüyle, API istekleri uygulama rolüyle çalışır.
#![cfg(feature = "db-tests")]

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::{Value, json};
use shedu_api::{
    admin::{self, AdminError, NewOrganization, NewPanel, Operator, PanelLayout},
    db,
};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use uuid::Uuid;

const OWNER: &str = "+905557776655";
const OTHER: &str = "+905554443322";

async fn admin_pool(connect: PgConnectOptions) -> PgPool {
    db::pool_options(Some(admin::ADMIN_ROLE.into()))
        .max_connections(2)
        .connect_with(connect)
        .await
        .expect("yönetici bağlantısı")
}

fn operator() -> Operator {
    Operator::new("pilot-ops", "Pilot müşteri kurulumu, sözleşme 14").expect("işlemci")
}

fn layout() -> PanelLayout {
    serde_json::from_value(json!({
        "partitions": [{ "number": 1, "name": "Mağaza" }, { "number": 2, "name": "Depo" }],
        "zones": [
            { "number": 1, "name": "Giriş kapısı", "kind": "intrusion", "partitions": [1] },
            { "number": 2, "name": "Depo hareket", "kind": "intrusion", "partitions": [2] },
            { "number": 3, "name": "Duman", "kind": "fire", "partitions": [1, 2] }
        ]
    }))
    .expect("düzen")
}

fn new_panel<'a>(org: Uuid, serial: &'a str, layout: &'a PanelLayout) -> NewPanel<'a> {
    NewPanel {
        organization_id: org,
        name: "Merkez",
        brand: "acme",
        model: Some("X1"),
        device_serial: serial,
        layout,
    }
}

async fn audit_details(app: &TestApp, action: &str) -> Vec<Value> {
    sqlx::query_as::<_, (Value,)>("SELECT details FROM audit_log WHERE action = $1 ORDER BY id")
        .bind(action)
        .fetch_all(&app.admin)
        .await
        .expect("denetim")
        .into_iter()
        .map(|(d,)| d)
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn operator_opens_an_organization_and_the_owner_takes_over(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let pool = admin_pool(connect.clone()).await;
    let app = app(connect).await;
    let op = operator();

    let created = admin::create_organization(
        &pool,
        &op,
        NewOrganization {
            name: "Örnek Mağaza",
            kind: "business",
            owner_phone: OWNER,
            owner_name: "Ayşe Yılmaz",
        },
    )
    .await
    .expect("organizasyon");
    assert!(created.owner_created);
    let org = created.organization_id.to_string();
    let layout = layout();
    let panel = admin::add_panel(
        &pool,
        &op,
        new_panel(created.organization_id, "SN-1", &layout),
    )
    .await
    .expect("panel");

    // Sahip parolasını kendisi belirler (araç parola belirlemez), sonra girer.
    let (status, _) = app.login(OWNER, PASSWORD).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "parolasız hesapla giriş olmamalı"
    );
    let before = app.sms.messages_to(OWNER).len();
    let (status, _) = app
        .post("/v1/auth/password-reset/start", json!({ "phone": OWNER }))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let code = app.last_code(OWNER, before).await;
    let (status, body) = app
        .post(
            "/v1/auth/password-reset/complete",
            json!({ "phone": OWNER, "code": code, "new_password": PASSWORD }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, login) = app.login(OWNER, PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
    let owner = s(&login, "access_token");
    let (_, me) = app.get("/v1/me", &owner).await;
    assert!(
        me["organizations"]
            .as_array()
            .expect("liste")
            .iter()
            .any(|o| o["id"] == org.as_str() && o["role"] == "owner")
    );

    // İşletme sahibi personeldir: MFA'dan sonra paneli görür; panel çevrimdışı başlar.
    let panels = format!("/v1/organizations/{org}/panels");
    let (status, _) = app.get(&panels, &owner).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    app.enable_mfa(&owner).await;
    let (status, detail) = app.get(&format!("{panels}/{panel}"), &owner).await;
    assert_eq!(status, StatusCode::OK, "{detail}");
    assert_eq!(detail["partitions"].as_array().map(Vec::len), Some(2));
    assert_eq!(detail["zones"].as_array().map(Vec::len), Some(3));
    assert_eq!(detail["connectivity"], "offline");
    let partition = s(&detail["partitions"][0], "id");
    let (status, body) = app
        .post_auth(
            &format!("{panels}/{panel}/commands"),
            json!({ "partition_id": partition, "kind": "arm_away",
                    "idempotency_key": format!("test-{}", Uuid::new_v4().simple()) }),
            &owner,
        )
        .await;
    assert_eq!(
        (status, s(&body, "error")),
        (StatusCode::CONFLICT, "panel_offline".into()),
        "gateway bağlanmadan komut kabul edilmemeli"
    );

    // Kayıtlı bir kullanıcı da sahip yapılabilir; yeni hesap açılmaz.
    let (_, other_id, _) = app.user(OTHER).await;
    let second = admin::create_organization(
        &pool,
        &op,
        NewOrganization {
            name: "İkinci Şube",
            kind: "business",
            owner_phone: OTHER,
            owner_name: "",
        },
    )
    .await
    .expect("organizasyon");
    assert!(!second.owner_created);
    assert_eq!(second.owner_user_id.to_string(), other_id);

    // Liste ve ayrıntı.
    let all = admin::list_organizations(&pool).await.expect("liste");
    assert!(
        all.iter()
            .any(|o| o.id == created.organization_id && o.panels == 1)
    );
    let (summary, members, panels) = admin::show_organization(&pool, created.organization_id)
        .await
        .expect("ayrıntı");
    assert_eq!((summary.members, members.len(), panels.len()), (1, 1, 1));

    // Denetim kaydı: kim, neden; numara yok.
    for action in ["admin.organization_created", "admin.panel_added"] {
        let details = audit_details(&app, action).await;
        assert!(!details.is_empty(), "{action}");
        for d in &details {
            assert_eq!(d["operator"], "pilot-ops");
            assert_eq!(d["reason"], "Pilot müşteri kurulumu, sözleşme 14");
            assert!(!d.to_string().contains(OWNER) && !d.to_string().contains(OTHER));
        }
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn admin_rules_and_role_separation(_: PgPoolOptions, connect: PgConnectOptions) {
    let pool = admin_pool(connect.clone()).await;
    let app = app(connect).await;
    let op = operator();
    let org = |kind: &'static str, phone: &'static str, name: &'static str| NewOrganization {
        name: "Kurum",
        kind,
        owner_phone: phone,
        owner_name: name,
    };

    for bad in [
        org("magaza", OWNER, "Ayşe"),
        org("business", "05557776655", "Ayşe"),
        org("business", OWNER, ""),
    ] {
        assert!(matches!(
            admin::create_organization(&pool, &op, bad).await,
            Err(AdminError::Invalid(_))
        ));
    }
    let created = admin::create_organization(&pool, &op, org("business", OWNER, "Ayşe"))
        .await
        .expect("organizasyon");
    let id = created.organization_id;
    let layout = layout();

    assert!(matches!(
        admin::add_panel(&pool, &op, new_panel(Uuid::new_v4(), "SN-1", &layout)).await,
        Err(AdminError::NotFound(_))
    ));
    let mut reserved = new_panel(id, "SN-1", &layout);
    reserved.brand = "Shedu-Demo";
    assert!(matches!(
        admin::add_panel(&pool, &op, reserved).await,
        Err(AdminError::Invalid(_))
    ));
    admin::add_panel(&pool, &op, new_panel(id, "SN-1", &layout))
        .await
        .expect("panel");
    assert!(matches!(
        admin::add_panel(&pool, &op, new_panel(id, "SN-1", &layout)).await,
        Err(AdminError::Conflict(_))
    ));
    let (panels,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM panels WHERE organization_id = $1")
            .bind(id)
            .fetch_one(&app.admin)
            .await
            .expect("sorgu");
    assert_eq!(panels, 1, "başarısız ekleme iz bırakmamalı");

    // API'nin rolü bütün organizasyonları listeleyemez (AZ-05).
    let denied = sqlx::query("SELECT * FROM admin_organizations()")
        .fetch_all(&app.pool)
        .await
        .expect_err("uygulama rolü listeleyememeli");
    assert_eq!(
        denied.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501")
    );
    assert!(admin::list_organizations(&app.pool).await.is_err());
    assert!(admin::list_organizations(&pool).await.is_ok());
}

#[sqlx::test(migrations = "../../migrations")]
async fn disabling_a_user_cuts_access_immediately(_: PgPoolOptions, connect: PgConnectOptions) {
    let pool = admin_pool(connect.clone()).await;
    let app = app(connect).await;
    let op = operator();
    let (access, user_id, _) = app.user(OWNER).await;
    let (status, _) = app
        .put(
            "/v1/devices/current/push-token",
            json!({ "token": "device-1" }),
            &access,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let disabled = admin::set_user_active(&pool, &op, OWNER, false)
        .await
        .expect("kapatma");
    assert_eq!(disabled.to_string(), user_id);
    let (status, _) = app.get("/v1/me", &access).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "açık oturum hemen kapanmalı"
    );
    let (status, _) = app.login(OWNER, PASSWORD).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (tokens,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM user_devices WHERE user_id = $1::uuid AND push_token IS NOT NULL",
    )
    .bind(&user_id)
    .fetch_one(&app.admin)
    .await
    .expect("sorgu");
    assert_eq!(tokens, 0);
    assert!(matches!(
        admin::set_user_active(&pool, &op, OWNER, false).await,
        Err(AdminError::Conflict(_))
    ));

    admin::set_user_active(&pool, &op, OWNER, true)
        .await
        .expect("açma");
    let (status, _) = app.login(OWNER, PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
    assert!(matches!(
        admin::set_user_active(&pool, &op, OWNER, true).await,
        Err(AdminError::Conflict(_))
    ));
    assert!(matches!(
        admin::set_user_active(&pool, &op, OTHER, false).await,
        Err(AdminError::NotFound(_))
    ));
    let details = audit_details(&app, "admin.user_disabled").await;
    assert_eq!(details.len(), 1);
    assert_eq!(details[0]["operator"], "pilot-ops");
    assert_eq!(audit_details(&app, "admin.user_enabled").await.len(), 1);
}
