//! Davet, üyelik ve panel yetkisi yönetimi entegrasyon testleri (gerçek PostgreSQL, uygulama
//! rolüyle). Her senaryoda önce meşru işlem çalıştırılır, sonra tek değişken değiştirilir; durum
//! kodu, yanıt ve veritabanındaki etki birlikte doğrulanır.
#![cfg(feature = "db-tests")]

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use uuid::Uuid;

const INVITEE: &str = "+905557776655";
const ADMIN_PHONE: &str = "+905554443322";
const OUTSIDER: &str = "+905553332211";
const SECOND: &str = "+905552221100";
const THIRD: &str = "+905551119988";

fn key() -> String {
    format!("test-{}", Uuid::new_v4().simple())
}

async fn invite(
    app: &TestApp,
    access: &str,
    org: &str,
    phone: &str,
    role: &str,
) -> (StatusCode, Value) {
    app.post_auth(
        &format!("/v1/organizations/{org}/invitations"),
        json!({ "phone": phone, "role": role }),
        access,
    )
    .await
}

/// Bekleyen davetin kimliği (davet edilen kişinin gözünden).
async fn my_invitation(app: &TestApp, access: &str, org: &str) -> Option<String> {
    let (status, body) = app.get("/v1/invitations", access).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["invitations"]
        .as_array()
        .expect("liste")
        .iter()
        .find(|i| i["organization_id"] == org)
        .map(|i| s(i, "id"))
}

/// Davet eder, kişi kayıt olur ve kabul eder; (access token, kullanıcı kimliği) döner.
async fn join(app: &TestApp, by: &str, org: &str, phone: &str, role: &str) -> (String, String) {
    let (status, body) = invite(app, by, org, phone, role).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (access, user_id, _) = app.user(phone).await;
    let id = my_invitation(app, &access, org).await.expect("davet");
    let (status, body) = app
        .post_auth(&format!("/v1/invitations/{id}/accept"), json!({}), &access)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (access, user_id)
}

async fn role_in_db(app: &TestApp, org: &str, user: &str) -> Option<String> {
    sqlx::query_as::<_, (String,)>(
        "SELECT role FROM memberships WHERE organization_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(org)
    .bind(user)
    .fetch_optional(&app.admin)
    .await
    .expect("sorgu")
    .map(|(r,)| r)
}

async fn audit_count(app: &TestApp, action: &str, outcome: &str) -> i64 {
    sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM audit_log WHERE action = $1 AND outcome = $2")
        .bind(action)
        .bind(outcome)
        .fetch_one(&app.admin)
        .await
        .expect("sorgu")
        .0
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

async fn command(
    app: &TestApp,
    access: &str,
    org: &str,
    panel: &str,
    partition: &str,
    kind: &str,
) -> (StatusCode, Value) {
    app.post_auth(
        &format!("/v1/organizations/{org}/panels/{panel}/commands"),
        json!({ "partition_id": partition, "kind": kind, "idempotency_key": key() }),
        access,
    )
    .await
}

async fn wait_succeeded(app: &TestApp, access: &str, org: &str, id: &str) {
    for _ in 0..100 {
        let (_, body) = app
            .get(&format!("/v1/organizations/{org}/commands/{id}"), access)
            .await;
        if body["status"] == "succeeded" {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("komut tamamlanmadı");
}

fn full_grant(panel: &str, partition: Option<&str>) -> Value {
    json!({
        "panel_id": panel, "partition_id": partition,
        "can_view_events": true, "can_arm": true, "can_disarm": true, "can_bypass": false,
        "always_open": true
    })
}

// ---------------------------------------------------------------------------------------------
// Davetler
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn invitation_is_bound_to_the_phone_and_accepted_once(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (owner, owner_id, org) = app.user(PHONE).await;

    let (status, body) = invite(&app, &owner, &org, INVITEE, "member").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(
        !body.to_string().contains(INVITEE),
        "yanıtta numaranın tamamı olmamalı"
    );

    // SMS gider; kullanıcının yazdığı metin (organizasyon adı) ve bağlantı/kod içermez.
    let mut sms = Vec::new();
    for _ in 0..100 {
        sms = app.sms.messages_to(INVITEE);
        if !sms.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(sms.len(), 1, "davet SMS'i gitmeli");
    assert!(!sms[0].contains("Ayşe"), "SMS'te organizasyon adı olmamalı");
    assert!(!sms[0].contains("http"), "SMS'te bağlantı olmamalı");
    assert!(
        !sms[0].chars().any(|c| c.is_ascii_digit()),
        "SMS'te kod olmamalı"
    );

    // Başka numarayla kayıtlı biri daveti göremez, kimliğini bilse de kabul edemez.
    let (outsider, _, _) = app.user(OUTSIDER).await;
    assert_eq!(my_invitation(&app, &outsider, &org).await, None);
    let (invitee, invitee_id, _) = app.user(INVITEE).await;
    let id = my_invitation(&app, &invitee, &org)
        .await
        .expect("davet görünmeli");
    for action in ["accept", "decline"] {
        let (status, _) = app
            .post_auth(
                &format!("/v1/invitations/{id}/{action}"),
                json!({}),
                &outsider,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{action}");
    }

    let (_, mine) = app.get("/v1/invitations", &invitee).await;
    assert_eq!(mine["invitations"][0]["organization_name"], "Ayşe");
    assert_eq!(mine["invitations"][0]["role"], "member");

    let (status, body) = app
        .post_auth(&format!("/v1/invitations/{id}/accept"), json!({}), &invitee)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["organization_id"], org.as_str());
    assert_eq!(
        role_in_db(&app, &org, &invitee_id).await.as_deref(),
        Some("member")
    );

    // Tek kullanımlık: ikinci kabul ve ret çalışmaz; davet listeden düşer.
    for action in ["accept", "decline"] {
        let (status, _) = app
            .post_auth(
                &format!("/v1/invitations/{id}/{action}"),
                json!({}),
                &invitee,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{action}");
    }
    assert_eq!(my_invitation(&app, &invitee, &org).await, None);
    let (_, open) = app
        .get(&format!("/v1/organizations/{org}/invitations"), &owner)
        .await;
    assert_eq!(open["invitations"].as_array().map(Vec::len), Some(0));

    let (_, me) = app.get("/v1/me", &invitee).await;
    assert!(
        me["organizations"]
            .as_array()
            .expect("liste")
            .iter()
            .any(|o| o["id"] == org.as_str() && o["role"] == "member")
    );

    // Yönetici üyeleri maskelenmiş numarayla görür; üye listeyi göremez.
    let (status, members) = app
        .get(&format!("/v1/organizations/{org}/members"), &owner)
        .await;
    assert_eq!(status, StatusCode::OK);
    let list = members["members"].as_array().expect("liste");
    assert_eq!(list.len(), 2);
    assert_eq!(list[0]["user_id"], owner_id.as_str());
    assert_eq!(list[0]["is_you"], true);
    assert!(!members.to_string().contains(INVITEE));
    let (status, _) = app
        .get(&format!("/v1/organizations/{org}/members"), &invitee)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    assert_eq!(audit_count(&app, "invitation.created", "success").await, 1);
    assert_eq!(audit_count(&app, "invitation.accepted", "success").await, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn invitation_rules_follow_the_role_hierarchy(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;

    // Geçersiz istekler: numara, sahiplik daveti, fazladan alan.
    let (status, _) = invite(&app, &owner, &org, "05551112233", "member").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = invite(&app, &owner, &org, INVITEE, "owner").await;
    assert!(status.is_client_error(), "sahiplik davetle verilmemeli");
    let (status, _) = app
        .post_auth(
            &format!("/v1/organizations/{org}/invitations"),
            json!({ "phone": INVITEE, "role": "member", "organization_id": Uuid::new_v4() }),
            &owner,
        )
        .await;
    assert!(status.is_client_error(), "bilinmeyen alan reddedilmeli");

    // Aynı numaraya ikinci açık davet ve zaten üye olan numara.
    let (status, first) = invite(&app, &owner, &org, INVITEE, "member").await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, body) = invite(&app, &owner, &org, INVITEE, "admin").await;
    assert_eq!(
        (status, s(&body, "error")),
        (StatusCode::CONFLICT, "invitation_pending".into())
    );
    let (status, body) = invite(&app, &owner, &org, PHONE, "member").await;
    assert_eq!(
        (status, s(&body, "error")),
        (StatusCode::CONFLICT, "already_member".into())
    );

    // İptal edilen davet kabul edilemez; aynı numaraya yeniden davet gönderilebilir.
    let (status, _) = app
        .delete(
            &format!("/v1/organizations/{org}/invitations/{}", s(&first, "id")),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (invitee, _, _) = app.user(INVITEE).await;
    assert_eq!(my_invitation(&app, &invitee, &org).await, None);
    let (status, _) = app
        .post_auth(
            &format!("/v1/invitations/{}/accept", s(&first, "id")),
            json!({}),
            &invitee,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Yönetici yalnızca üye davet eder; sahibin yönetici davetini iptal edemez.
    let (admin, _) = join(&app, &owner, &org, ADMIN_PHONE, "admin").await;
    let (status, _) = invite(&app, &admin, &org, SECOND, "member").await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = invite(&app, &admin, &org, THIRD, "admin").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, owners_invite) = invite(&app, &owner, &org, THIRD, "admin").await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = app
        .delete(
            &format!(
                "/v1/organizations/{org}/invitations/{}",
                s(&owners_invite, "id")
            ),
            &admin,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Üye davet gönderemez ve davetleri göremez; reddedilen deneme denetim kaydına girer.
    let (member, _) = join(&app, &owner, &org, OUTSIDER, "member").await;
    let (status, _) = invite(&app, &member, &org, "+905550001122", "member").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = app
        .get(&format!("/v1/organizations/{org}/invitations"), &member)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(audit_count(&app, "invitation.create", "denied").await, 2);

    // Üye olmayan biri organizasyonun davetlerine dokunamaz; varlığı da belli olmaz.
    let (status, _) = invite(&app, &invitee, &org, "+905550001122", "member").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "../../migrations")]
async fn invitation_sms_to_one_number_is_limited(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    // Davet et, iptal et, yeniden davet et: aynı numaraya günde en fazla 3 davet SMS'i.
    for attempt in 1..=4 {
        let (status, body) = invite(&app, &owner, &org, INVITEE, "member").await;
        if attempt <= 3 {
            assert_eq!(status, StatusCode::CREATED, "{body}");
            let (status, _) = app
                .delete(
                    &format!("/v1/organizations/{org}/invitations/{}", s(&body, "id")),
                    &owner,
                )
                .await;
            assert_eq!(status, StatusCode::NO_CONTENT);
        } else {
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
        }
    }
    // Davet sayacı kayıt kodunu engellemez.
    app.user(INVITEE).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn inviter_losing_rights_invalidates_open_invitations(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (owner, _, org) = app.user(PHONE).await;
    let (admin, admin_id) = join(&app, &owner, &org, ADMIN_PHONE, "admin").await;

    // API yolu: yönetici üyeliğe düşürülünce gönderdiği açık davetler iptal edilir.
    let (status, _) = invite(&app, &admin, &org, INVITEE, "member").await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = app
        .patch(
            &format!("/v1/organizations/{org}/members/{admin_id}"),
            json!({ "role": "member" }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (invitee, _, _) = app.user(INVITEE).await;
    assert_eq!(my_invitation(&app, &invitee, &org).await, None);

    // İkinci bariyer: rol API dışında düşürülse de (iptal çalışmadı) kabul anında yeniden
    // doğrulanır ve davet geçersiz olur.
    sqlx::query("UPDATE memberships SET role = 'admin' WHERE user_id = $1::uuid AND organization_id = $2::uuid")
        .bind(&admin_id)
        .bind(&org)
        .execute(&app.admin)
        .await
        .expect("rol");
    let (status, _) = invite(&app, &admin, &org, SECOND, "member").await;
    assert_eq!(status, StatusCode::CREATED);
    sqlx::query("UPDATE memberships SET role = 'member' WHERE user_id = $1::uuid AND organization_id = $2::uuid")
        .bind(&admin_id)
        .bind(&org)
        .execute(&app.admin)
        .await
        .expect("rol");
    let (second, second_id, _) = app.user(SECOND).await;
    let id = my_invitation(&app, &second, &org)
        .await
        .expect("davet hâlâ açık");
    let (status, _) = app
        .post_auth(&format!("/v1/invitations/{id}/accept"), json!({}), &second)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(role_in_db(&app, &org, &second_id).await, None);
}

// ---------------------------------------------------------------------------------------------
// Roller ve üyelik
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn role_changes_respect_the_hierarchy(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (owner, owner_id, org) = app.user(PHONE).await;
    let (admin, admin_id) = join(&app, &owner, &org, ADMIN_PHONE, "admin").await;
    let (member, member_id) = join(&app, &owner, &org, INVITEE, "member").await;
    let path = |user: &str| format!("/v1/organizations/{org}/members/{user}");

    // Yönetici kimseyi yönetici yapamaz, sahibe ve kendine dokunamaz.
    let (status, _) = app
        .patch(&path(&member_id), json!({ "role": "admin" }), &admin)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        role_in_db(&app, &org, &member_id).await.as_deref(),
        Some("member")
    );
    let (status, _) = app
        .patch(&path(&owner_id), json!({ "role": "member" }), &admin)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = app
        .patch(&path(&admin_id), json!({ "role": "member" }), &admin)
        .await;
    assert_eq!(
        (status, s(&body, "error")),
        (StatusCode::FORBIDDEN, "cannot_change_self".into())
    );
    // Sahip kendi rolünü değiştiremez; kimse sahiplik atayamaz; üye hiçbir rolü değiştiremez.
    let (status, _) = app
        .patch(&path(&owner_id), json!({ "role": "admin" }), &owner)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = app
        .patch(&path(&member_id), json!({ "role": "owner" }), &owner)
        .await;
    assert!(status.is_client_error());
    let (status, _) = app
        .patch(&path(&admin_id), json!({ "role": "member" }), &member)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        role_in_db(&app, &org, &owner_id).await.as_deref(),
        Some("owner")
    );
    assert_eq!(audit_count(&app, "member.role_change", "denied").await, 3);

    // Sahip yükseltir ve düşürür; değişiklik bir sonraki istekte geçerlidir (SES-04).
    let (status, _) = app
        .patch(&path(&member_id), json!({ "role": "admin" }), &owner)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = app
        .get(&format!("/v1/organizations/{org}/members"), &member)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "yükseltilen üye hemen yönetici olmalı"
    );
    let (status, _) = app
        .patch(&path(&admin_id), json!({ "role": "member" }), &owner)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = app
        .get(&format!("/v1/organizations/{org}/members"), &admin)
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "düşürülen yönetici hemen yetkisini kaybetmeli"
    );
    assert_eq!(audit_count(&app, "member.role_changed", "success").await, 2);

    // Üye olmayan kişi: yönetici 404 alır.
    let (status, _) = app
        .patch(
            &path(&Uuid::new_v4().to_string()),
            json!({ "role": "member" }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "../../migrations")]
async fn removing_a_member_revokes_access_immediately(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (owner, owner_id, org) = app.user(PHONE).await;
    let (panel, _, garage) = demo(&app, &owner, &org).await;
    let (member, member_id) = join(&app, &owner, &org, INVITEE, "member").await;
    let (status, body) = app
        .post_auth(
            &format!("/v1/organizations/{org}/members/{member_id}/grants"),
            full_grant(&panel, Some(&garage)),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let detail = format!("/v1/organizations/{org}/panels/{panel}");
    let (status, _) = app.get(&detail, &member).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = command(&app, &member, &org, &panel, &garage, "arm_away").await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    wait_succeeded(&app, &member, &org, &s(&body, "id")).await;

    let (status, _) = app
        .delete(
            &format!("/v1/organizations/{org}/members/{member_id}"),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Aynı access token'la, hemen: panel, liste ve komut kapalı; yetki kaydı silindi.
    let (status, _) = app.get(&detail, &member).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = app
        .get(&format!("/v1/organizations/{org}/panels"), &member)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = command(&app, &member, &org, &panel, &garage, "disarm").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (grants,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM access_grants WHERE user_id = $1::uuid")
            .bind(&member_id)
            .fetch_one(&app.admin)
            .await
            .expect("sorgu");
    assert_eq!(grants, 0, "yetki kaydı silinmeli");
    let (_, me) = app.get("/v1/me", &member).await;
    assert!(
        !me["organizations"]
            .as_array()
            .expect("liste")
            .iter()
            .any(|o| o["id"] == org.as_str())
    );
    let (removed,): (Value,) = sqlx::query_as(
        "SELECT details FROM audit_log WHERE action = 'member.removed' AND outcome = 'success'",
    )
    .fetch_one(&app.admin)
    .await
    .expect("denetim");
    assert_eq!(removed["grants_removed"], 1);

    // Sahip ayrılamaz; üye kendisi ayrılabilir; üye başkasını çıkaramaz; yönetici yöneticiyi
    // ve sahibi çıkaramaz.
    let (status, body) = app
        .delete(
            &format!("/v1/organizations/{org}/members/{owner_id}"),
            &owner,
        )
        .await;
    assert_eq!(
        (status, s(&body, "error")),
        (StatusCode::CONFLICT, "owner_cannot_leave".into())
    );
    let (admin, _) = join(&app, &owner, &org, ADMIN_PHONE, "admin").await;
    let (_, admin2_id) = join(&app, &owner, &org, OUTSIDER, "admin").await;
    let (second, second_id) = join(&app, &owner, &org, SECOND, "member").await;
    let (_, third_id) = join(&app, &owner, &org, THIRD, "member").await;
    for (target, actor) in [
        (&third_id, &second),
        (&admin2_id, &admin),
        (&owner_id, &admin),
    ] {
        let (status, _) = app
            .delete(&format!("/v1/organizations/{org}/members/{target}"), actor)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(role_in_db(&app, &org, target).await.is_some());
    }
    let (status, _) = app
        .delete(
            &format!("/v1/organizations/{org}/members/{second_id}"),
            &second,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(role_in_db(&app, &org, &second_id).await, None);
    let (status, _) = app
        .delete(
            &format!("/v1/organizations/{org}/members/{third_id}"),
            &admin,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "yönetici üyeyi çıkarabilmeli"
    );
}

// ---------------------------------------------------------------------------------------------
// Panel yetkileri
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn grants_are_validated_scoped_and_take_effect(_: PgPoolOptions, connect: PgConnectOptions) {
    let app = app(connect).await;
    let (owner, owner_id, org) = app.user(PHONE).await;
    let (panel, home, garage) = demo(&app, &owner, &org).await;
    let (member, member_id) = join(&app, &owner, &org, INVITEE, "member").await;
    let (other, other_user_id, other_org) = app.user(OUTSIDER).await;
    let (other_panel, other_home, _) = demo(&app, &other, &other_org).await;
    let grants = |user: &str| format!("/v1/organizations/{org}/members/{user}/grants");

    // Üye kendine (veya başkasına) yetki veremez.
    let (status, _) = app
        .post_auth(&grants(&member_id), full_grant(&panel, None), &member)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(audit_count(&app, "grant.create", "denied").await, 1);

    // Gövdedeki ve yoldaki kimlikler organizasyon içinde doğrulanır (AZ-04).
    let (status, _) = app
        .post_auth(&grants(&other_user_id), full_grant(&panel, None), &owner)
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "üye olmayana yetki verilmemeli"
    );
    let (status, body) = app
        .post_auth(&grants(&owner_id), full_grant(&panel, None), &owner)
        .await;
    assert_eq!(
        (status, s(&body, "error")),
        (StatusCode::CONFLICT, "member_is_manager".into())
    );
    let (status, body) = app
        .post_auth(&grants(&member_id), full_grant(&other_panel, None), &owner)
        .await;
    assert_eq!(
        (status, s(&body, "error")),
        (StatusCode::UNPROCESSABLE_ENTITY, "unknown_panel".into())
    );
    let (status, body) = app
        .post_auth(
            &grants(&member_id),
            full_grant(&panel, Some(&other_home)),
            &owner,
        )
        .await;
    assert_eq!(
        (status, s(&body, "error")),
        (StatusCode::UNPROCESSABLE_ENTITY, "unknown_partition".into())
    );

    // Geçersiz içerik.
    let invalid = [
        (
            json!({ "windows": [{ "day": 8, "start_minute": 0, "end_minute": 60 }], "always_open": false }),
            "invalid_window",
        ),
        (
            json!({ "windows": [{ "day": 1, "start_minute": 60, "end_minute": 60 }], "always_open": false }),
            "invalid_window",
        ),
        (
            json!({ "windows": [{ "day": 1, "start_minute": 0, "end_minute": 60 }] }),
            "windows_with_always_open",
        ),
        (json!({ "can_view_events": false }), "actions_require_view"),
        (
            json!({ "expires_at": "2020-01-01T00:00:00Z" }),
            "expires_in_past",
        ),
    ];
    for (patch, code) in invalid {
        let mut body = full_grant(&panel, Some(&garage));
        for (k, v) in patch.as_object().expect("nesne") {
            body[k] = v.clone();
        }
        let (status, response) = app.post_auth(&grants(&member_id), body, &owner).await;
        assert_eq!(
            (status, s(&response, "error")),
            (StatusCode::BAD_REQUEST, code.into())
        );
    }
    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM access_grants")
        .fetch_one(&app.admin)
        .await
        .expect("sorgu");
    assert_eq!(count, 0, "reddedilen istekler yetki oluşturmamalı");

    // Geçerli yetki: yalnızca garaj, kurma ve kapatma, her zaman açık.
    let (status, created) = app
        .post_auth(
            &grants(&member_id),
            full_grant(&panel, Some(&garage)),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let grant_id = s(&created, "id");
    let (status, body) = app
        .post_auth(
            &grants(&member_id),
            full_grant(&panel, Some(&garage)),
            &owner,
        )
        .await;
    assert_eq!(
        (status, s(&body, "error")),
        (StatusCode::CONFLICT, "grant_exists".into())
    );

    let (status, body) = command(&app, &member, &org, &panel, &garage, "arm_away").await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    wait_succeeded(&app, &member, &org, &s(&body, "id")).await;
    let (status, _) = command(&app, &member, &org, &panel, &home, "arm_away").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "yetkisiz bölüm görünmemeli");

    // Üye kendi yetkisini görür, başkasınınkini göremez.
    let (status, mine) = app.get(&grants(&member_id), &member).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mine["grants"].as_array().map(Vec::len), Some(1));
    let (status, _) = app.get(&grants(&owner_id), &member).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Değiştirme: bugün olmayan bir günde pencere, kapatma yok. Kapsam değiştirilemez.
    let (today,): (i32,) =
        sqlx::query_as("SELECT extract(isodow FROM now() AT TIME ZONE 'Europe/Istanbul')::int")
            .fetch_one(&app.admin)
            .await
            .expect("gün");
    let other_day = today % 7 + 1;
    let terms = json!({
        "can_view_events": true, "can_arm": true, "can_disarm": false, "can_bypass": false,
        "always_open": false,
        "windows": [{ "day": other_day, "start_minute": 480, "end_minute": 1080 }]
    });
    let grant_path = format!("/v1/organizations/{org}/grants/{grant_id}");
    let mut moved = terms.clone();
    moved["user_id"] = json!(owner_id);
    let (status, _) = app.put(&grant_path, moved, &owner).await;
    assert!(status.is_client_error(), "kapsam alanı reddedilmeli");
    let (status, _) = app.put(&grant_path, terms.clone(), &member).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = app
        .put(
            &format!("/v1/organizations/{other_org}/grants/{grant_id}"),
            terms.clone(),
            &other,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "başka organizasyon yetkiye ulaşamamalı"
    );
    let (status, updated) = app.put(&grant_path, terms, &owner).await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["user_id"], member_id.as_str());
    assert_eq!(updated["windows"].as_array().map(Vec::len), Some(1));

    // Pencere kapalı: görebilir, kapatamaz ve kuramaz.
    let (status, _) = app
        .get(&format!("/v1/organizations/{org}/panels/{panel}"), &member)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = command(&app, &member, &org, &panel, &garage, "disarm").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Silme: panel hemen görünmez olur.
    let (status, _) = app.delete(&grant_path, &member).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = app.delete(&grant_path, &owner).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = app
        .get(&format!("/v1/organizations/{org}/panels/{panel}"), &member)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = app.delete(&grant_path, &owner).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    for action in ["grant.created", "grant.updated", "grant.deleted"] {
        assert_eq!(audit_count(&app, action, "success").await, 1, "{action}");
    }
}

// ---------------------------------------------------------------------------------------------
// Sahiplik devri
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn ownership_is_transferred_only_to_an_admin_after_reauth(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    let (owner, owner_id, org) = app.user(PHONE).await;
    let (admin, admin_id) = join(&app, &owner, &org, ADMIN_PHONE, "admin").await;
    let (_, member_id) = join(&app, &owner, &org, INVITEE, "member").await;
    let transfer = format!("/v1/organizations/{org}/ownership-transfer");
    let body = |to: &str, password: &str| json!({ "user_id": to, "password": password });

    // Sahip olmayan devredemez; devralan yönetici olmalı; kendine devredilmez.
    let (status, _) = app
        .post_auth(&transfer, body(&member_id, PASSWORD), &admin)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, response) = app
        .post_auth(&transfer, body(&member_id, PASSWORD), &owner)
        .await;
    assert_eq!(
        (status, s(&response, "error")),
        (StatusCode::CONFLICT, "target_must_be_admin".into())
    );
    let (status, _) = app
        .post_auth(&transfer, body(&owner_id, PASSWORD), &owner)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Yanlış parola: devir olmaz, deneme kaydedilir.
    let (status, response) = app
        .post_auth(&transfer, body(&admin_id, NEW_PASSWORD), &owner)
        .await;
    assert_eq!(
        (status, s(&response, "error")),
        (StatusCode::FORBIDDEN, "reauth_failed".into())
    );
    assert_eq!(
        role_in_db(&app, &org, &owner_id).await.as_deref(),
        Some("owner")
    );
    assert_eq!(
        audit_count(&app, "organization.ownership_transfer", "denied").await,
        2
    );

    // Önceki sahibin açık yönetici daveti devirle iptal edilir; üye daveti kalır.
    let (status, _) = invite(&app, &owner, &org, SECOND, "admin").await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = invite(&app, &owner, &org, THIRD, "member").await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, response) = app
        .post_auth(&transfer, body(&admin_id, PASSWORD), &owner)
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        role_in_db(&app, &org, &admin_id).await.as_deref(),
        Some("owner")
    );
    assert_eq!(
        role_in_db(&app, &org, &owner_id).await.as_deref(),
        Some("admin")
    );
    let (owners,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM memberships WHERE organization_id = $1::uuid AND role = 'owner'",
    )
    .bind(&org)
    .fetch_one(&app.admin)
    .await
    .expect("sorgu");
    assert_eq!(owners, 1);
    let (_, open) = app
        .get(&format!("/v1/organizations/{org}/invitations"), &admin)
        .await;
    let roles: Vec<&str> = open["invitations"]
        .as_array()
        .expect("liste")
        .iter()
        .filter_map(|i| i["role"].as_str())
        .collect();
    assert_eq!(roles, vec!["member"]);

    // Önceki sahip artık yönetici: yeni sahibe dokunamaz; yeni sahip onu yönetebilir.
    let (status, _) = app
        .patch(
            &format!("/v1/organizations/{org}/members/{admin_id}"),
            json!({ "role": "member" }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = app
        .delete(
            &format!("/v1/organizations/{org}/members/{admin_id}"),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = app
        .patch(
            &format!("/v1/organizations/{org}/members/{owner_id}"),
            json!({ "role": "member" }),
            &admin,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        audit_count(&app, "organization.ownership_transferred", "success").await,
        1
    );
}

// ---------------------------------------------------------------------------------------------
// Operatör
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn operator_sees_all_panels_but_controls_only_with_grants(
    _: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let app = app(connect).await;
    app.start_background().await;
    let (owner, _, org) = app.user(PHONE).await;

    // Ev organizasyonunda operatör olmaz.
    let (status, response) = invite(&app, &owner, &org, INVITEE, "operator").await;
    assert_eq!(
        (status, s(&response, "error")),
        (StatusCode::UNPROCESSABLE_ENTITY, "role_not_allowed".into())
    );
    let (_, member_id) = join(&app, &owner, &org, SECOND, "member").await;
    let (status, _) = app
        .patch(
            &format!("/v1/organizations/{org}/members/{member_id}"),
            json!({ "role": "operator" }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // İşletme organizasyonu.
    sqlx::query("UPDATE organizations SET kind = 'business' WHERE id = $1::uuid")
        .bind(&org)
        .execute(&app.admin)
        .await
        .expect("tür");
    // İşletmede sahip ve operatör personeldir: ikinci adım zorunlu (AUT-01).
    let (status, response) = app
        .get(&format!("/v1/organizations/{org}/panels"), &owner)
        .await;
    assert_eq!(
        (status, s(&response, "error")),
        (StatusCode::FORBIDDEN, "mfa_required".into())
    );
    app.enable_mfa(&owner).await;
    let (panel, home, garage) = demo(&app, &owner, &org).await;
    let (operator, operator_id) = join(&app, &owner, &org, INVITEE, "operator").await;
    let (status, _) = app
        .get(&format!("/v1/organizations/{org}/panels"), &operator)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    app.enable_mfa(&operator).await;
    let (status, _) = app
        .put(
            "/v1/devices/current/push-token",
            json!({ "token": "operator-device-token" }),
            &operator,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Yetki kaydı olmadan bütün panelleri, bölümleri, zonları ve olayları görür.
    let (_, panels) = app
        .get(&format!("/v1/organizations/{org}/panels"), &operator)
        .await;
    assert_eq!(panels.as_array().map(Vec::len), Some(1));
    let (status, detail) = app
        .get(
            &format!("/v1/organizations/{org}/panels/{panel}"),
            &operator,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["partitions"].as_array().map(Vec::len), Some(2));
    assert_eq!(detail["zones"].as_array().map(Vec::len), Some(5));
    assert!(detail.get("outputs").is_none(), "operatör çıkışları görmez");
    let (status, _) = app
        .get(
            &format!("/v1/organizations/{org}/panels/{panel}/events"),
            &operator,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Ama kuramaz, kimseyi yönetemez, yetki veremez.
    let (status, _) = command(&app, &operator, &org, &panel, &home, "arm_away").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = app
        .get(&format!("/v1/organizations/{org}/members"), &operator)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = invite(&app, &operator, &org, THIRD, "member").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = app
        .post_auth(
            &format!("/v1/organizations/{org}/members/{operator_id}/grants"),
            full_grant(&panel, None),
            &operator,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Yönetici garaj için yetki verince yalnızca garajı kurar.
    let (status, _) = app
        .post_auth(
            &format!("/v1/organizations/{org}/members/{operator_id}/grants"),
            full_grant(&panel, Some(&garage)),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, response) = command(&app, &operator, &org, &panel, &garage, "arm_away").await;
    assert_eq!(status, StatusCode::ACCEPTED, "{response}");
    wait_succeeded(&app, &operator, &org, &s(&response, "id")).await;
    let (status, _) = command(&app, &operator, &org, &panel, &home, "arm_away").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Alarm bildirimi operatöre gider; yetkisi olmayan üyeye gitmez.
    let (status, alarm) = app
        .post_auth(
            &format!("/v1/organizations/{org}/panels/{panel}/simulate-alarm"),
            json!({ "zone_number": 3 }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{alarm}");
    let event_id = alarm["event_id"].as_i64().expect("olay");
    let mut tokens = Vec::new();
    for _ in 0..150 {
        tokens = app
            .push
            .messages()
            .into_iter()
            .filter(|m| m.event_id == event_id)
            .map(|m| (m.token, m.user_id.to_string()))
            .collect();
        if !tokens.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert_eq!(
        tokens,
        vec![("operator-device-token".to_owned(), operator_id.clone())]
    );
    assert_ne!(operator_id, member_id);
}
