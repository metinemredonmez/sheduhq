//! Veritabanı bağlantısı.

use std::time::Duration;

use sqlx::{
    PgConnection, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use uuid::Uuid;

/// Havuz kurar. `role` verilmişse her yeni bağlantı bu role geçer; uygulama hiçbir zaman RLS'yi
/// aşan bir rolle çalışmaz (AZ-02). Rol adı SQL'e metin olarak eklenmez, parametre olarak gider.
pub fn pool_options(role: Option<String>) -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(20)
        .acquire_timeout(Duration::from_secs(5))
        .after_connect(move |conn, _meta| {
            let role = role.clone();
            Box::pin(async move {
                if let Some(role) = role {
                    sqlx::query("SELECT set_config('role', $1, false)")
                        .bind(role)
                        .execute(&mut *conn)
                        .await?;
                }
                Ok(())
            })
        })
}

pub async fn connect(
    options: PgConnectOptions,
    role: Option<String>,
) -> Result<PgPool, sqlx::Error> {
    pool_options(role).connect_with(options).await
}

/// İşlem boyunca geçerli kullanıcı ve kiracı bağlamını ayarlar (`SET LOCAL` eşdeğeri).
/// Yalnızca bir işlem (transaction) içinde çağrılmalıdır.
pub async fn set_context(
    conn: &mut PgConnection,
    user_id: Option<Uuid>,
    organization_id: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('app.user_id', $1, true), set_config('app.org_id', $2, true)")
        .bind(user_id.map(|id| id.to_string()).unwrap_or_default())
        .bind(organization_id.map(|id| id.to_string()).unwrap_or_default())
        .execute(conn)
        .await?;
    Ok(())
}

/// Bağlantı ayarı TLS ile sunucu sertifikasını ve ana makine adını doğruluyor mu? (NET-01)
/// Bağlantı dizgesindeki metne değil, ayrıştırılmış etkin ayara bakılır: tekrarlanan `sslmode`,
/// başka bir parametrenin içindeki metin veya `PGSSLMODE` ortam değişkeni sonucu yanıltamaz.
/// Üretim ve yönetim bağlantısı yalnızca `verify-full` ile kurulur; `require` sertifikayı
/// doğrulamaz (araya giren sunucuyu fark etmez).
pub fn verifies_server_identity(options: &PgConnectOptions) -> bool {
    matches!(options.get_ssl_mode(), PgSslMode::VerifyFull)
}

/// Bağlantıyı kuran ikili: her biri yalnızca kendi veritabanı rolüyle çalışır (AZ-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    /// HTTP API: `shedu_app` rolü; yönetim rolünün yetkileri olmamalı.
    Api,
    /// Yönetim aracı: `shedu_admin` rolü.
    Admin,
}

/// Bağlantı rolü RLS'yi aşıyorsa dönen hata.
#[derive(Debug)]
pub struct PrivilegeError(String);

impl std::fmt::Display for PrivilegeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PrivilegeError {}

/// Bağlantının RLS'yi aşmayan ve ikiliye ait rolle çalıştığını doğrular (AZ-02, AZ-05, EXC-01).
/// Süper kullanıcı, BYPASSRLS yetkili rol ve tabloların sahibi (veya sahibin yetkilerini taşıyan
/// rol) RLS'den muaftır; kiracı izolasyonu bu durumda yalnızca sorgu filtrelerine kalır. Ayrıca
/// API yalnızca uygulama rolüyle (yönetim rolünün yetkileri olmadan), yönetim aracı yalnızca
/// yönetim rolüyle başlar.
pub async fn verify_least_privilege(pool: &PgPool, service: Service) -> Result<(), PrivilegeError> {
    let row: Result<(String, bool, bool, i64, bool, bool), sqlx::Error> = sqlx::query_as(
        "SELECT current_user::text, r.rolsuper, r.rolbypassrls,
                (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = 'public' AND c.relkind = 'r'
                    AND pg_has_role(current_user, c.relowner, 'USAGE')),
                pg_has_role(current_user, 'shedu_app', 'MEMBER'),
                pg_has_role(current_user, 'shedu_admin', 'MEMBER')
           FROM pg_roles r WHERE r.rolname = current_user",
    )
    .fetch_one(pool)
    .await;
    let (role, superuser, bypass, owned, app, admin) =
        row.map_err(|e| PrivilegeError(format!("veritabanı rolü denetlenemedi: {e}")))?;
    if superuser || bypass || owned > 0 {
        return Err(PrivilegeError(format!(
            "veritabanı rolü '{role}' RLS'yi aşıyor (süper kullanıcı, BYPASSRLS veya tablo sahibi); \
             SHEDU_DB_ROLE=shedu_app ile uygulama rolüne geçin"
        )));
    }
    match service {
        Service::Api if !app || admin => Err(PrivilegeError(format!(
            "API veritabanı rolü '{role}' uygulama rolü değil veya yönetim rolünün yetkilerini \
             taşıyor; SHEDU_DB_ROLE=shedu_app kullanın"
        ))),
        Service::Admin if !admin => Err(PrivilegeError(format!(
            "yönetim aracının veritabanı rolü '{role}' yönetim rolü değil; \
             SHEDU_ADMIN_DB_ROLE=shedu_admin kullanın"
        ))),
        _ => Ok(()),
    }
}
