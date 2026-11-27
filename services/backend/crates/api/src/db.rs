//! Veritabanı bağlantısı.

use std::time::Duration;

use sqlx::{
    PgConnection, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
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
