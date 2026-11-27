use std::{net::SocketAddr, sync::Arc, time::Duration};

use shedu_api::{
    AppState,
    auth::rate_limit,
    config::{Config, Environment},
    db,
    sms::{DevConsoleSms, SmsSender},
};
use sqlx::postgres::PgConnectOptions;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env()?;

    // Üretim için SMS sağlayıcısı henüz yok: güvensiz bir yedekle başlamak yerine dur (KEY-01).
    let sms: Arc<dyn SmsSender> = match config.environment {
        Environment::Development => Arc::new(DevConsoleSms),
        Environment::Production => {
            return Err("üretim için SMS sağlayıcısı yapılandırılmadı; API başlatılmadı".into());
        }
    };

    let options: PgConnectOptions = config.database_url.parse()?;
    let pool = db::connect(options, config.database_role.clone()).await?;
    let mut state = AppState::new(pool.clone(), &config.jwt_secret, &config.hmac_secret, sms)
        .map_err(|_| "uygulama durumu kurulamadı")?;
    state.allowed_origins = config.allowed_origins.clone().into();
    state.start_event_listener();

    // Eski deneme sayacı pencerelerini saatte bir temizle.
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
            if let Ok(mut conn) = pool.acquire().await
                && let Err(error) = rate_limit::purge_old(&mut conn).await
            {
                tracing::warn!(?error, "deneme sayaçları temizlenemedi");
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(config.addr).await?;
    tracing::info!(addr = %config.addr, environment = ?config.environment, "shedu-api dinliyor");

    axum::serve(
        listener,
        shedu_api::router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("kapatılıyor");
    })
    .await?;

    Ok(())
}
