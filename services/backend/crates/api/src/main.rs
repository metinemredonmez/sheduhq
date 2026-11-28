use std::{net::SocketAddr, sync::Arc, time::Duration};

use shedu_api::{
    AppState,
    auth::rate_limit,
    config::{Config, Environment},
    db,
    providers::{PlatformPush, apns::Apns, fcm::Fcm, iletimerkezi::IletiMerkezi},
    push::{DevConsolePush, PushSender},
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

    // Sağlayıcılar açılışta kurulur; anahtar dosyası okunamazsa veya geçersizse API başlamaz.
    // Üretimde üçü de zorunludur (yapılandırma bunu denetler); geliştirmede verilmeyen sağlayıcının
    // yerine konsola yazan gönderici kullanılır (KEY-01, EXC-01).
    let production = matches!(config.environment, Environment::Production);
    if production && (config.sms.is_none() || config.apns.is_none() || config.fcm.is_none()) {
        return Err(
            "üretim için SMS ve push sağlayıcıları yapılandırılmadı; API başlatılmadı".into(),
        );
    }
    let sms: Arc<dyn SmsSender> = match &config.sms {
        Some(settings) => Arc::new(IletiMerkezi::new(settings)?),
        None => Arc::new(DevConsoleSms),
    };
    let push: Arc<dyn PushSender> = if config.apns.is_none() && config.fcm.is_none() {
        Arc::new(DevConsolePush)
    } else {
        Arc::new(PlatformPush {
            apns: config.apns.as_ref().map(Apns::new).transpose()?,
            fcm: config.fcm.as_ref().map(Fcm::new).transpose()?,
        })
    };

    let options: PgConnectOptions = config.database_url.parse()?;
    let pool = db::connect(options, config.database_role.clone()).await?;
    // RLS'yi aşan bir rolle (süper kullanıcı, tablo sahibi) başlamak yerine dur (AZ-02, EXC-01).
    db::verify_least_privilege(&pool, db::Service::Api).await?;
    // Üretimde bağlantıyı açan giriş rolü de denetlenir (Y08).
    if matches!(config.environment, Environment::Production) {
        db::verify_login_role(&pool, db::Service::Api).await?;
    }
    let mut state = AppState::new(
        pool.clone(),
        &config.jwt_secret,
        &config.hmac_secret,
        (&config.data_key, config.data_key_version),
        sms,
    )
    .map_err(|_| "uygulama durumu kurulamadı")?;
    state.allowed_origins = config.allowed_origins.clone().into();
    state.push = push;
    state.push_content = config.push_content;
    if let Some(ai) = &config.ai {
        let client = shedu_api::ai::AiClient::new(&ai.url, &ai.token)
            .map_err(|_| "AI servisi istemcisi kurulamadı")?
            .with_global_budget(i64::from(ai.daily_budget_usd) * 1_000_000);
        state.ai = Some(Arc::new(client));
    }
    state.start_event_listener();
    state.start_push_dispatcher();
    state.start_erasure_job();
    state.start_simulator_recovery();

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
