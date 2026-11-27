use std::net::SocketAddr;

use tracing_subscriber::EnvFilter;

/// Varsayılan olarak yalnızca yerel arayüzü dinler; dışarı açmak bilinçli bir ayar olmalıdır (OPS-01).
const DEFAULT_ADDR: &str = "127.0.0.1:8080";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let addr: SocketAddr = std::env::var("SHEDU_API_ADDR")
        .unwrap_or_else(|_| DEFAULT_ADDR.to_owned())
        .parse()?;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "shedu-api dinliyor");

    axum::serve(listener, shedu_api::router())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("kapatılıyor");
        })
        .await?;

    Ok(())
}
