//! Shedu panel gateway.
//!
//! Panellerle bağlantı kuran, gelen ham veriyi çözen ve onaylanmış komutları panele ileten servis.
//! Hedef panellerin protokolü henüz belli değil (bkz. `docs/acik-sorular.md`, soru 1); protokol
//! netleşene kadar bu ikili yalnızca bir yer tutucudur.

use tracing_subscriber::EnvFilter;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::warn!(
        "shedu-gateway henüz uygulanmadı: panel protokolü belirlenince eklenecek (docs/acik-sorular.md)"
    );
}
