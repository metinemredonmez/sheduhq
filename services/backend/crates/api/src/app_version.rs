//! Zorunlu güncelleme kontrolü.
//!
//! - `GET /v1/app-version?platform=ios&version=1.4.2`: giriş gerektirmez; uygulama açılışta
//!   sorar ve "güncel", "güncelleme önerilir" veya "güncelleme zorunlu" yanıtını alır.
//! - İstemci `X-Shedu-App: ios/1.4.2` başlığı gönderiyorsa API, desteklenen en düşük sürümün
//!   altındaki istemcinin bütün isteklerini 426 ile reddeder (kontrol ucu hariç; eski uygulama
//!   güncellemesi gerektiğini öğrenebilmeli). Başlık göndermeyen istemciler (web arka yüzü,
//!   araçlar) etkilenmez. Bu bir güvenlik sınırı değildir, başlık taklit edilebilir; amaç dürüst
//!   eski istemcileri bilinen hatalı sürümlerden uzaklaştırmaktır.
//! - Politika veritabanındadır (migration 0013), yalnızca yönetici değiştirir; API kısa süreli
//!   önbellekle okur.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use serde_json::json;
use shedu_domain::version::{AppVersion, UpdateStatus, update_status};
use sqlx::PgPool;
use tokio::sync::RwLock;

use crate::{
    AppState,
    error::{ApiError, ApiResult},
};

/// İstemcinin platformunu ve sürümünü bildirdiği başlık: `ios/1.4.2`.
pub const HEADER: &str = "x-shedu-app";

pub fn routes() -> Router<AppState> {
    Router::new().route("/app-version", get(check))
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub minimum: AppVersion,
    pub latest: AppVersion,
    pub store_url: Option<String>,
}

type Policies = Arc<HashMap<String, Policy>>;

/// Politikaların kısa süreli önbelleği; her istekte veritabanına gidilmez.
pub struct VersionCache {
    ttl: Duration,
    inner: RwLock<Option<(Instant, Policies)>>,
}

impl VersionCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: RwLock::new(None),
        }
    }

    pub async fn policies(&self, db: &PgPool) -> ApiResult<Policies> {
        if let Some((loaded, policies)) = self.inner.read().await.as_ref()
            && loaded.elapsed() < self.ttl
        {
            return Ok(policies.clone());
        }
        let rows: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
            "SELECT platform, minimum_version, latest_version, store_url FROM app_versions",
        )
        .fetch_all(db)
        .await?;
        let mut policies = HashMap::new();
        for (platform, minimum, latest, store_url) in rows {
            // Biçim veritabanı kısıtıyla da denetlenir; çözülemeyen kayıt güvenli tarafta hata verir.
            let (Ok(minimum), Ok(latest)) = (minimum.parse(), latest.parse()) else {
                tracing::error!(%platform, "geçersiz sürüm politikası");
                return Err(ApiError::Internal);
            };
            policies.insert(
                platform,
                Policy {
                    minimum,
                    latest,
                    store_url,
                },
            );
        }
        let policies = Arc::new(policies);
        *self.inner.write().await = Some((Instant::now(), policies.clone()));
        Ok(policies)
    }
}

fn platform(value: &str) -> Option<&'static str> {
    match value {
        "ios" => Some("ios"),
        "android" => Some("android"),
        "web" => Some("web"),
        _ => None,
    }
}

fn status_name(status: UpdateStatus) -> &'static str {
    match status {
        UpdateStatus::UpToDate => "up_to_date",
        UpdateStatus::Recommended => "update_recommended",
        UpdateStatus::Required => "update_required",
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckQuery {
    platform: String,
    version: String,
}

pub async fn check(
    State(state): State<AppState>,
    Query(query): Query<CheckQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let platform = platform(&query.platform).ok_or(ApiError::BadRequest("invalid_platform"))?;
    let current: AppVersion = query
        .version
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid_version"))?;
    let policies = state.versions.policies(&state.db).await?;
    let Some(policy) = policies.get(platform) else {
        return Ok(Json(
            json!({ "status": status_name(UpdateStatus::UpToDate) }),
        ));
    };
    let status = update_status(current, policy.minimum, policy.latest);
    Ok(Json(json!({
        "status": status_name(status),
        "minimum_version": policy.minimum.to_string(),
        "latest_version": policy.latest.to_string(),
        "store_url": policy.store_url,
    })))
}

/// `X-Shedu-App` başlığını çözer: `ios/1.4.2`.
fn parse_header(value: &str) -> Option<(&'static str, AppVersion)> {
    let (platform_name, version) = value.split_once('/')?;
    Some((platform(platform_name)?, version.parse().ok()?))
}

/// Desteklenmeyen sürümdeki istemcinin isteğini reddeder (426).
pub async fn enforce(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let Some(raw) = request.headers().get(HEADER) else {
        return next.run(request).await;
    };
    let Some((platform, current)) = raw.to_str().ok().and_then(parse_header) else {
        return ApiError::BadRequest("invalid_app_header").into_response();
    };
    let policies = match state.versions.policies(&state.db).await {
        Ok(policies) => policies,
        Err(error) => return error.into_response(),
    };
    if let Some(policy) = policies.get(platform)
        && current < policy.minimum
    {
        return (
            StatusCode::UPGRADE_REQUIRED,
            Json(json!({
                "error": "update_required",
                "minimum_version": policy.minimum.to_string(),
                "store_url": policy.store_url,
            })),
        )
            .into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_format() {
        assert!(parse_header("ios/1.4.2").is_some());
        assert!(parse_header("android/2").is_some());
        for bad in [
            "ios",
            "ios/",
            "/1.0",
            "symbian/1.0",
            "ios/1.0-beta",
            "ios/1.0/2",
            "IOS/1.0",
        ] {
            assert!(parse_header(bad).is_none(), "{bad}");
        }
    }
}
