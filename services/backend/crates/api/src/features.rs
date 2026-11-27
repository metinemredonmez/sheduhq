//! Özellik bayrakları: bir özelliği yeniden dağıtım yapmadan açıp kapatma, pilot
//! organizasyonlarda veya organizasyonların bir yüzdesinde deneme.
//!
//! Bayrak yetki vermez; yalnızca özelliği gösterir veya gizler (yetki her istekte ayrıca
//! denetlenir). Tanımsız bayrak kapalıdır. Bayrakları yalnızca platform yöneticisi
//! (`shedu-admin`) değiştirir; kurallar migration 0012'dedir.

use std::collections::BTreeMap;

use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{AppState, auth::AuthUser, authz, error::ApiResult};

pub fn routes() -> Router<AppState> {
    Router::new().route("/organizations/{org_id}/features", get(list))
}

/// Organizasyonun bayrak için sabit kovası (0–99): aynı organizasyon aynı bayrakta hep aynı
/// sonucu alır; yüzde artınca önceden açık olanlar açık kalır.
pub fn bucket(key: &str, organization_id: Uuid) -> u8 {
    let digest = Sha256::new()
        .chain_update(key.as_bytes())
        .chain_update([0u8])
        .chain_update(organization_id.as_bytes())
        .finalize();
    let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    u8::try_from(value % 100).unwrap_or(0)
}

/// Bayrağın bir organizasyondaki değeri. Kapalı bayrak her yerde kapalıdır (acil kapatma,
/// organizasyon ayarını da ezer); açıksa organizasyon ayarı, yoksa yüzde uygulanır.
pub fn evaluate(enabled: bool, rollout_percent: i16, overridden: Option<bool>, bucket: u8) -> bool {
    if !enabled {
        return false;
    }
    match overridden {
        Some(value) => value,
        None => i16::from(bucket) < rollout_percent,
    }
}

/// Organizasyon için bütün bayrakların değeri. Bağlantının kiracı bağlamı bu organizasyon
/// olmalıdır (organizasyon ayarları RLS ile okunur).
pub async fn flags_for(
    conn: &mut PgConnection,
    organization_id: Uuid,
) -> ApiResult<BTreeMap<String, bool>> {
    let rows: Vec<(String, bool, i16, Option<bool>)> = sqlx::query_as(
        "SELECT f.key, f.enabled, f.rollout_percent, o.enabled
           FROM feature_flags f
           LEFT JOIN feature_flag_overrides o
                  ON o.flag_key = f.key AND o.organization_id = $1
          ORDER BY f.key",
    )
    .bind(organization_id)
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(key, enabled, rollout, overridden)| {
            let value = evaluate(enabled, rollout, overridden, bucket(&key, organization_id));
            (key, value)
        })
        .collect())
}

/// Sunucu tarafında tek bayrak sorgusu; tanımsız bayrak kapalıdır.
pub async fn is_enabled(
    conn: &mut PgConnection,
    key: &str,
    organization_id: Uuid,
) -> ApiResult<bool> {
    Ok(flags_for(conn, organization_id)
        .await?
        .get(key)
        .copied()
        .unwrap_or(false))
}

/// Organizasyon üyesinin gördüğü bayraklar (uygulama hangi ekranları göstereceğine bunlarla karar
/// verir).
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let (mut tx, _ctx) = authz::begin(&state, user, org_id).await?;
    let features = flags_for(&mut tx, org_id).await?;
    tx.commit().await?;
    Ok(Json(json!({ "features": features })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_switch_beats_overrides_and_overrides_beat_rollout() {
        assert!(
            !evaluate(false, 100, Some(true), 0),
            "kapalı bayrak her yerde kapalı"
        );
        assert!(evaluate(true, 0, Some(true), 99), "pilot organizasyon açık");
        assert!(
            !evaluate(true, 100, Some(false), 0),
            "organizasyon kapatabilir"
        );
        assert!(evaluate(true, 100, None, 99));
        assert!(!evaluate(true, 0, None, 0));
        assert!(evaluate(true, 50, None, 49) && !evaluate(true, 50, None, 50));
    }

    #[test]
    fn buckets_are_stable_and_spread() {
        let org = Uuid::new_v4();
        assert_eq!(bucket("camera", org), bucket("camera", org));
        let mut counts = [0u32; 10];
        for _ in 0..5000 {
            let b = bucket("camera", Uuid::new_v4());
            assert!(b < 100);
            counts[usize::from(b / 10)] += 1;
        }
        // Her onluk dilimde kabaca %10 (geniş tolerans).
        assert!(counts.iter().all(|c| (350..=650).contains(c)), "{counts:?}");
    }
}
