//! AI olay özeti: bir panelin son saatlerdeki olaylarının kullanıcı için kısa Türkçe özeti.
//!
//! Kurallar (AI-01, AI-02, AI-03, LOG-02, ARC-04):
//! - Özellik `ai_event_summary` bayrağıyla kapalı başlar. Bayrak, olay verisinin yurt dışındaki
//!   model sağlayıcısına aktarımı için KVKK kararı verilene kadar açılmaz
//!   (docs/acik-sorular.md).
//! - Yetki paneli görme yetkisidir. AI servisine yalnızca kullanıcının zaten görebildiği olaylar
//!   gider (bölüm yetkisi uygulanır). Organizasyon veya kullanıcı kimliği, telefon, PIN ya da
//!   token gönderilmez.
//! - Kesin bilgiler (sayılar, "dikkat gerekiyor mu?") burada SQL ile hesaplanır ve AI servisinin
//!   yanıtından alınmaz. AI servisinden yalnızca anlatım metni gelir ve yanıtta
//!   `ai_generated` ile işaretlenir.
//! - Bütçe iki katmanlıdır (AI-03). Sıklık: kullanıcı başına saatte 10, organizasyon başına günde
//!   50 özet. Maliyet: her çağrıdan önce `ai_usage` defterinden son 24 saatin harcaması okunur;
//!   kullanıcı, organizasyon veya bütün sistem sınırı dolduysa çağrı yapılmaz. Her çağrının
//!   harcaması, sonucu ne olursa olsun, çağrı döner dönmez deftere yazılır. Sonucu bilinmeyen
//!   çağrı (zaman aşımı, kopan bağlantı) en kötü durum tahminiyle yazılır. Sınırı yalnızca o an
//!   süren çağrılar aşabilir. Servise en fazla 500 olay gider.
//! - AI servisi yalnızca iç ağdan, paylaşılan servis token'ıyla çağrılır. Yönlendirme izlenmez,
//!   vekil sunucu kullanılmaz ve yanıt boyutu sınırlıdır. Loopback dışında yalnızca HTTPS kabul
//!   edilir.
//! - Alarm yolu AI'ya bağlı değildir. Servis yoksa veya yanıt vermezse yalnızca özet gelmez
//!   (503).
//! - Denetim kaydına özet metni değil, yalnızca sayılar ve token kullanımı yazılır.

use std::{net::IpAddr, time::Duration};

use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use chrono::{DateTime, Utc};
use reqwest::{
    StatusCode, Url,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    AppState, audit,
    auth::{AuthUser, rate_limit},
    authz,
    db::set_context,
    error::{ApiError, ApiResult},
    features,
};

/// Özelliği açıp kapatan bayrak.
pub const FLAG: &str = "ai_event_summary";
const DEFAULT_HOURS: i64 = 24;
const MAX_HOURS: i64 = 7 * 24;
/// AI servisine gönderilen en fazla olay (en yeniler).
pub const MAX_EVENTS: usize = 500;
const SUMMARY_MAX_CHARS: usize = 800;
const HIGHLIGHT_MAX_CHARS: usize = 200;
const MAX_HIGHLIGHTS: usize = 5;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MIN_TOKEN_LEN: usize = 32;
/// AI servisinin kendi model zaman aşımı ve bir yeniden denemesi bu sürenin içinde kalır.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(75);
/// Son 24 saatte kullanıcı başına en fazla harcama (mikro-dolar): 1 $. Opus 5.5 ile tipik bir
/// özet 0,01–0,03 $, en büyük istek (500 olay) yaklaşık 0,20 $ tutar.
pub const USER_DAILY_MICROUSD: i64 = 1_000_000;
/// Son 24 saatte organizasyon başına en fazla harcama: 5 $.
pub const ORG_DAILY_MICROUSD: i64 = 5_000_000;
/// Bütün sistem için varsayılan günlük sınır: 20 $ (`SHEDU_AI_DAILY_BUDGET_USD`).
pub const DEFAULT_GLOBAL_DAILY_USD: u32 = 20;
/// Sonucu bilinmeyen çağrının tahmini için AI servisinin sınırları (services/ai: `MAX_TOKENS`,
/// `UNKNOWN_MODEL_PRICE`). Biri değişirse burası da güncellenir.
const SERVICE_MAX_OUTPUT_TOKENS: i64 = 4096;
const PRICIEST_INPUT_MICROUSD_PER_TOKEN: i64 = 10;
const PRICIEST_OUTPUT_MICROUSD_PER_TOKEN: i64 = 50;
/// Sistem prompt'u ve sabit metinler için pay (token).
const PROMPT_OVERHEAD_TOKENS: i64 = 2048;

pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/organizations/{org_id}/panels/{panel_id}/ai-summary",
        post(event_summary),
    )
}

#[derive(Debug, PartialEq, Eq)]
pub enum AiConfigError {
    InvalidUrl,
    /// Loopback dışında düz HTTP.
    InsecureUrl,
    TokenTooShort,
    Client,
}

/// AI servisinin adresini doğrular: kullanıcı bilgisi, sorgu ve parça yok; loopback dışında
/// yalnızca HTTPS.
pub fn validate_url(value: &str) -> Result<Url, AiConfigError> {
    let url = Url::parse(value).map_err(|_| AiConfigError::InvalidUrl)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AiConfigError::InvalidUrl);
    }
    let loopback = match url.host_str() {
        None => return Err(AiConfigError::InvalidUrl),
        Some("localhost") => true,
        Some(host) => host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback()),
    };
    match url.scheme() {
        "https" => Ok(url),
        "http" if loopback => Ok(url),
        "http" => Err(AiConfigError::InsecureUrl),
        _ => Err(AiConfigError::InvalidUrl),
    }
}

/// İç AI servisinin istemcisi.
pub struct AiClient {
    http: reqwest::Client,
    endpoint: Url,
    authorization: HeaderValue,
    /// Bütün sistemin son 24 saatteki harcama sınırı (mikro-dolar).
    global_daily_microusd: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AiError {
    /// Model isteği güvenlik gerekçesiyle reddetti.
    Refused,
    /// Servis yok, yanıt vermedi veya geçersiz yanıt verdi.
    Unavailable,
}

impl AiClient {
    pub fn new(base_url: &str, token: &str) -> Result<Self, AiConfigError> {
        let base = validate_url(base_url)?;
        if token.len() < MIN_TOKEN_LEN {
            return Err(AiConfigError::TokenTooShort);
        }
        let mut endpoint = base;
        let path = format!(
            "{}/v1/summaries/events",
            endpoint.path().trim_end_matches('/')
        );
        endpoint.set_path(&path);
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| AiConfigError::TokenTooShort)?;
        authorization.set_sensitive(true);

        // reqwest yalnızca ring sağlayıcısıyla derlenir; süreç genelinde bir kez kurulur.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .https_only(endpoint.scheme() == "https")
            .build()
            .map_err(|_| AiConfigError::Client)?;
        Ok(Self {
            http,
            endpoint,
            authorization,
            global_daily_microusd: i64::from(DEFAULT_GLOBAL_DAILY_USD) * 1_000_000,
        })
    }

    /// Bütün sistemin günlük harcama sınırını değiştirir (mikro-dolar).
    #[must_use]
    pub fn with_global_budget(mut self, microusd: i64) -> Self {
        self.global_daily_microusd = microusd;
        self
    }

    async fn summarize(&self, request: &ServiceRequest<'_>) -> Reply {
        let unavailable = |spend: Option<Spend>| Reply {
            result: Err(AiError::Unavailable),
            spend,
        };
        let Ok(payload) = serde_json::to_vec(request) else {
            return unavailable(None);
        };
        let unknown = Spend::unknown(payload.len());
        let sent = self
            .http
            .post(self.endpoint.clone())
            .header(AUTHORIZATION, self.authorization.clone())
            .header(CONTENT_TYPE, "application/json")
            .body(payload)
            .send()
            .await;
        let mut response = match sent {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(
                    timeout = error.is_timeout(),
                    connect = error.is_connect(),
                    "AI servisine ulaşılamadı"
                );
                // Bağlantı kurulamadıysa istek gitmedi; kurulduysa model çalışmış olabilir.
                return unavailable((!error.is_connect()).then_some(unknown));
            }
        };
        let status = response.status();
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if body.len() + chunk.len() <= MAX_RESPONSE_BYTES => {
                    body.extend_from_slice(&chunk);
                }
                Ok(Some(_)) => {
                    tracing::warn!("AI servisinin yanıtı çok büyük");
                    return unavailable(Some(unknown.clone()));
                }
                Ok(None) => break,
                Err(_) => return unavailable(Some(unknown.clone())),
            }
        }
        if status == StatusCode::OK {
            return match serde_json::from_slice::<ServiceResponse>(&body) {
                Ok(answer) => Reply {
                    spend: Some(answer.spend.clone()),
                    result: Ok(answer),
                },
                Err(_) => {
                    tracing::warn!("AI servisinin yanıtı okunamadı");
                    unavailable(Some(unknown.clone()))
                }
            };
        }
        // Servis hata gövdesinde modelin harcamasını bildirir. Gövde okunamıyorsa servis
        // beklenmedik biçimde düşmüştür: harcama bilinmiyor sayılır.
        let error = serde_json::from_slice::<ServiceError>(&body).ok();
        let spend = match &error {
            Some(error) => error.usage.clone(),
            None => Some(unknown.clone()),
        };
        let refused = status == StatusCode::UNPROCESSABLE_ENTITY
            && error
                .as_ref()
                .is_some_and(|e| e.detail.as_str() == Some("ai_refused"));
        if !refused {
            tracing::warn!(status = status.as_u16(), "AI servisi hata döndürdü");
        }
        Reply {
            result: Err(if refused {
                AiError::Refused
            } else {
                AiError::Unavailable
            }),
            spend,
        }
    }
}

/// AI servisine yapılan çağrının sonucu ve harcaması (harcama yoksa `None`).
struct Reply {
    result: Result<ServiceResponse, AiError>,
    spend: Option<Spend>,
}

/// Bir çağrının harcaması. AI servisi bildirir; bilinmiyorsa tahmin edilir.
#[derive(Deserialize, Clone, Debug)]
struct Spend {
    model: Option<String>,
    #[serde(default)]
    input_tokens: i64,
    #[serde(default)]
    output_tokens: i64,
    #[serde(default)]
    cost_microusd: i64,
    /// Servis bildirmedi; en kötü durum tahmini.
    #[serde(skip)]
    estimated: bool,
}

impl Spend {
    /// Sonucu bilinmeyen çağrının temkinli tahmini. Prompt, isteğin kısaltılmış biçimidir; JSON
    /// ve Türkçe metinde token başına 2 bayttan fazla düşer, bu yüzden giriş token'ı bayt
    /// sayısının yarısıyla sayılır. Çıktı `max_tokens` sınırında, ikisi de en pahalı katmanın
    /// fiyatıyla. Gerçek maliyetin birkaç katıdır, ama en büyük istekte bile kullanıcının günlük
    /// sınırının altında kalır: tek bir kesinti kullanıcıyı bir gün kilitlemez.
    fn unknown(payload_bytes: usize) -> Self {
        let input_tokens = i64::try_from(payload_bytes / 2)
            .unwrap_or(i64::MAX / 4)
            .saturating_add(PROMPT_OVERHEAD_TOKENS);
        Self {
            model: None,
            input_tokens: 0,
            output_tokens: 0,
            cost_microusd: input_tokens
                .saturating_mul(PRICIEST_INPUT_MICROUSD_PER_TOKEN)
                .saturating_add(SERVICE_MAX_OUTPUT_TOKENS * PRICIEST_OUTPUT_MICROUSD_PER_TOKEN),
            estimated: true,
        }
    }
}

/// AI servisine giden istek. Kimlik, telefon, PIN, token yok (AI-02).
#[derive(Serialize)]
struct ServiceRequest<'a> {
    panel_name: &'a str,
    time_zone: &'a str,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    events: Vec<ServiceEvent>,
    truncated: bool,
}

#[derive(Serialize)]
struct ServiceEvent {
    occurred_at: DateTime<Utc>,
    kind: String,
    alarm_kind: Option<String>,
    arm_mode: Option<String>,
    partition: Option<String>,
    zone: Option<String>,
    source: String,
}

/// AI servisinin yanıtından kullanılan alanlar. Sayılar ve dikkat işareti alınmaz.
#[derive(Deserialize)]
struct ServiceResponse {
    summary: String,
    highlights: Vec<String>,
    generated: bool,
    #[serde(flatten)]
    spend: Spend,
}

#[derive(Deserialize)]
struct ServiceError {
    detail: serde_json::Value,
    usage: Option<Spend>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummaryRequest {
    /// Kaç saatlik dönem (1–168, varsayılan 24).
    hours: Option<i64>,
}

#[derive(Debug, Serialize, Default, sqlx::FromRow)]
pub struct Stats {
    total: i64,
    alarms: i64,
    armed: i64,
    disarmed: i64,
    disconnected: i64,
    power_problems: i64,
}

#[derive(Serialize)]
pub struct SummaryView {
    summary: String,
    highlights: Vec<String>,
    /// Metin yapay zekâ ile üretildi; istemci bunu kullanıcıya belirtir. Olay yoksa sabit metin
    /// döner ve `false` olur.
    ai_generated: bool,
    model: Option<String>,
    /// Kodla hesaplanır: alarm, güç sorunu veya hâlâ süren bağlantı kopması.
    needs_attention: bool,
    /// Dönemdeki bütün görünür olayların kesin sayıları (AI'ya giden liste kısaltılsa bile).
    stats: Stats,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    /// AI'ya yalnızca en yeni olaylar gitti.
    truncated: bool,
}

type EventRow = (
    DateTime<Utc>,
    String,
    Option<String>,
    Option<String>,
    String,
    Option<i16>,
    Option<String>,
    Option<i16>,
    Option<String>,
);

fn clip(text: &str, max: usize) -> String {
    let joined = text.split_whitespace().collect::<Vec<_>>().join(" ");
    joined.chars().take(max).collect()
}

/// Panel olaylarının AI özeti.
pub async fn event_summary(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_id, panel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<SummaryRequest>,
) -> ApiResult<Json<SummaryView>> {
    let hours = request.hours.unwrap_or(DEFAULT_HOURS);
    if !(1..=MAX_HOURS).contains(&hours) {
        return Err(ApiError::BadRequest("invalid_hours"));
    }

    let (mut tx, ctx) = authz::begin(&state, user, org_id).await?;
    if !authz::permissions(&mut tx, &ctx, panel_id, None)
        .await?
        .view
    {
        return Err(ApiError::NotFound);
    }
    if !features::is_enabled(&mut tx, FLAG, org_id).await? {
        return Err(ApiError::Forbidden("feature_disabled"));
    }
    let Some(ai) = state.ai.clone() else {
        return Err(ApiError::Unavailable("ai_unavailable"));
    };
    // Bütçe, üyelik ve bayrak doğrulandıktan sonra sayılır: üye olmayan biri bir organizasyonun
    // bütçesini tüketemez. Sınır aşılırsa işlem geri alınır, sayaç artmaz.
    rate_limit::hit(
        &mut tx,
        &state.hmac_secret,
        rate_limit::AI_SUMMARY_PER_USER,
        &user.user_id.to_string(),
    )
    .await?;
    rate_limit::hit(
        &mut tx,
        &state.hmac_secret,
        rate_limit::AI_SUMMARY_PER_ORG,
        &org_id.to_string(),
    )
    .await?;
    // Maliyet bütçesi: defterdeki son 24 saatin harcaması (AI-03).
    let (user_spent, org_spent, global_spent): (i64, i64, i64) = sqlx::query_as(
        "SELECT user_microusd, org_microusd, global_microusd FROM ai_spend_last_day()",
    )
    .fetch_one(&mut *tx)
    .await?;
    if user_spent >= USER_DAILY_MICROUSD
        || org_spent >= ORG_DAILY_MICROUSD
        || global_spent >= ai.global_daily_microusd
    {
        tracing::warn!(
            user = user_spent >= USER_DAILY_MICROUSD,
            organization = org_spent >= ORG_DAILY_MICROUSD,
            global = global_spent >= ai.global_daily_microusd,
            "AI harcama sınırı doldu"
        );
        return Err(ApiError::TooManyRequests {
            retry_after_secs: 3600,
        });
    }

    let partitions = authz::visible_partition_numbers(&mut tx, &ctx, panel_id).await?;
    let (panel_name, time_zone): (String, String) = sqlx::query_as(
        "SELECT p.name, o.time_zone
           FROM panels p JOIN organizations o ON o.id = p.organization_id
          WHERE p.id = $1 AND p.organization_id = $2",
    )
    .bind(panel_id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;

    let period_end = Utc::now();
    let period_start = period_end - chrono::Duration::hours(hours);
    let fetch_limit = i64::try_from(MAX_EVENTS + 1).unwrap_or(i64::MAX);
    let mut rows: Vec<EventRow> = sqlx::query_as(
        "SELECT e.occurred_at, e.kind, e.alarm_kind, e.arm_mode, e.source,
                e.partition_number, pt.name, e.zone_number, z.name
           FROM panel_events e
           LEFT JOIN partitions pt
                  ON pt.panel_id = e.panel_id AND pt.number = e.partition_number
                 AND pt.organization_id = e.organization_id
           LEFT JOIN zones z
                  ON z.panel_id = e.panel_id AND z.number = e.zone_number
                 AND z.organization_id = e.organization_id
          WHERE e.panel_id = $1 AND e.organization_id = $2
            AND e.occurred_at > $3 AND e.occurred_at <= $4
            AND ($5::smallint[] IS NULL OR e.partition_number IS NULL
                 OR e.partition_number = ANY($5))
          ORDER BY e.occurred_at DESC, e.id DESC
          LIMIT $6",
    )
    .bind(panel_id)
    .bind(org_id)
    .bind(period_start)
    .bind(period_end)
    .bind(&partitions)
    .bind(fetch_limit)
    .fetch_all(&mut *tx)
    .await?;
    let truncated = rows.len() > MAX_EVENTS;
    rows.truncate(MAX_EVENTS);

    let stats: Stats = sqlx::query_as(
        "SELECT count(*) AS total,
                count(*) FILTER (WHERE kind = 'alarm') AS alarms,
                count(*) FILTER (WHERE kind = 'armed') AS armed,
                count(*) FILTER (WHERE kind = 'disarmed') AS disarmed,
                count(*) FILTER (WHERE kind = 'disconnected') AS disconnected,
                count(*) FILTER (WHERE kind = 'power_problem') AS power_problems
           FROM panel_events
          WHERE panel_id = $1 AND organization_id = $2
            AND occurred_at > $3 AND occurred_at <= $4
            AND ($5::smallint[] IS NULL OR partition_number IS NULL
                 OR partition_number = ANY($5))",
    )
    .bind(panel_id)
    .bind(org_id)
    .bind(period_start)
    .bind(period_end)
    .bind(&partitions)
    .fetch_one(&mut *tx)
    .await?;
    // Bağlantı olayları panel düzeyindedir (bölümsüz).
    let last_connectivity: Option<(String,)> = sqlx::query_as(
        "SELECT kind FROM panel_events
          WHERE panel_id = $1 AND organization_id = $2
            AND occurred_at > $3 AND occurred_at <= $4
            AND kind IN ('connected', 'disconnected')
          ORDER BY occurred_at DESC, id DESC
          LIMIT 1",
    )
    .bind(panel_id)
    .bind(org_id)
    .bind(period_start)
    .bind(period_end)
    .fetch_optional(&mut *tx)
    .await?;
    // AI çağrısı uzun sürebilir: veritabanı işlemi önce kapanır (bütçe sayacı da kalıcı olur).
    tx.commit().await?;

    let needs_attention = stats.alarms > 0
        || stats.power_problems > 0
        || last_connectivity.is_some_and(|(kind,)| kind == "disconnected");
    let events: Vec<ServiceEvent> = rows
        .into_iter()
        .map(
            |(occurred_at, kind, alarm_kind, arm_mode, source, pn, pname, zn, zname)| {
                ServiceEvent {
                    occurred_at,
                    kind,
                    alarm_kind,
                    arm_mode,
                    partition: pn.map(|n| pname.unwrap_or_else(|| format!("Bölüm {n}"))),
                    zone: zn.map(|n| zname.unwrap_or_else(|| format!("Zon {n}"))),
                    source,
                }
            },
        )
        .collect();
    let event_count = events.len();
    let service_request = ServiceRequest {
        panel_name: &panel_name,
        time_zone: &time_zone,
        period_start,
        period_end,
        events,
        truncated,
    };
    let reply = ai.summarize(&service_request).await;
    // Harcama önce ve ayrı işlemde yazılır: denetim kaydı başarısız olsa da defterde kalır.
    if let Some(spend) = &reply.spend {
        let outcome = match (&reply.result, spend.estimated) {
            (_, true) => "unknown",
            (Ok(_), false) => "success",
            (Err(AiError::Refused), false) => "refused",
            (Err(AiError::Unavailable), false) => "failed",
        };
        record_spend(&state, user.user_id, org_id, spend, outcome).await?;
    }
    let cost = reply.spend.as_ref().map_or(0, |s| s.cost_microusd);

    let mut audit_tx = state.db.begin().await?;
    set_context(&mut audit_tx, Some(user.user_id), Some(org_id)).await?;
    let response = match reply.result {
        Ok(answer) => {
            audit::record(
                &mut audit_tx,
                audit::Event {
                    organization_id: Some(org_id),
                    actor_user_id: Some(user.user_id),
                    action: "ai.summary_generated",
                    target_type: Some("panel"),
                    target_id: Some(&panel_id.to_string()),
                    outcome: audit::Outcome::Success,
                    details: json!({
                        "hours": hours,
                        "event_count": event_count,
                        "truncated": truncated,
                        "generated": answer.generated,
                        "model": answer.spend.model,
                        "input_tokens": answer.spend.input_tokens,
                        "output_tokens": answer.spend.output_tokens,
                        "cost_microusd": cost,
                    }),
                },
            )
            .await?;
            Ok(SummaryView {
                summary: clip(&answer.summary, SUMMARY_MAX_CHARS),
                highlights: answer
                    .highlights
                    .iter()
                    .map(|h| clip(h, HIGHLIGHT_MAX_CHARS))
                    .filter(|h| !h.is_empty())
                    .take(MAX_HIGHLIGHTS)
                    .collect(),
                ai_generated: answer.generated,
                model: answer.spend.model,
                needs_attention,
                stats,
                period_start,
                period_end,
                truncated,
            })
        }
        Err(error) => {
            let code = match error {
                AiError::Refused => "ai_refused",
                AiError::Unavailable => "ai_unavailable",
            };
            audit::record(
                &mut audit_tx,
                audit::Event {
                    organization_id: Some(org_id),
                    actor_user_id: Some(user.user_id),
                    action: "ai.summary_failed",
                    target_type: Some("panel"),
                    target_id: Some(&panel_id.to_string()),
                    outcome: audit::Outcome::Failure,
                    details: json!({
                        "hours": hours,
                        "event_count": event_count,
                        "reason": code,
                        "cost_microusd": cost,
                    }),
                },
            )
            .await?;
            Err(match error {
                AiError::Refused => ApiError::Unprocessable("ai_refused"),
                AiError::Unavailable => ApiError::Unavailable("ai_unavailable"),
            })
        }
    };
    audit_tx.commit().await?;
    response.map(Json)
}

/// Harcamayı maliyet defterine yazar (kendi işleminde, kullanıcı ve organizasyon bağlamıyla).
async fn record_spend(
    state: &AppState,
    user_id: Uuid,
    organization_id: Uuid,
    spend: &Spend,
    outcome: &'static str,
) -> ApiResult<()> {
    let mut tx = state.db.begin().await?;
    set_context(&mut tx, Some(user_id), Some(organization_id)).await?;
    sqlx::query(
        "INSERT INTO ai_usage (organization_id, user_id, feature, model, input_tokens, output_tokens,
                               cost_microusd, outcome)
         VALUES ($1, $2, 'event_summary', $3, $4, $5, $6, $7)",
    )
    .bind(organization_id)
    .bind(user_id)
    .bind(spend.model.as_deref().filter(|m| !m.is_empty()).map(|m| clip(m, 100)))
    .bind(spend.input_tokens.max(0))
    .bind(spend.output_tokens.max(0))
    .bind(spend.cost_microusd.max(0))
    .bind(outcome)
    .execute(&mut *tx)
    .await
    .inspect_err(|_| tracing::error!("AI harcaması deftere yazılamadı"))?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_or_loopback_http_is_accepted() {
        assert!(validate_url("https://ai.internal:8443").is_ok());
        assert!(validate_url("http://127.0.0.1:8000").is_ok());
        assert!(validate_url("http://[::1]:8000").is_ok());
        assert!(validate_url("http://localhost:8000").is_ok());
        assert_eq!(
            validate_url("http://ai.internal:8000").err(),
            Some(AiConfigError::InsecureUrl)
        );
        assert_eq!(
            validate_url("http://10.0.0.5:8000").err(),
            Some(AiConfigError::InsecureUrl)
        );
        for bad in [
            "ftp://ai.internal",
            "https://user:parola@ai.internal",
            "https://ai.internal/?x=1",
            "https://ai.internal/#a",
            "ai.internal",
        ] {
            assert_eq!(
                validate_url(bad).err(),
                Some(AiConfigError::InvalidUrl),
                "{bad}"
            );
        }
    }

    #[test]
    fn client_requires_a_long_token_and_builds_the_endpoint() {
        assert_eq!(
            AiClient::new("http://127.0.0.1:8000", "kisa").err(),
            Some(AiConfigError::TokenTooShort)
        );
        let client = AiClient::new("https://ai.internal/ic/", &"t".repeat(40)).expect("istemci");
        assert_eq!(
            client.endpoint.as_str(),
            "https://ai.internal/ic/v1/summaries/events"
        );
        assert!(client.authorization.is_sensitive());
    }

    #[test]
    fn unknown_spend_grows_with_the_request_but_stays_below_the_user_budget() {
        let small = Spend::unknown(1_000).cost_microusd;
        // 500 olaylık tipik istek yaklaşık 90 KB.
        let large = Spend::unknown(100_000).cost_microusd;
        // 4096 çıktı token'ı × 50 + (1000 / 2 + 2048) × 10
        assert_eq!(small, 204_800 + 25_480);
        assert!(large > small);
        assert!(large < USER_DAILY_MICROUSD, "{large}");
    }

    #[test]
    fn clip_collapses_whitespace_and_limits_characters() {
        assert_eq!(clip("  bir\n\niki   üç ", 100), "bir iki üç");
        assert_eq!(clip("ğğğğ", 2), "ğğ");
    }
}
