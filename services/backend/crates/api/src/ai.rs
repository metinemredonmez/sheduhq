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
//!   50 özet. Maliyet: çağrıdan önce en kötü durum tahmini `ai_reserve()` ile kullanıcı,
//!   organizasyon ve sistem bütçesinden **ayrılır**; rezervasyonlar tek kilitle sıralandığı için
//!   eşzamanlı çağrılar aynı boş bütçeyi iki kez kullanamaz. Çağrı bitince gerçek harcama
//!   rezervasyonu kapatan ayrı bir defter satırı olarak yazılır. Sonucu bilinmeyen çağrı (zaman
//!   aşımı, kopan bağlantı, okunamayan yanıt) tahminle kapanır; süreç kesilirse veya kayıt
//!   yazılamazsa rezervasyon açık kalır ve tahminiyle sayılmaya devam eder. Çağrı ve kayıt ayrı bir
//!   görevde yürür: istemci bağlantıyı koparsa da tamamlanır. Servise en fazla 500 olay gider.
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
use chrono::{DateTime, SubsecRound, Utc};
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
/// Olay olmayan dönemin sabit metinleri (AI servisinin `summary.NO_EVENTS` ve
/// `summary.STILL_DISCONNECTED` metinleriyle aynı).
const NO_EVENTS: &str = "Bu dönemde panelde kayıtlı olay yok.";
const STILL_DISCONNECTED: &str = "Panelin bilinen son bağlantı durumu: kopuk.";
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MIN_TOKEN_LEN: usize = 32;
/// AI servisinin kendi model zaman aşımı ve bir yeniden denemesi bu sürenin içinde kalır.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(75);
/// Son 24 saatte kullanıcı başına en fazla harcama (mikro-dolar): 3 $. Opus 5.5 ile tipik bir
/// özet 0,01–0,03 $, en büyük istek (500 olay) yaklaşık 0,20 $ tutar. Çağrı öncesi ayrılan en kötü
/// durum tahmini bunun birkaç katıdır (en büyük istekte yaklaşık 1,45 $). Sınır, sonucu bilinmeyen
/// en büyük bir çağrı tahminle yazıldıktan sonra da bir sonrakinin rezervasyonu sığacak kadar
/// geniştir: tek bir kesinti kullanıcıyı bir gün kilitlemez.
pub const USER_DAILY_MICROUSD: i64 = 3_000_000;
/// Son 24 saatte organizasyon başına en fazla harcama: 10 $.
pub const ORG_DAILY_MICROUSD: i64 = 10_000_000;
/// Bütün sistem için varsayılan günlük sınır: 20 $ (`SHEDU_AI_DAILY_BUDGET_USD`).
pub const DEFAULT_GLOBAL_DAILY_USD: u32 = 20;
/// Sonucu bilinmeyen çağrının tahmini için AI servisinin sınırları (services/ai: `MAX_TOKENS`,
/// `UNKNOWN_MODEL_PRICE`). Biri değişirse burası da güncellenir.
const SERVICE_MAX_OUTPUT_TOKENS: i64 = 4096;
const PRICIEST_INPUT_MICROUSD_PER_TOKEN: i64 = 10;
const PRICIEST_OUTPUT_MICROUSD_PER_TOKEN: i64 = 50;
/// Sistem prompt'u ve sabit metinler için pay (token).
const PROMPT_OVERHEAD_TOKENS: i64 = 2048;
/// Bir özet isteğinde faturalanabilecek en fazla model çalışması: asıl model ve güvenlik reddinde
/// sağlayıcının yedek modeli. AI servisi SDK'nın kendi yeniden denemesini kapatır.
const MAX_MODEL_RUNS: i64 = 2;

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

    /// Hazır istek gövdesiyle AI servisini çağırır. Harcama her durumda belirlenir: servis
    /// bildirdiyse o, istek kesinlikle faturalanmadıysa sıfır, bilinmiyorsa `reserved` (en kötü
    /// durum tahmini).
    async fn summarize(&self, payload: Vec<u8>, reserved: &Spend) -> Reply {
        let unavailable = |spend: Spend| Reply {
            result: Err(AiError::Unavailable),
            spend,
        };
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
                return unavailable(if error.is_connect() {
                    Spend::none()
                } else {
                    reserved.clone()
                });
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
                    return unavailable(reserved.clone());
                }
                Ok(None) => break,
                Err(_) => return unavailable(reserved.clone()),
            }
        }
        if status == StatusCode::OK {
            return match serde_json::from_slice::<ServiceResponse>(&body) {
                Ok(answer) => Reply {
                    spend: answer.spend.clone().into_spend(reserved),
                    result: Ok(answer),
                },
                Err(_) => {
                    tracing::warn!("AI servisinin yanıtı okunamadı");
                    unavailable(reserved.clone())
                }
            };
        }
        // Servis hata gövdesinde modelin harcamasını ve faturalanmış olabilir mi bilgisini
        // bildirir. Gövde okunamıyorsa servis beklenmedik biçimde düşmüştür: harcama bilinmiyor.
        let error = serde_json::from_slice::<ServiceError>(&body).ok();
        let spend = match &error {
            Some(ServiceError {
                usage: Some(usage), ..
            }) => usage.clone().into_spend(reserved),
            Some(ServiceError {
                usage: None,
                may_be_billed: false,
                ..
            }) => Spend::none(),
            _ => reserved.clone(),
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

/// AI servisine yapılan çağrının sonucu ve harcaması.
struct Reply {
    result: Result<ServiceResponse, AiError>,
    spend: Spend,
}

/// Bir çağrının harcaması. AI servisi bildirir; bilinmiyorsa tahmin edilir.
#[derive(Clone, Debug)]
struct Spend {
    model: Option<String>,
    input_tokens: i64,
    output_tokens: i64,
    cost_microusd: i64,
    /// Servis bildirmedi; en kötü durum tahmini.
    estimated: bool,
}

/// AI servisinin bildirdiği kullanım. Kullanım alanlarından biri eksik veya negatifse kullanım
/// bilinmiyor sayılır ve en kötü durum tahmini yazılır: eksik alan sıfır sayılmaz, eksik maliyet
/// bütçeden kaçmaz (Y10).
#[derive(Deserialize, Clone, Debug)]
struct RawSpend {
    model: Option<String>,
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
    cost_microusd: Option<i64>,
}

impl RawSpend {
    fn into_spend(self, reserved: &Spend) -> Spend {
        match (self.input_tokens, self.output_tokens, self.cost_microusd) {
            (Some(input), Some(output), Some(cost)) if input >= 0 && output >= 0 && cost >= 0 => {
                Spend {
                    model: self.model,
                    input_tokens: input,
                    output_tokens: output,
                    cost_microusd: cost,
                    estimated: false,
                }
            }
            _ => {
                tracing::warn!(
                    "AI servisinin bildirdiği kullanım eksik veya geçersiz; tahmin yazılıyor"
                );
                reserved.clone()
            }
        }
    }
}

impl Spend {
    /// Çağrı öncesi ayrılan ve sonucu bilinmeyen çağrıda yazılan en kötü durum tahmini. Prompt,
    /// isteğin kısaltılmış biçimidir; JSON ve Türkçe metinde token başına 2 bayttan fazla düşer,
    /// bu yüzden giriş token'ı bayt sayısının yarısıyla sayılır. Çıktı `max_tokens` sınırında,
    /// ikisi de en pahalı katmanın fiyatıyla ve faturalanabilecek en fazla model çalışması kadar.
    /// Gerçek maliyetin birkaç katıdır, ama en büyük istekte bile kullanıcının günlük sınırının
    /// altında kalır: tek bir kesinti kullanıcıyı bir gün kilitlemez.
    fn upper_bound(payload_bytes: usize) -> Self {
        let input_tokens = i64::try_from(payload_bytes / 2)
            .unwrap_or(i64::MAX / 4)
            .saturating_add(PROMPT_OVERHEAD_TOKENS);
        let per_run = input_tokens
            .saturating_mul(PRICIEST_INPUT_MICROUSD_PER_TOKEN)
            .saturating_add(SERVICE_MAX_OUTPUT_TOKENS * PRICIEST_OUTPUT_MICROUSD_PER_TOKEN);
        Self {
            model: None,
            input_tokens: 0,
            output_tokens: 0,
            cost_microusd: per_run.saturating_mul(MAX_MODEL_RUNS),
            estimated: true,
        }
    }

    /// Sağlayıcıya faturalanan bir istek gitmedi.
    fn none() -> Self {
        Self {
            model: None,
            input_tokens: 0,
            output_tokens: 0,
            cost_microusd: 0,
            estimated: false,
        }
    }
}

/// AI servisine giden istek. Kimlik, telefon, PIN, token yok (AI-02). Kesin sayılar (`counts`)
/// ve güncel bağlantı durumu (`connection`) burada hesaplanır; liste kısaltılsa da model sayıları
/// listeden saymaz.
#[derive(Serialize)]
struct ServiceRequest<'a> {
    panel_name: &'a str,
    time_zone: &'a str,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    events: &'a [ServiceEvent],
    truncated: bool,
    counts: &'a Stats,
    connection: Option<&'a str>,
}

#[derive(Serialize, Deserialize)]
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
    spend: RawSpend,
}

#[derive(Deserialize)]
struct ServiceError {
    detail: serde_json::Value,
    usage: Option<RawSpend>,
    /// `false`: sağlayıcıya faturalanan istek kesinlikle gitmedi. Alan yoksa temkinli: `true`.
    #[serde(default = "billed_by_default")]
    may_be_billed: bool,
}

fn billed_by_default() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummaryRequest {
    /// Kaç saatlik dönem (1–168, varsayılan 24).
    hours: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Default, sqlx::FromRow)]
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
    // bütçesini tüketemez. Sıklık sınırı aşılırsa işlem geri alınır (sayaç zaten dolu). Bütçe
    // reddinde ise işlem commit'lenir: yetkili isteğin sıklık kaydı kalır, sürekli bütçe retleri
    // ağır sorguyu sıklık kapısında durdurur (Y09).
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
    // Sınır zaten dolduysa veri toplanmaz (kesin denetim aşağıda, rezervasyonla).
    let (user_spent, org_spent, global_spent): (i64, i64, i64) = sqlx::query_as(
        "SELECT user_microusd, org_microusd, global_microusd FROM ai_spend_last_day()",
    )
    .fetch_one(&mut *tx)
    .await?;
    if user_spent >= USER_DAILY_MICROUSD
        || org_spent >= ORG_DAILY_MICROUSD
        || global_spent >= ai.global_daily_microusd
    {
        tx.commit().await?;
        return Err(budget_exhausted());
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

    // Mikrosaniyeye kesilir: PostgreSQL ve AI servisi zamanı bu çözünürlükte tutar; dönem sınırı
    // üç tarafta aynı anı gösterir.
    let period_end = Utc::now().trunc_subsecs(6);
    let period_start = period_end - chrono::Duration::hours(hours);
    let fetch_limit = i64::try_from(MAX_EVENTS + 1).unwrap_or(i64::MAX);
    // Sayılar ve liste tek sorguda (tek anlık görüntü): liste hiçbir zaman sayılardan fazla olay
    // içermez, araya giren olay ikisinden birinde eksik kalmaz.
    let window: PeriodRow = sqlx::query_as(
        "WITH visible AS (
             SELECT e.id, e.occurred_at, e.kind, e.alarm_kind, e.arm_mode, e.source,
                    e.partition_number, e.zone_number
               FROM panel_events e
              WHERE e.panel_id = $1 AND e.organization_id = $2
                AND e.occurred_at > $3 AND e.occurred_at <= $4
                AND ($5::smallint[] IS NULL OR e.partition_number IS NULL
                     OR e.partition_number = ANY($5))
         )
         SELECT count(*) AS total,
                count(*) FILTER (WHERE kind = 'alarm') AS alarms,
                count(*) FILTER (WHERE kind = 'armed') AS armed,
                count(*) FILTER (WHERE kind = 'disarmed') AS disarmed,
                count(*) FILTER (WHERE kind = 'disconnected') AS disconnected,
                count(*) FILTER (WHERE kind = 'power_problem') AS power_problems,
                coalesce((
                    SELECT jsonb_agg(jsonb_build_object(
                               'occurred_at', l.occurred_at, 'kind', l.kind,
                               'alarm_kind', l.alarm_kind, 'arm_mode', l.arm_mode,
                               'source', l.source,
                               'partition', CASE WHEN l.partition_number IS NOT NULL
                                    THEN coalesce(pt.name, 'Bölüm ' || l.partition_number) END,
                               'zone', CASE WHEN l.zone_number IS NOT NULL
                                    THEN coalesce(z.name, 'Zon ' || l.zone_number) END)
                           ORDER BY l.occurred_at DESC, l.id DESC)
                      FROM (SELECT * FROM visible ORDER BY occurred_at DESC, id DESC LIMIT $6) l
                      LEFT JOIN partitions pt
                             ON pt.panel_id = $1 AND pt.number = l.partition_number
                            AND pt.organization_id = $2
                      LEFT JOIN zones z
                             ON z.panel_id = $1 AND z.number = l.zone_number
                            AND z.organization_id = $2
                ), '[]'::jsonb) AS events,
                -- Güncel bağlantı durumu dönemle sınırlı değildir: dönem başlamadan kopmuş ve hâlâ
                -- kopuk panel de dikkat ister. Aynı deyimde okunur: sayılarla aynı anlık görüntü
                -- (Y11). Bağlantı olayları panel düzeyindedir (bölümsüz).
                (SELECT c.kind FROM panel_events c
                  WHERE c.panel_id = $1 AND c.organization_id = $2 AND c.occurred_at <= $4
                    AND c.kind IN ('connected', 'disconnected') AND c.partition_number IS NULL
                  ORDER BY c.occurred_at DESC, c.id DESC
                  LIMIT 1) AS connection
           FROM visible",
    )
    .bind(panel_id)
    .bind(org_id)
    .bind(period_start)
    .bind(period_end)
    .bind(&partitions)
    .bind(fetch_limit)
    .fetch_one(&mut *tx)
    .await?;
    let stats = Stats {
        total: window.total,
        alarms: window.alarms,
        armed: window.armed,
        disarmed: window.disarmed,
        disconnected: window.disconnected,
        power_problems: window.power_problems,
    };
    let mut events: Vec<ServiceEvent> =
        serde_json::from_value(window.events.0).map_err(|_| ApiError::Internal)?;
    let truncated = events.len() > MAX_EVENTS;
    events.truncate(MAX_EVENTS);

    let connection = window.connection;
    let needs_attention = stats.alarms > 0
        || stats.power_problems > 0
        || connection.as_deref() == Some("disconnected");

    // Dönemde olay yoksa model gerekmez: sabit metin kodla üretilir, bütçeden ayrılmaz ve AI servisi
    // çağrılmaz (Y09). Metinler AI servisinin boş dönem yanıtıyla aynı.
    if stats.total == 0 {
        tx.commit().await?;
        let summary = if connection.as_deref() == Some("disconnected") {
            format!("{NO_EVENTS} {STILL_DISCONNECTED}")
        } else {
            NO_EVENTS.to_owned()
        };
        return Ok(Json(SummaryView {
            summary,
            highlights: Vec::new(),
            ai_generated: false,
            model: None,
            needs_attention,
            stats,
            period_start,
            period_end,
            truncated: false,
        }));
    }

    let event_count = events.len();
    let payload = serde_json::to_vec(&ServiceRequest {
        panel_name: &panel_name,
        time_zone: &time_zone,
        period_start,
        period_end,
        events: &events,
        truncated,
        counts: &stats,
        connection: connection.as_deref(),
    })
    .map_err(|_| ApiError::Internal)?;
    let reserved = Spend::upper_bound(payload.len());

    // En kötü durum tahmini bütçeden ayrılır (işlemin son adımı: rezervasyon kilidi kısa tutulur).
    // AI çağrısı uzun sürebilir: veritabanı işlemi çağrıdan önce kapanır.
    let reservation: (Option<i64>,) =
        sqlx::query_as("SELECT ai_reserve('event_summary', $1, $2, $3, $4)")
            .bind(reserved.cost_microusd)
            .bind(USER_DAILY_MICROUSD)
            .bind(ORG_DAILY_MICROUSD)
            .bind(ai.global_daily_microusd)
            .fetch_one(&mut *tx)
            .await?;
    let Some(reservation_id) = reservation.0 else {
        tx.commit().await?;
        return Err(budget_exhausted());
    };

    // Rezervasyonun commit'i, çağrı, harcama kaydı ve denetim kaydı aynı ayrı görevde: istemci
    // bağlantıyı koparsa da (işleyici iptal edilse de) sonuna kadar yürür ve rezervasyon kapanır.
    // İşleyici görev başlamadan iptal edilirse işlem geri alınır ve rezervasyon hiç yazılmaz (Y10).
    let call = Call {
        user_id: user.user_id,
        org_id,
        panel_id,
        hours,
        event_count,
        truncated,
        reservation_id,
        reserved,
    };
    let view = Pending {
        needs_attention,
        stats,
        period_start,
        period_end,
        truncated,
    };
    let state = state.clone();
    let task = tokio::spawn(async move {
        tx.commit().await?;
        complete_summary(state, ai, payload, call, view).await
    });
    task.await.map_err(|_| ApiError::Internal)?.map(Json)
}

fn budget_exhausted() -> ApiError {
    tracing::warn!("AI harcama sınırı doldu");
    ApiError::TooManyRequests {
        retry_after_secs: 3600,
    }
}

#[derive(sqlx::FromRow)]
struct PeriodRow {
    total: i64,
    alarms: i64,
    armed: i64,
    disarmed: i64,
    disconnected: i64,
    power_problems: i64,
    events: sqlx::types::Json<serde_json::Value>,
    connection: Option<String>,
}

/// Rezervasyonu yapılmış çağrının bilgileri.
struct Call {
    user_id: Uuid,
    org_id: Uuid,
    panel_id: Uuid,
    hours: i64,
    event_count: usize,
    truncated: bool,
    reservation_id: i64,
    reserved: Spend,
}

/// Yanıtın kodla hesaplanan kısmı.
struct Pending {
    needs_attention: bool,
    stats: Stats,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    truncated: bool,
}

async fn complete_summary(
    state: AppState,
    ai: std::sync::Arc<AiClient>,
    payload: Vec<u8>,
    call: Call,
    view: Pending,
) -> ApiResult<SummaryView> {
    let reply = ai.summarize(payload, &call.reserved).await;
    // Harcama önce ve ayrı işlemde yazılır: denetim kaydı başarısız olsa da defterde kalır.
    // Yazılamazsa rezervasyon açık kalır ve tahminiyle sayılır.
    let outcome = match (&reply.result, reply.spend.estimated) {
        (_, true) => "unknown",
        (Ok(_), false) => "success",
        (Err(AiError::Refused), false) => "refused",
        (Err(AiError::Unavailable), false) => "failed",
    };
    settle(&state, &call, &reply.spend, outcome).await?;
    let cost = reply.spend.cost_microusd;

    let mut audit_tx = state.db.begin().await?;
    set_context(&mut audit_tx, Some(call.user_id), Some(call.org_id)).await?;
    let response = match reply.result {
        Ok(answer) => {
            audit::record(
                &mut audit_tx,
                audit::Event {
                    organization_id: Some(call.org_id),
                    actor_user_id: Some(call.user_id),
                    action: "ai.summary_generated",
                    target_type: Some("panel"),
                    target_id: Some(&call.panel_id.to_string()),
                    outcome: audit::Outcome::Success,
                    details: json!({
                        "hours": call.hours,
                        "event_count": call.event_count,
                        "truncated": call.truncated,
                        "generated": answer.generated,
                        "model": answer.spend.model,
                        "input_tokens": answer.spend.input_tokens,
                        "output_tokens": answer.spend.output_tokens,
                        "cost_microusd": cost,
                        "reserved_microusd": call.reserved.cost_microusd,
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
                needs_attention: view.needs_attention,
                stats: view.stats,
                period_start: view.period_start,
                period_end: view.period_end,
                truncated: view.truncated,
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
                    organization_id: Some(call.org_id),
                    actor_user_id: Some(call.user_id),
                    action: "ai.summary_failed",
                    target_type: Some("panel"),
                    target_id: Some(&call.panel_id.to_string()),
                    outcome: audit::Outcome::Failure,
                    details: json!({
                        "hours": call.hours,
                        "event_count": call.event_count,
                        "reason": code,
                        "cost_microusd": cost,
                        "reserved_microusd": call.reserved.cost_microusd,
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
    response
}

/// Rezervasyonu gerçek (veya bilinmiyorsa tahmini) harcamayla kapatır: defter yalnızca eklenir,
/// kapatma ayrı bir satırdır (kendi işleminde, kullanıcı ve organizasyon bağlamıyla).
async fn settle(
    state: &AppState,
    call: &Call,
    spend: &Spend,
    outcome: &'static str,
) -> ApiResult<()> {
    let mut tx = state.db.begin().await?;
    set_context(&mut tx, Some(call.user_id), Some(call.org_id)).await?;
    // Uygulama deftere doğrudan yazamaz: kapanış yalnızca kişinin kendi açık rezervasyonuna,
    // rezervasyonun özelliğiyle bağlanır (`ai_settle`, Y10). Değerler burada negatif olamaz
    // (bilinmeyen veya geçersiz kullanım tahmine dönüşür, bkz. `RawSpend`).
    sqlx::query("SELECT ai_settle($1, $2, $3, $4, $5, $6)")
        .bind(call.reservation_id)
        .bind(
            spend
                .model
                .as_deref()
                .filter(|m| !m.is_empty())
                .map(|m| clip(m, 100)),
        )
        .bind(spend.input_tokens)
        .bind(spend.output_tokens)
        .bind(spend.cost_microusd)
        .bind(outcome)
        .execute(&mut *tx)
        .await
        .inspect_err(|_| {
            tracing::error!("AI harcaması deftere yazılamadı; rezervasyon açık kaldı")
        })?;
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
    fn reservation_covers_every_billable_run_and_fits_the_user_budget() {
        let small = Spend::upper_bound(1_000).cost_microusd;
        // 500 olaylık tipik istek yaklaşık 90 KB.
        let large = Spend::upper_bound(100_000).cost_microusd;
        // İki model çalışması × (4096 çıktı token'ı × 50 + (1000 / 2 + 2048) × 10)
        assert_eq!(small, 2 * (204_800 + 25_480));
        assert!(large > small);
        // Sonucu bilinmeyen en büyük çağrıdan sonra bir sonrakinin rezervasyonu da sığar.
        assert!(2 * large < USER_DAILY_MICROUSD, "{large}");
        assert!(Spend::upper_bound(100_000).estimated);
        assert_eq!(Spend::none().cost_microusd, 0);
        assert!(!Spend::none().estimated);
    }

    #[test]
    fn service_error_without_billing_flag_is_treated_as_billed() {
        let error: ServiceError =
            serde_json::from_str(r#"{"detail": "ai_unavailable", "usage": null}"#).expect("json");
        assert!(error.may_be_billed);
        let error: ServiceError = serde_json::from_str(
            r#"{"detail": "unauthorized", "usage": null, "may_be_billed": false}"#,
        )
        .expect("json");
        assert!(!error.may_be_billed);
    }

    #[test]
    fn clip_collapses_whitespace_and_limits_characters() {
        assert_eq!(clip("  bir\n\niki   üç ", 100), "bir iki üç");
        assert_eq!(clip("ğğğğ", 2), "ğğ");
    }
}
