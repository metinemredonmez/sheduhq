//! Push bildirimleri.
//!
//! Teslim kalıcı bir kuyrukla yapılır (BUS-02, ARC-05):
//! 1. Panel olayı yazılınca dağıtıcı olayı **kilitleyerek** alır (`FOR UPDATE SKIP LOCKED`),
//!    alıcıları yetkiye göre bulur, her alıcı cihaz için `pending` bir teslim işi yazar ve olayı
//!    "dağıtıldı" işaretler. Birden fazla API kopyası aynı olayı iki kez dağıtmaz.
//! 2. Her iş kısa bir işlemde süreli olarak alınır (`sending`, `lease_until`), sağlayıcıya
//!    **veritabanı işlemi dışında** gönderilir ve sonuç ayrı bir işlemde yazılır. Sağlayıcıyı
//!    beklerken bağlantı veya kilit tutulmaz.
//! 3. Geçici hata artan aralıklarla yeniden denenir; deneme hakkı veya süre dolarsa iş `failed`
//!    olur ve hata olarak loglanır. Süreç gönderim sırasında kesilirse süre dolunca iş yeniden
//!    alınır: bildirim kaybolmaz (en az bir kez). Aynı bildirimin ikinci kez gitmesi yalnızca
//!    sağlayıcının kabulü ile sonucun yazılması arasındaki kesintide olur; sağlayıcı bağdaştırıcısı
//!    `collapse_key`'i (APNs `apns-collapse-id`, FCM `collapse_key`) kullanarak cihazda tekilleştirir.
//! 4. Kaçırılan olaylar ve zamanı gelen işler düzenli taramayla yakalanır. Tarama yeni olayların
//!    dağıtımından ayrı yürür ve işler sınırlı sayıda eşzamanlı gönderilir: yavaş veya düşmüş bir
//!    sağlayıcı (iş başına en çok `SEND_TIMEOUT`) yeni alarmları ve öbür platformu bekletmez.
//!
//! Alıcılar: organizasyonun yöneticileri, operatörleri ve o panelde (bölüm düzeyinde) geçerli görme
//! yetkisi olan üyeler; yalnızca etkin oturumu (`session_active`) olan ve push token'ı kayıtlı
//! cihazlar. Çıkış yapılmış cihaza bildirim gitmez; gönderim anında token silinmişse iş iptal olur.
//!
//! Sağlayıcılar `providers` modülündedir: iOS → APNs, Android → FCM. Üretimde ikisi de
//! yapılandırılmadan API başlamaz. Gönderimin üst süresi (`SEND_TIMEOUT`) `LEASE_SECS`'ten kısadır.
//!
//! İçerik: bildirim Apple ve Google sunucularından geçer. KVKK aktarım kararına kadar (açık soru
//! 11) varsayılan içerik kısadır: başlık "Shedu", metin yalnızca olay türü; panel, bölüm ve zon
//! adları (kullanıcının verdiği adlar) gitmez. Ayrıntı uygulamada açılır. `SHEDU_PUSH_CONTENT=full`
//! adları da gönderir. Bildirim merkezi (uygulama içi) her zaman tam metni gösterir.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures_util::{StreamExt, stream};
use serde::Serialize;
use tokio::{
    sync::{Semaphore, broadcast::error::RecvError},
    time::MissedTickBehavior,
};
use uuid::Uuid;

use crate::{AppState, db::set_context, notifications};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PushPriority {
    /// Bilgi: normal kanal.
    Info,
    /// Uyarı: yüksek öncelik.
    Warning,
    /// Kritik: iOS'ta "critical alert", Android'de sessiz modu aşan alarm kanalı.
    Critical,
}

impl PushPriority {
    fn parse(value: &str) -> Self {
        match value {
            "critical" => Self::Critical,
            "warning" => Self::Warning,
            _ => Self::Info,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

/// Push bildiriminin içeriği.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PushContent {
    /// Başlık "Shedu", metin yalnızca olay türü; ad gitmez.
    #[default]
    Minimal,
    /// Başlıkta panel adı, metinde bölüm ve zon adı.
    Full,
}

#[derive(Debug, Clone, Serialize)]
pub struct PushMessage {
    /// Cihazın push token'ı. Log'a yazılmaz.
    #[serde(skip)]
    pub token: String,
    pub platform: String,
    pub user_id: Uuid,
    pub priority: PushPriority,
    pub title: String,
    pub body: String,
    pub organization_id: Uuid,
    pub panel_id: Uuid,
    pub event_id: i64,
    pub kind: String,
    /// Aynı bildirimin tekrarını cihazda tekilleştirme anahtarı (APNs `apns-collapse-id`, FCM
    /// `collapse_key`). Olay başına sabittir.
    pub collapse_key: String,
    /// Bu andan sonra (Unix saniye) bildirim gösterilmez: olayın alınmasından bir saat sonrası.
    /// Sağlayıcı cihaza o zamana kadar ulaşamazsa bildirimi atar.
    pub expires_at: u64,
}

pub type PushFuture<'a> = Pin<Box<dyn Future<Output = Result<(), PushError>> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushError {
    /// Geçici hata (ağ, sağlayıcı yoğunluğu, yapılandırma): yeniden denenir.
    Transient,
    /// Token geçersiz veya cihaz sağlayıcıda kayıtlı değil: yeniden denenmez, token silinir.
    InvalidToken,
    /// Sağlayıcı isteği kalıcı olarak reddetti (bozuk yük, yanlış yapılandırma, sağlayıcısı
    /// olmayan platform): yeniden denenmez, token silinmez, hata olarak loglanır.
    Rejected,
}

pub trait PushSender: Send + Sync {
    fn send<'a>(&'a self, message: &'a PushMessage) -> PushFuture<'a>;
}

/// Sağlayıcı yapılandırılmadı: her gönderim başarısız sayılır ve hata kaydı düşer.
pub struct DisabledPush;

impl PushSender for DisabledPush {
    fn send<'a>(&'a self, _message: &'a PushMessage) -> PushFuture<'a> {
        Box::pin(async { Err(PushError::Transient) })
    }
}

/// Yalnızca geliştirme: bildirimi konsola yazar (token yazılmaz).
pub struct DevConsolePush;

impl PushSender for DevConsolePush {
    fn send<'a>(&'a self, message: &'a PushMessage) -> PushFuture<'a> {
        Box::pin(async move {
            println!(
                "[geliştirme push] {:?} {} -> {}: {}",
                message.priority, message.platform, message.title, message.body
            );
            Ok(())
        })
    }
}

/// Testler için: gönderilen bildirimleri bellekte tutar; istenirse sonraki gönderimleri hatayla
/// düşürür.
#[derive(Clone)]
pub struct RecordingPush {
    sent: Arc<Mutex<Vec<PushMessage>>>,
    failures: Arc<Mutex<(usize, PushError)>>,
    delay: Arc<Mutex<Duration>>,
}

impl Default for RecordingPush {
    fn default() -> Self {
        Self {
            sent: Arc::default(),
            failures: Arc::new(Mutex::new((0, PushError::Transient))),
            delay: Arc::default(),
        }
    }
}

impl RecordingPush {
    pub fn messages(&self) -> Vec<PushMessage> {
        self.sent
            .lock()
            .map(|sent| sent.clone())
            .unwrap_or_default()
    }

    /// Sonraki `count` gönderim geçici hata verir.
    pub fn fail_next(&self, count: usize) {
        self.fail_next_with(count, PushError::Transient);
    }

    /// Her gönderim bu kadar bekler (yavaş sağlayıcı).
    pub fn set_delay(&self, delay: Duration) {
        if let Ok(mut current) = self.delay.lock() {
            *current = delay;
        }
    }

    /// Sonraki `count` gönderim verilen hatayı verir.
    pub fn fail_next_with(&self, count: usize, error: PushError) {
        if let Ok(mut failures) = self.failures.lock() {
            *failures = (count, error);
        }
    }
}

impl PushSender for RecordingPush {
    fn send<'a>(&'a self, message: &'a PushMessage) -> PushFuture<'a> {
        Box::pin(async move {
            let delay = self.delay.lock().map(|d| *d).unwrap_or_default();
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let failing = self.failures.lock().ok().and_then(|mut failures| {
                let (count, error) = *failures;
                failures.0 = count.saturating_sub(1);
                (count > 0).then_some(error)
            });
            if let Some(error) = failing {
                return Err(error);
            }
            if let Ok(mut sent) = self.sent.lock() {
                sent.push(message.clone());
            }
            Ok(())
        })
    }
}

/// Alınmış işin süresi: süreç bu sürede sonucu yazamazsa iş yeniden alınır.
const LEASE_SECS: f64 = 30.0;
/// Bir teslim işinin en fazla deneme sayısı.
const MAX_ATTEMPTS: i16 = 6;
/// Bu kadar eski bildirim artık gönderilmez: bir saat sonra gelen alarm bildirimi yanıltıcıdır.
/// Yaş olayın alınma zamanından ölçülür (iş ne zaman yazılmış olursa olsun).
const MAX_AGE_MINUTES: i32 = 60;
/// Sağlayıcı çağrısının en uzun süresi. İşin süresinden (`LEASE_SECS`) kısa olmalı: yavaş sağlayıcı
/// beklenirken iş başka bir kopyaya geçmez, tarama da tek bir çağrıda takılı kalmaz.
const SEND_TIMEOUT: Duration = Duration::from_secs(20);

/// Aynı anda dağıtılan en fazla olay sayısı (kopya başına).
const CONCURRENT_EVENTS: usize = 3;
/// Bir grupta aynı anda gönderilen en fazla teslim işi. Her iş veritabanı bağlantısını yalnızca
/// kısa işlemlerde tutar, sağlayıcıyı beklerken tutmaz; havuz (20) bu sınırlarla dolmaz.
const CONCURRENT_DELIVERIES: usize = 4;

/// Geçici hatadan sonra bir sonraki denemeye kadar bekleme (saniye).
fn retry_delay_secs(attempts: i16) -> f64 {
    match attempts {
        ..=1 => 5.0,
        2 => 15.0,
        3 => 60.0,
        4 => 120.0,
        _ => 300.0,
    }
}

/// Olay bildirimlerini dinleyen dağıtıcı ve kaçırılan olaylar için düzenli tarama.
///
/// İkisi aynı görevde ama birbirini beklemeden yürür: tarama sağlayıcı yanıtını beklerken yeni
/// olaylar dağıtılmaya devam eder. Her yeni olay ayrı görevde dağıtılır (aynı anda en çok
/// `CONCURRENT_EVENTS`). Tarama turu bitmeden sonraki başlamaz; turlar arasında en az 5 saniye
/// vardır.
pub fn start_dispatcher(state: &AppState) -> tokio::task::JoinHandle<()> {
    let state = state.clone();
    tokio::spawn(async move {
        let listen = async {
            let mut events = state.events.subscribe();
            let limit = Arc::new(Semaphore::new(CONCURRENT_EVENTS));
            loop {
                match events.recv().await {
                    Ok(event) if event.kind == "panel_event" => {
                        let Ok(id) = event.id.parse::<i64>() else {
                            continue;
                        };
                        let Ok(permit) = limit.clone().acquire_owned().await else {
                            break;
                        };
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(error) = dispatch(&state, event.org, id).await {
                                tracing::warn!(
                                    ?error,
                                    event_id = id,
                                    "push dağıtımı başarısız; tarama yeniden deneyecek"
                                );
                            }
                            drop(permit);
                        });
                    }
                    Ok(_) => {}
                    // Kaçırılan olayları tarama yakalar (`pending_panel_events`).
                    Err(RecvError::Lagged(skipped)) => {
                        tracing::warn!(skipped, "olay akışında gecikme; tarama yakalayacak");
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        };
        let sweep = async {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                sweep_pending(&state).await;
            }
        };
        tokio::select! {
            () = listen => {}
            () = sweep => {}
        }
    })
}

/// Düzenli tarama: önce bitmesi gereken işleri kapatır (deneme hakkı veya süre doldu), sonra
/// kaçırılan olayları (birkaç saniyeden eski, dağıtılmamış) dağıtır ve zamanı gelen teslim
/// işlerini (yeniden deneme, süresi dolmuş alınmış iş) gönderir. İşlenen olay ve iş sayısını döner.
///
/// Her adım ve her kayıt ayrı ele alınır: bir kaydın hatası loglanır ve tarama diğer kayıtlarla
/// (başka organizasyonların işleriyle) sürer (BUS-02).
pub async fn sweep_pending(state: &AppState) -> usize {
    match sqlx::query_scalar::<_, i32>("SELECT reap_push_deliveries($1, $2)")
        .bind(i32::from(MAX_ATTEMPTS))
        .bind(MAX_AGE_MINUTES)
        .fetch_one(&state.db)
        .await
    {
        Ok(0) => {}
        Ok(reaped) => tracing::error!(
            reaped,
            "push bildirimleri deneme hakkı veya süre dolduğu için gönderilmedi"
        ),
        Err(error) => tracing::warn!(?error, "biten push işleri kapatılamadı"),
    }

    let mut count = 0;
    match sqlx::query_as::<_, (i64, Uuid)>(
        "SELECT id, organization_id FROM pending_panel_events(100)",
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(pending) => {
            let results: Vec<_> = stream::iter(pending)
                .map(|(id, organization_id)| async move {
                    (id, dispatch(state, organization_id, id).await)
                })
                .buffer_unordered(CONCURRENT_EVENTS)
                .collect()
                .await;
            for (id, result) in results {
                match result {
                    Ok(_) => count += 1,
                    Err(error) => tracing::warn!(
                        ?error,
                        event_id = id,
                        "olay dağıtılamadı; sonraki taramada yeniden denenecek"
                    ),
                }
            }
        }
        Err(error) => tracing::warn!(?error, "dağıtılmamış olaylar okunamadı"),
    }

    match sqlx::query_as::<_, (i64, Uuid)>(
        "SELECT id, organization_id FROM due_push_deliveries(200)",
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(due) => {
            let results: Vec<_> = stream::iter(due)
                .map(|(id, organization_id)| async move {
                    (id, deliver(state, organization_id, id).await)
                })
                .buffer_unordered(CONCURRENT_DELIVERIES)
                .collect()
                .await;
            for (id, result) in results {
                match result {
                    Ok(Delivery::Skipped) => {}
                    Ok(_) => count += 1,
                    Err(error) => tracing::warn!(
                        ?error,
                        delivery_id = id,
                        "push işi işlenemedi; sonraki taramada yeniden denenecek"
                    ),
                }
            }
        }
        Err(error) => tracing::warn!(?error, "zamanı gelen push işleri okunamadı"),
    }
    count
}

/// Alınan iş: olay, kişi, cihaz, deneme, öncelik, süresi geçti mi, son geçerlilik (Unix sn).
type ClaimRow = (i64, Uuid, Option<Uuid>, i16, String, bool, i64);

type EventRow = (
    Uuid,
    String,
    Option<String>,
    Option<String>,
    String,
    Option<i16>,
    Option<i16>,
    String,
    Option<String>,
    Option<String>,
);

/// Tek bir olayı dağıtır ve oluşan teslim işlerini hemen gönderir; gönderilen bildirim sayısını
/// döner. Olay başka bir kopya tarafından işleniyorsa veya zaten dağıtıldıysa hiçbir şey yapmaz.
pub async fn dispatch(
    state: &AppState,
    organization_id: Uuid,
    event_id: i64,
) -> Result<usize, sqlx::Error> {
    let deliveries = fan_out(state, organization_id, event_id).await?;
    let results: Vec<_> = stream::iter(deliveries)
        .map(|id| deliver(state, organization_id, id))
        .buffer_unordered(CONCURRENT_DELIVERIES)
        .collect()
        .await;
    let mut sent = 0;
    for result in results {
        if result? == Delivery::Sent {
            sent += 1;
        }
    }
    Ok(sent)
}

/// Olayın alıcılarını bulur ve her cihaz için teslim işi yazar (tek ve kısa işlem).
async fn fan_out(
    state: &AppState,
    organization_id: Uuid,
    event_id: i64,
) -> Result<Vec<i64>, sqlx::Error> {
    let mut tx = state.db.begin().await?;
    set_context(&mut tx, None, Some(organization_id)).await?;

    let claimed: Option<(Uuid, String, String, Option<i16>, bool)> = sqlx::query_as(
        "SELECT panel_id, kind, priority, partition_number,
                received_at < now() - make_interval(mins => $3)
           FROM panel_events
          WHERE id = $1 AND organization_id = $2 AND notified_at IS NULL
          FOR UPDATE SKIP LOCKED",
    )
    .bind(event_id)
    .bind(organization_id)
    .bind(MAX_AGE_MINUTES)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((panel_id, kind, priority, partition_number, too_old)) = claimed else {
        tx.commit().await?;
        return Ok(Vec::new());
    };
    // Geç dağıtılan (ör. kesintiden sonra) eski olay için iş yazılmaz: bir saat sonra gelen alarm
    // bildirimi yanıltıcıdır. Olay yalnızca dağıtıldı işaretlenir; geçmişte ve bildirim merkezinde
    // görünmeye devam eder.
    if too_old {
        sqlx::query("UPDATE panel_events SET notified_at = now() WHERE id = $1")
            .bind(event_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        tracing::error!(
            event_id,
            "olay geç dağıtıldı; push bildirimi süresi dolduğu için gönderilmedi"
        );
        return Ok(Vec::new());
    }

    // Kapatılabilen kategorideyse kişinin tercihi uygulanır; bilinmeyen tür ve alarm her zaman
    // gönderilir (şüphede bildirim gider).
    let muteable = notifications::category_of_event(&kind)
        .filter(|category| category.can_be_disabled())
        .map(notifications::category_name);
    // Alıcı kuralı veritabanında tek yerde (`push_recipient_eligible`): üyelik, etkin hesap,
    // kategori tercihi, etkin oturum (personelde ikinci adım) ve panel/bölüm görme yetkisi. Aynı
    // kural gönderimden hemen önce yeniden uygulanır (Y01).
    let recipients: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT d.id, d.user_id
           FROM user_devices d
           JOIN memberships m ON m.user_id = d.user_id AND m.organization_id = $1
          WHERE d.push_token IS NOT NULL
            AND push_recipient_eligible(d.id, d.user_id, $1, $2, $3, $4)",
    )
    .bind(organization_id)
    .bind(panel_id)
    .bind(partition_number)
    .bind(muteable)
    .fetch_all(&mut *tx)
    .await?;

    let priority = PushPriority::parse(&priority);
    let mut deliveries = Vec::with_capacity(recipients.len());
    for (device_id, user_id) in recipients {
        let id: Option<(i64,)> = sqlx::query_as(
            "INSERT INTO push_deliveries (organization_id, panel_event_id, user_id, device_id, priority, status)
             VALUES ($1, $2, $3, $4, $5, 'pending')
             ON CONFLICT (panel_event_id, device_id) DO NOTHING
             RETURNING id",
        )
        .bind(organization_id)
        .bind(event_id)
        .bind(user_id)
        .bind(device_id)
        .bind(priority.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        deliveries.extend(id.map(|(id,)| id));
    }

    sqlx::query("UPDATE panel_events SET notified_at = now() WHERE id = $1")
        .bind(event_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(deliveries)
}

/// Bir teslim işinin sonucu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    /// İş başka bir kopyada veya zamanı gelmemiş: dokunulmadı.
    Skipped,
    Sent,
    /// Yeniden denenecek.
    Retrying,
    /// Gönderilmeyecek (deneme hakkı/süre doldu, token geçersiz, cihaz çıkış yaptı).
    Abandoned,
}

/// Bir teslim işini alır, gönderir ve sonucunu yazar.
async fn deliver(
    state: &AppState,
    organization_id: Uuid,
    delivery_id: i64,
) -> Result<Delivery, sqlx::Error> {
    // 1. İş kısa bir işlemde süreli olarak alınır. Aynı işi iki kopya aynı anda alamaz: ikincisi
    //    satır kilidini bekler ve koşulu yeniden değerlendirince işi alınmış bulur.
    let mut tx = state.db.begin().await?;
    set_context(&mut tx, None, Some(organization_id)).await?;
    //    Deneme hakkı biten iş alınmaz (taramadaki kapatma onu `failed` yapar); yaş olayın alınma
    //    zamanından ölçülür.
    let claimed: Option<ClaimRow> = sqlx::query_as(
        "UPDATE push_deliveries d
            SET status = 'sending', attempts = d.attempts + 1, updated_at = now(),
                lease_until = now() + make_interval(secs => $2)
           FROM panel_events e
          WHERE d.id = $1
            AND e.id = d.panel_event_id AND e.organization_id = d.organization_id
            AND d.attempts < $4
            AND ((d.status = 'pending' AND d.next_attempt_at <= now())
                 OR (d.status = 'sending' AND d.lease_until < now()))
          RETURNING d.panel_event_id, d.user_id, d.device_id, d.attempts, d.priority,
                    e.received_at < now() - make_interval(mins => $3),
                    extract(epoch FROM e.received_at + make_interval(mins => $3))::bigint",
    )
    .bind(delivery_id)
    .bind(LEASE_SECS)
    .bind(MAX_AGE_MINUTES)
    .bind(MAX_ATTEMPTS)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((event_id, user_id, device_id, attempt, priority, too_old, expires_at)) = claimed
    else {
        tx.commit().await?;
        return Ok(Delivery::Skipped);
    };
    if too_old {
        finish(&mut tx, delivery_id, attempt, "failed", None).await?;
        tx.commit().await?;
        tracing::error!(
            event_id,
            delivery_id,
            "push bildirimi süresi dolduğu için gönderilmedi"
        );
        return Ok(Delivery::Abandoned);
    }

    let (panel_id, kind, alarm_kind, arm_mode, _, partition_number, zone_number, panel_name, partition_name, zone_name): EventRow =
        sqlx::query_as(
            "SELECT e.panel_id, e.kind, e.alarm_kind, e.arm_mode, e.priority, e.partition_number, e.zone_number,
                    p.name, pt.name, z.name
               FROM panel_events e
               JOIN panels p ON p.id = e.panel_id
               LEFT JOIN partitions pt ON pt.panel_id = e.panel_id AND pt.number = e.partition_number
               LEFT JOIN zones z ON z.panel_id = e.panel_id AND z.number = e.zone_number
              WHERE e.id = $1",
        )
        .bind(event_id)
        .fetch_one(&mut *tx)
        .await?;

    // Alıcı gönderim anında yeniden denetlenir ve token aynı sorguda okunur: kuyrukta beklerken
    // çıkış yapan, üyeliği veya yetkisi kalkan, oturumu biten ya da kategoriyi kapatan kişiye
    // bildirim gitmez (AZ-04, SES-04). İş iptal edilir.
    let muteable = notifications::category_of_event(&kind)
        .filter(|category| category.can_be_disabled())
        .map(notifications::category_name);
    let device: Option<(String, String)> = match device_id {
        Some(device_id) => {
            sqlx::query_as(
                "SELECT push_token, platform FROM user_devices
                  WHERE id = $1 AND user_id = $2 AND push_token IS NOT NULL
                    AND push_recipient_eligible(id, user_id, $3, $4, $5, $6)",
            )
            .bind(device_id)
            .bind(user_id)
            .bind(organization_id)
            .bind(panel_id)
            .bind(partition_number)
            .bind(muteable)
            .fetch_optional(&mut *tx)
            .await?
        }
        None => None,
    };
    let Some((token, platform)) = device else {
        finish(&mut tx, delivery_id, attempt, "cancelled", None).await?;
        tx.commit().await?;
        return Ok(Delivery::Abandoned);
    };
    tx.commit().await?;

    let (title, body) = match state.push_content {
        PushContent::Full => text(
            &kind,
            alarm_kind.as_deref(),
            arm_mode.as_deref(),
            &panel_name,
            partition_name.as_deref(),
            zone_name.as_deref(),
            zone_number,
        ),
        PushContent::Minimal => minimal_text(&kind, alarm_kind.as_deref(), arm_mode.as_deref()),
    };
    let message = PushMessage {
        token,
        platform,
        user_id,
        priority: PushPriority::parse(&priority),
        title,
        body,
        organization_id,
        panel_id,
        event_id,
        kind,
        collapse_key: format!("shedu-event-{event_id}"),
        expires_at: u64::try_from(expires_at).unwrap_or_default(),
    };

    // 2. Gönderim veritabanı işlemi dışında ve süre sınırıyla; süre dolarsa geçici hata sayılır.
    let result = match tokio::time::timeout(SEND_TIMEOUT, state.push.send(&message)).await {
        Ok(result) => result,
        Err(_) => {
            tracing::warn!(
                event_id,
                delivery_id,
                "push sağlayıcısı zamanında yanıt vermedi"
            );
            Err(PushError::Transient)
        }
    };

    // 3. Sonuç ayrı işlemde yazılır; yalnızca bu denemenin aldığı iş güncellenir.
    let mut tx = state.db.begin().await?;
    set_context(&mut tx, None, Some(organization_id)).await?;
    let outcome = match result {
        Ok(()) => {
            finish(&mut tx, delivery_id, attempt, "sent", None).await?;
            Delivery::Sent
        }
        Err(PushError::InvalidToken) => {
            // Token yalnızca bu deneme işin sahibiyse silinir: süresi dolup başka bir kopyaya geçmiş
            // işin eski sonucu, o arada yenilenmiş kaydı değiştirmez.
            if finish(&mut tx, delivery_id, attempt, "failed", None).await? {
                sqlx::query(
                    "UPDATE user_devices SET push_token = NULL WHERE id = $1 AND push_token = $2",
                )
                .bind(device_id)
                .bind(&message.token)
                .execute(&mut *tx)
                .await?;
                tracing::warn!(
                    event_id,
                    delivery_id,
                    "push token geçersiz; cihazın token'ı silindi"
                );
            }
            Delivery::Abandoned
        }
        Err(PushError::Rejected) => {
            finish(&mut tx, delivery_id, attempt, "failed", None).await?;
            tracing::error!(
                event_id,
                delivery_id,
                "push sağlayıcısı bildirimi reddetti; yeniden denenmeyecek"
            );
            Delivery::Abandoned
        }
        Err(PushError::Transient) if attempt >= MAX_ATTEMPTS => {
            finish(&mut tx, delivery_id, attempt, "failed", None).await?;
            tracing::error!(
                event_id,
                delivery_id,
                attempt,
                "push bildirimi kalıcı olarak gönderilemedi"
            );
            Delivery::Abandoned
        }
        Err(PushError::Transient) => {
            finish(
                &mut tx,
                delivery_id,
                attempt,
                "pending",
                Some(retry_delay_secs(attempt)),
            )
            .await?;
            tracing::warn!(
                event_id,
                delivery_id,
                attempt,
                "push gönderilemedi; yeniden denenecek"
            );
            Delivery::Retrying
        }
    };
    tx.commit().await?;
    Ok(outcome)
}

/// Alınmış işin sonucunu yazar. `retry_in` verilirse iş o kadar saniye sonra yeniden denenir.
/// Yalnızca bu denemenin aldığı iş güncellenir; iş başka bir denemeye geçtiyse `false` döner.
async fn finish(
    conn: &mut sqlx::PgConnection,
    delivery_id: i64,
    attempt: i16,
    status: &'static str,
    retry_in: Option<f64>,
) -> Result<bool, sqlx::Error> {
    let updated = sqlx::query(
        "UPDATE push_deliveries
            SET status = $3, lease_until = NULL, updated_at = now(),
                sent_at = CASE WHEN $3 = 'sent' THEN now() END,
                next_attempt_at = CASE WHEN $4::float8 IS NULL THEN next_attempt_at
                                       ELSE now() + make_interval(secs => $4) END
          WHERE id = $1 AND status = 'sending' AND attempts = $2",
    )
    .bind(delivery_id)
    .bind(attempt)
    .bind(status)
    .bind(retry_in)
    .execute(conn)
    .await?;
    Ok(updated.rows_affected() == 1)
}

fn alarm_label(alarm_kind: Option<&str>) -> &'static str {
    match alarm_kind {
        Some("intrusion") => "Hırsızlık alarmı",
        Some("keypad_or_keyfob") => "Tuş takımı / kumanda alarmı",
        Some("panic") => "Panik alarmı",
        Some("fire") => "Yangın alarmı",
        Some("medical") => "Tıbbi acil durum",
        Some("tamper") => "Sabotaj alarmı",
        Some("gas") => "Gaz kaçağı alarmı",
        Some("flood") => "Su baskını alarmı",
        _ => "Alarm",
    }
}

/// Kısa içerik: başlık "Shedu", metin yalnızca olay türü. Kullanıcının verdiği adlar (panel,
/// bölüm, zon) yurt dışındaki push sağlayıcısına gitmez.
pub(crate) fn minimal_text(
    kind: &str,
    alarm_kind: Option<&str>,
    arm_mode: Option<&str>,
) -> (String, String) {
    let body = match kind {
        "alarm" => alarm_label(alarm_kind).to_owned(),
        "armed" => match arm_mode {
            Some("stay") => "Sistem evde kipinde kuruldu".to_owned(),
            Some("night") => "Sistem gece kipinde kuruldu".to_owned(),
            _ => "Sistem kuruldu".to_owned(),
        },
        "disarmed" => "Sistem kapatıldı".to_owned(),
        "disconnected" => "Panel bağlantısı koptu".to_owned(),
        "connected" => "Panel yeniden bağlandı".to_owned(),
        "power_problem" => "Güç sorunu (pil veya şebeke)".to_owned(),
        _ => "Yeni olay".to_owned(),
    };
    ("Shedu".to_owned(), body)
}

pub(crate) fn text(
    kind: &str,
    alarm_kind: Option<&str>,
    arm_mode: Option<&str>,
    panel: &str,
    partition: Option<&str>,
    zone: Option<&str>,
    zone_number: Option<i16>,
) -> (String, String) {
    let place = partition.unwrap_or(panel);
    let body = match kind {
        "alarm" => match (zone, zone_number) {
            (Some(zone), _) => format!("{} — {zone}", alarm_label(alarm_kind)),
            (None, Some(number)) => format!("{} — zon {number}", alarm_label(alarm_kind)),
            _ => alarm_label(alarm_kind).to_owned(),
        },
        "armed" => match arm_mode {
            Some("stay") => format!("{place} evde kipinde kuruldu"),
            Some("night") => format!("{place} gece kipinde kuruldu"),
            _ => format!("{place} kuruldu"),
        },
        "disarmed" => format!("{place} kapatıldı"),
        "disconnected" => "Panel bağlantısı koptu".to_owned(),
        "connected" => "Panel yeniden bağlandı".to_owned(),
        "power_problem" => "Güç sorunu (pil veya şebeke)".to_owned(),
        _ => "Yeni olay".to_owned(),
    };
    (panel.to_owned(), body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alarm_text_names_kind_and_zone() {
        let (title, body) = text(
            "alarm",
            Some("fire"),
            None,
            "Ev paneli",
            Some("Ev"),
            Some("Mutfak duman"),
            Some(3),
        );
        assert_eq!(title, "Ev paneli");
        assert_eq!(body, "Yangın alarmı — Mutfak duman");
    }

    #[test]
    fn arm_text_uses_partition_and_mode() {
        let (_, body) = text(
            "armed",
            None,
            Some("night"),
            "Ev paneli",
            Some("Ev"),
            None,
            None,
        );
        assert_eq!(body, "Ev gece kipinde kuruldu");
    }

    #[test]
    fn minimal_text_never_contains_names() {
        let (title, body) = minimal_text("alarm", Some("fire"), None);
        assert_eq!((title.as_str(), body.as_str()), ("Shedu", "Yangın alarmı"));
        let (_, body) = minimal_text("armed", None, Some("night"));
        assert_eq!(body, "Sistem gece kipinde kuruldu");
        let (_, body) = minimal_text("disarmed", None, None);
        assert_eq!(body, "Sistem kapatıldı");
    }

    #[test]
    fn push_message_serialization_never_contains_token() {
        let message = PushMessage {
            token: "gizli-cihaz-tokeni".into(),
            platform: "ios".into(),
            user_id: Uuid::new_v4(),
            priority: PushPriority::Critical,
            title: "t".into(),
            body: "b".into(),
            organization_id: Uuid::new_v4(),
            panel_id: Uuid::new_v4(),
            event_id: 1,
            kind: "alarm".into(),
            collapse_key: "shedu-event-1".into(),
            expires_at: 0,
        };
        assert!(
            !serde_json::to_string(&message)
                .unwrap_or_default()
                .contains("gizli-cihaz-tokeni")
        );
    }
}
