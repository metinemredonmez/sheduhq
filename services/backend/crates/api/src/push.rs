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
//! 4. Kaçırılan olaylar ve zamanı gelen işler düzenli taramayla yakalanır.
//!
//! Alıcılar: organizasyonun yöneticileri, operatörleri ve o panelde (bölüm düzeyinde) geçerli görme
//! yetkisi olan üyeler; yalnızca etkin oturumu (`session_active`) olan ve push token'ı kayıtlı
//! cihazlar. Çıkış yapılmış cihaza bildirim gitmez; gönderim anında token silinmişse iş iptal olur.
//!
//! Gerçek sağlayıcılar (FCM, APNs) henüz bağlanmadı; üretimde sağlayıcı yoksa API başlamaz.
//! Bağdaştırıcının gönderim zaman aşımı `LEASE_SECS`'ten kısa olmalıdır.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use serde::Serialize;
use tokio::sync::broadcast::error::RecvError;
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
}

pub type PushFuture<'a> = Pin<Box<dyn Future<Output = Result<(), PushError>> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushError {
    /// Geçici hata (ağ, sağlayıcı yoğunluğu, yapılandırma): yeniden denenir.
    Transient,
    /// Token geçersiz veya cihaz sağlayıcıda kayıtlı değil: yeniden denenmez, token silinir.
    InvalidToken,
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

/// Testler için: gönderilen bildirimleri bellekte tutar; istenirse sonraki gönderimleri geçici
/// hatayla düşürür.
#[derive(Default, Clone)]
pub struct RecordingPush {
    sent: Arc<Mutex<Vec<PushMessage>>>,
    failures: Arc<Mutex<usize>>,
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
        if let Ok(mut failures) = self.failures.lock() {
            *failures = count;
        }
    }
}

impl PushSender for RecordingPush {
    fn send<'a>(&'a self, message: &'a PushMessage) -> PushFuture<'a> {
        Box::pin(async move {
            let failing = self.failures.lock().is_ok_and(|mut failures| {
                let fail = *failures > 0;
                *failures = failures.saturating_sub(1);
                fail
            });
            if failing {
                return Err(PushError::Transient);
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
const MAX_AGE_MINUTES: i32 = 60;

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
pub fn start_dispatcher(state: &AppState) -> tokio::task::JoinHandle<()> {
    let state = state.clone();
    tokio::spawn(async move {
        let mut events = state.events.subscribe();
        let mut sweep = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                received = events.recv() => match received {
                    Ok(event) if event.kind == "panel_event" => {
                        if let Ok(id) = event.id.parse::<i64>()
                            && let Err(error) = dispatch(&state, event.org, id).await
                        {
                            tracing::warn!(?error, event_id = id, "push dağıtımı başarısız; tarama yeniden deneyecek");
                        }
                    }
                    Ok(_) | Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => break,
                },
                _ = sweep.tick() => {
                    if let Err(error) = sweep_pending(&state).await {
                        tracing::warn!(?error, "bekleyen olay taraması başarısız");
                    }
                }
            }
        }
    })
}

/// Kaçırılan olayları (birkaç saniyeden eski, dağıtılmamış) dağıtır ve zamanı gelen teslim
/// işlerini (yeniden deneme, süresi dolmuş alınmış iş) gönderir. İşlenen olay ve iş sayısını döner.
pub async fn sweep_pending(state: &AppState) -> Result<usize, sqlx::Error> {
    let pending: Vec<(i64, Uuid)> =
        sqlx::query_as("SELECT id, organization_id FROM pending_panel_events(100)")
            .fetch_all(&state.db)
            .await?;
    let mut count = pending.len();
    for (id, organization_id) in pending {
        dispatch(state, organization_id, id).await?;
    }
    let due: Vec<(i64, Uuid)> =
        sqlx::query_as("SELECT id, organization_id FROM due_push_deliveries(200)")
            .fetch_all(&state.db)
            .await?;
    for (id, organization_id) in due {
        if deliver(state, organization_id, id).await? != Delivery::Skipped {
            count += 1;
        }
    }
    Ok(count)
}

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
    let mut sent = 0;
    for id in deliveries {
        if deliver(state, organization_id, id).await? == Delivery::Sent {
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

    let claimed: Option<(Uuid, String, String, Option<i16>)> = sqlx::query_as(
        "SELECT panel_id, kind, priority, partition_number FROM panel_events
          WHERE id = $1 AND organization_id = $2 AND notified_at IS NULL
          FOR UPDATE SKIP LOCKED",
    )
    .bind(event_id)
    .bind(organization_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((panel_id, kind, priority, partition_number)) = claimed else {
        tx.commit().await?;
        return Ok(Vec::new());
    };

    // Kapatılabilen kategorideyse kişinin tercihi uygulanır; bilinmeyen tür ve alarm her zaman
    // gönderilir (şüphede bildirim gider).
    let muteable = notifications::category_of_event(&kind)
        .filter(|category| category.can_be_disabled())
        .map(notifications::category_name);
    let recipients: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT DISTINCT d.id, d.user_id
           FROM user_devices d
           JOIN memberships m ON m.user_id = d.user_id AND m.organization_id = $1
           JOIN organizations o ON o.id = m.organization_id
           JOIN users u ON u.id = d.user_id AND u.status = 'active'
          WHERE d.push_token IS NOT NULL
            -- Kişinin kapattığı kategori (alarm hiç kapatılamaz; $4 alarmda NULL'dır).
            AND ($4::text IS NULL OR NOT EXISTS (
                   SELECT 1 FROM notification_preferences np
                    WHERE np.user_id = d.user_id AND np.organization_id = $1
                      AND np.category = $4 AND NOT np.enabled))
            -- Cihazın oturumu etkin (HTTP ile aynı kural: iptal yok, 90 gün, yenilenebilir).
            AND EXISTS (SELECT 1 FROM session_families f
                         WHERE f.device_id = d.id AND f.user_id = d.user_id
                           AND session_active(f.id, f.user_id)
                           -- Personel cihazı yalnızca ikinci adımı tamamlanmış oturumla (AUT-01;
                           -- kural authz::mfa_required ile aynı).
                           AND (o.kind NOT IN ('business', 'monitoring_center')
                                OR m.role NOT IN ('owner', 'admin', 'operator')
                                OR EXISTS (SELECT 1 FROM session_factors sf
                                            WHERE sf.family_id = f.id AND sf.user_id = d.user_id)))
            AND (m.role IN ('owner', 'admin', 'operator') OR EXISTS (
                   SELECT 1 FROM access_grants g
                    WHERE g.user_id = d.user_id AND g.panel_id = $2 AND g.can_view_events
                      AND (g.valid_from IS NULL OR g.valid_from <= now())
                      AND (g.expires_at IS NULL OR g.expires_at > now())
                      AND (g.partition_id IS NULL OR $3::smallint IS NULL
                           OR g.partition_id = (SELECT id FROM partitions WHERE panel_id = $2 AND number = $3))))",
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
    let claimed: Option<(i64, Uuid, Option<Uuid>, i16, String, bool)> = sqlx::query_as(
        "UPDATE push_deliveries d
            SET status = 'sending', attempts = d.attempts + 1, updated_at = now(),
                lease_until = now() + make_interval(secs => $2)
          WHERE d.id = $1
            AND ((d.status = 'pending' AND d.next_attempt_at <= now())
                 OR (d.status = 'sending' AND d.lease_until < now()))
          RETURNING d.panel_event_id, d.user_id, d.device_id, d.attempts, d.priority,
                    d.created_at < now() - make_interval(mins => $3)",
    )
    .bind(delivery_id)
    .bind(LEASE_SECS)
    .bind(MAX_AGE_MINUTES)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((event_id, user_id, device_id, attempt, priority, too_old)) = claimed else {
        tx.commit().await?;
        return Ok(Delivery::Skipped);
    };

    // Token gönderim anında okunur: arada çıkış yapılmışsa (token silindi) iş iptal olur.
    let device: Option<(String, String)> = match device_id {
        Some(device_id) => {
            sqlx::query_as(
                "SELECT push_token, platform FROM user_devices
                  WHERE id = $1 AND user_id = $2 AND push_token IS NOT NULL",
            )
            .bind(device_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
        }
        None => None,
    };
    let (Some((token, platform)), false) = (device, too_old) else {
        finish(
            &mut tx,
            delivery_id,
            attempt,
            if too_old { "failed" } else { "cancelled" },
            None,
        )
        .await?;
        tx.commit().await?;
        if too_old {
            tracing::error!(
                event_id,
                delivery_id,
                "push bildirimi süresi dolduğu için gönderilmedi"
            );
        }
        return Ok(Delivery::Abandoned);
    };

    let (panel_id, kind, alarm_kind, arm_mode, _, _, zone_number, panel_name, partition_name, zone_name): EventRow =
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
    tx.commit().await?;

    let (title, body) = text(
        &kind,
        alarm_kind.as_deref(),
        arm_mode.as_deref(),
        &panel_name,
        partition_name.as_deref(),
        zone_name.as_deref(),
        zone_number,
    );
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
    };

    // 2. Gönderim veritabanı işlemi dışında.
    let result = state.push.send(&message).await;

    // 3. Sonuç ayrı işlemde yazılır; yalnızca bu denemenin aldığı iş güncellenir.
    let mut tx = state.db.begin().await?;
    set_context(&mut tx, None, Some(organization_id)).await?;
    let outcome = match result {
        Ok(()) => {
            finish(&mut tx, delivery_id, attempt, "sent", None).await?;
            Delivery::Sent
        }
        Err(PushError::InvalidToken) => {
            finish(&mut tx, delivery_id, attempt, "failed", None).await?;
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
async fn finish(
    conn: &mut sqlx::PgConnection,
    delivery_id: i64,
    attempt: i16,
    status: &'static str,
    retry_in: Option<f64>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
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
    Ok(())
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
        };
        assert!(
            !serde_json::to_string(&message)
                .unwrap_or_default()
                .contains("gizli-cihaz-tokeni")
        );
    }
}
