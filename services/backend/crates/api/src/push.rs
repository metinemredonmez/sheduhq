//! Push bildirimleri.
//!
//! Panel olayı yazıldığında veritabanı bildirim gönderir; dağıtıcı olayı **kilitleyerek** alır
//! (`FOR UPDATE SKIP LOCKED`), alıcıları yetkiye göre bulur, gönderir, teslim kaydını yazar ve
//! olayı "bildirildi" işaretler. Böylece:
//! - birden fazla API kopyası aynı olayı iki kez göndermez;
//! - gönderim sırasında süreç çökerse işlem geri alınır, düzenli tarama olayı yeniden dener:
//!   alarm bildirimi kaybolmaz.
//!
//! Alıcılar: organizasyonun yöneticileri ve o panelde (bölüm düzeyinde) geçerli görme yetkisi olan
//! üyeler; yalnızca etkin oturumu olan ve push token'ı kayıtlı cihazlar. Çıkış yapılmış cihaza
//! bildirim gitmez.
//!
//! Gerçek sağlayıcılar (FCM, APNs) henüz bağlanmadı; üretimde sağlayıcı yoksa API başlamaz.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use serde::Serialize;
use tokio::sync::broadcast::error::RecvError;
use uuid::Uuid;

use crate::{AppState, db::set_context};

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
}

pub type PushFuture<'a> = Pin<Box<dyn Future<Output = Result<(), PushError>> + Send + 'a>>;

#[derive(Debug)]
pub struct PushError;

pub trait PushSender: Send + Sync {
    fn send<'a>(&'a self, message: &'a PushMessage) -> PushFuture<'a>;
}

/// Sağlayıcı yapılandırılmadı: her gönderim başarısız sayılır ve hata kaydı düşer.
pub struct DisabledPush;

impl PushSender for DisabledPush {
    fn send<'a>(&'a self, _message: &'a PushMessage) -> PushFuture<'a> {
        Box::pin(async { Err(PushError) })
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

/// Testler için: gönderilen bildirimleri bellekte tutar.
#[derive(Default, Clone)]
pub struct RecordingPush {
    sent: Arc<Mutex<Vec<PushMessage>>>,
}

impl RecordingPush {
    pub fn messages(&self) -> Vec<PushMessage> {
        self.sent
            .lock()
            .map(|sent| sent.clone())
            .unwrap_or_default()
    }
}

impl PushSender for RecordingPush {
    fn send<'a>(&'a self, message: &'a PushMessage) -> PushFuture<'a> {
        Box::pin(async move {
            if let Ok(mut sent) = self.sent.lock() {
                sent.push(message.clone());
            }
            Ok(())
        })
    }
}

/// Olay bildirimlerini dinleyen dağıtıcı ve kaçırılan olaylar için düzenli tarama.
pub fn start_dispatcher(state: &AppState) -> tokio::task::JoinHandle<()> {
    let state = state.clone();
    tokio::spawn(async move {
        let mut events = state.events.subscribe();
        let mut sweep = tokio::time::interval(Duration::from_secs(15));
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

/// Bildirimi bekleyen olayları (birkaç saniyeden eski) yeniden dağıtır.
pub async fn sweep_pending(state: &AppState) -> Result<usize, sqlx::Error> {
    let pending: Vec<(i64, Uuid)> =
        sqlx::query_as("SELECT id, organization_id FROM pending_panel_events(100)")
            .fetch_all(&state.db)
            .await?;
    let count = pending.len();
    for (id, organization_id) in pending {
        dispatch(state, organization_id, id).await?;
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
type Recipient = (Uuid, Uuid, String, String);

/// Tek bir olayın bildirimlerini gönderir. Olay başka bir kopya tarafından işleniyorsa veya zaten
/// bildirildiyse hiçbir şey yapmaz.
pub async fn dispatch(
    state: &AppState,
    organization_id: Uuid,
    event_id: i64,
) -> Result<usize, sqlx::Error> {
    let mut tx = state.db.begin().await?;
    set_context(&mut tx, None, Some(organization_id)).await?;

    let claimed: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM panel_events WHERE id = $1 AND notified_at IS NULL FOR UPDATE SKIP LOCKED",
    )
    .bind(event_id)
    .fetch_optional(&mut *tx)
    .await?;
    if claimed.is_none() {
        tx.commit().await?;
        return Ok(0);
    }

    let (panel_id, kind, alarm_kind, arm_mode, priority, partition_number, zone_number, panel_name, partition_name, zone_name): EventRow =
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

    let recipients: Vec<Recipient> = sqlx::query_as(
        "SELECT DISTINCT d.id, d.user_id, d.push_token, d.platform
           FROM user_devices d
           JOIN memberships m ON m.user_id = d.user_id AND m.organization_id = $1
           JOIN users u ON u.id = d.user_id AND u.status = 'active'
          WHERE d.push_token IS NOT NULL
            AND EXISTS (SELECT 1 FROM refresh_tokens r
                         WHERE r.device_id = d.id AND r.revoked_at IS NULL AND r.expires_at > now())
            AND (m.role IN ('owner', 'admin') OR EXISTS (
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
    .fetch_all(&mut *tx)
    .await?;

    let priority = PushPriority::parse(&priority);
    let (title, body) = text(
        &kind,
        alarm_kind.as_deref(),
        arm_mode.as_deref(),
        &panel_name,
        partition_name.as_deref(),
        zone_name.as_deref(),
        zone_number,
    );

    let mut sent = 0;
    for (device_id, user_id, token, platform) in recipients {
        let message = PushMessage {
            token,
            platform,
            user_id,
            priority,
            title: title.clone(),
            body: body.clone(),
            organization_id,
            panel_id,
            event_id,
            kind: kind.clone(),
        };
        let status = match state.push.send(&message).await {
            Ok(()) => {
                sent += 1;
                "sent"
            }
            Err(_) => {
                tracing::error!(event_id, %device_id, "push gönderilemedi");
                "failed"
            }
        };
        sqlx::query(
            "INSERT INTO push_deliveries (organization_id, panel_event_id, user_id, device_id, priority, status)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(organization_id)
        .bind(event_id)
        .bind(user_id)
        .bind(device_id)
        .bind(priority.as_str())
        .bind(status)
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query("UPDATE panel_events SET notified_at = now() WHERE id = $1")
        .bind(event_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(sent)
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

fn text(
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
        };
        assert!(
            !serde_json::to_string(&message)
                .unwrap_or_default()
                .contains("gizli-cihaz-tokeni")
        );
    }
}
