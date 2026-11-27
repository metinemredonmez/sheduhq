//! Panelden gelen bildirimler ve öncelikleri.
//!
//! Öncelik, bildirimin hangi kanaldan gideceğini belirler: kritik bildirimler sessiz modu aşan
//! kanaldan gönderilir ve izleme merkezinde operatör kuyruğunun başına geçer.

use crate::panel::ArmMode;

/// Alarmın türü.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlarmKind {
    /// Zon (sensör) tetiklendi: hırsızlık şüphesi.
    Intrusion,
    /// Tuş takımı veya uzaktan kumandadan alarm.
    KeypadOrKeyfob,
    /// Panik butonu (polis).
    Panic,
    Fire,
    /// Tıbbi acil durum (ambulans).
    Medical,
    /// Cihaza fiziksel müdahale (sabotaj).
    Tamper,
    /// Gaz kaçağı.
    Gas,
    /// Su baskını.
    Flood,
}

/// Panelden gelen bir bildirim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PanelNotification {
    Alarm {
        kind: AlarmKind,
        partition: u8,
        /// Alarmı tetikleyen zon; panik gibi zonsuz alarmlarda yoktur.
        zone: Option<u16>,
    },
    Armed {
        partition: u8,
        mode: ArmMode,
    },
    Disarmed {
        partition: u8,
    },
    /// Panelle bağlantı koptu.
    Disconnected,
    /// Panelle bağlantı yeniden kuruldu.
    Connected,
    /// Pil veya şebeke gerilimi düşük.
    PowerProblem,
}

/// Bildirimin önceliği.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    Info,
    Warning,
    /// Sessiz modu aşan kanaldan gider, operatör kuyruğunun başına geçer.
    Critical,
}

impl PanelNotification {
    pub fn priority(&self) -> Priority {
        match self {
            Self::Alarm { .. } => Priority::Critical,
            // Bağlantının kopması bir saldırının ilk adımı olabilir; sessizce geçilmez.
            Self::Disconnected | Self::PowerProblem => Priority::Warning,
            Self::Armed { .. } | Self::Disarmed { .. } | Self::Connected => Priority::Info,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_alarm_kind_is_critical() {
        for kind in [
            AlarmKind::Intrusion,
            AlarmKind::KeypadOrKeyfob,
            AlarmKind::Panic,
            AlarmKind::Fire,
            AlarmKind::Medical,
            AlarmKind::Tamper,
            AlarmKind::Gas,
            AlarmKind::Flood,
        ] {
            let notification = PanelNotification::Alarm {
                kind,
                partition: 1,
                zone: None,
            };
            assert_eq!(notification.priority(), Priority::Critical, "{kind:?}");
        }
    }

    #[test]
    fn disconnect_is_never_just_info() {
        assert!(PanelNotification::Disconnected.priority() > Priority::Info);
    }

    #[test]
    fn arm_and_disarm_are_informational() {
        assert_eq!(
            PanelNotification::Disarmed { partition: 1 }.priority(),
            Priority::Info
        );
        assert_eq!(
            PanelNotification::Armed {
                partition: 1,
                mode: ArmMode::Away
            }
            .priority(),
            Priority::Info
        );
    }
}
