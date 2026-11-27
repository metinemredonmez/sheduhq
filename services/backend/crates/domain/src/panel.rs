//! Panel, bölüm (partition) ve zon kuralları.
//!
//! Bir alarm paneli bir veya daha fazla bölümden oluşur; her bölüm ayrı kurulur ve kapatılır.
//! Zonlar (sensörler) bölümlere bağlıdır. Komutlar her zaman tek bir bölümü hedefler.

use std::collections::BTreeSet;

/// Panelin bağlantı durumu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Connectivity {
    Online,
    /// Panelle bağlantı yok; bölümlerin gerçek durumu bilinmiyor.
    Offline,
}

/// Bölümün kurulma kipi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArmMode {
    /// Evde kimse yok; bütün zonlar aktif.
    Away,
    /// Evde biri var; iç zonlar pasif.
    Stay,
    /// Gece kipi.
    Night,
}

/// Bir bölümün bilinen son durumu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PartitionState {
    Disarmed,
    Armed(ArmMode),
    /// Bölümde alarm çalıyor.
    Alarm,
}

/// Kullanıcının bir bölüme gönderebileceği kurma / kapatma komutları.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Command {
    Arm(ArmMode),
    Disarm,
}

/// Bir komutun sunucuda, panele gönderilmeden önce reddedilme nedeni.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CommandRejection {
    /// Panel çevrimdışı. Durum bilinmediği için komut reddedilir (fail-closed, EXC-01).
    PanelOffline,
    /// Bölüm zaten istenen durumda.
    AlreadyInState,
    /// Önce kapatılması gerekiyor: alarm çalarken ya da başka bir kipte kuruluyken
    /// doğrudan yeni bir kipe geçilmez.
    DisarmRequiredFirst,
    /// Panel kurulmaya hazır değil (ör. açık kapı veya pencere var).
    NotReadyToArm,
    /// Zon devre dışı bırakma isteği boş.
    NoZonesRequested,
    /// İstenen zonlar hedef bölüme ait değil. Başka bir bölümün zonu bu yoldan
    /// devre dışı bırakılamaz (AZ-04).
    ZonesNotInPartition(BTreeSet<u16>),
}

/// Kurma / kapatma komutu geçerliyse, bölümün komut başarılı olduğunda geçeceği durumu döner.
///
/// Bütün durum ve komut çiftleri açıkça ele alınır; yeni bir durum veya komut eklendiğinde
/// derleyici bu fonksiyonu güncellemeye zorlar.
pub fn expected_state(
    connectivity: Connectivity,
    ready_to_arm: bool,
    current: PartitionState,
    command: Command,
) -> Result<PartitionState, CommandRejection> {
    use CommandRejection::{AlreadyInState, DisarmRequiredFirst, NotReadyToArm, PanelOffline};

    if connectivity == Connectivity::Offline {
        return Err(PanelOffline);
    }

    match (current, command) {
        (PartitionState::Disarmed, Command::Arm(_)) if !ready_to_arm => Err(NotReadyToArm),
        (PartitionState::Disarmed, Command::Arm(mode)) => Ok(PartitionState::Armed(mode)),
        (PartitionState::Disarmed, Command::Disarm) => Err(AlreadyInState),

        (PartitionState::Armed(current_mode), Command::Arm(mode)) if current_mode == mode => {
            Err(AlreadyInState)
        }
        (PartitionState::Armed(_), Command::Arm(_)) => Err(DisarmRequiredFirst),
        (PartitionState::Armed(_), Command::Disarm) => Ok(PartitionState::Disarmed),

        (PartitionState::Alarm, Command::Disarm) => Ok(PartitionState::Disarmed),
        (PartitionState::Alarm, Command::Arm(_)) => Err(DisarmRequiredFirst),
    }
}

/// Zon devre dışı bırakma (bypass) veya geri alma isteğini doğrular: istenen her zon hedef
/// bölüme ait olmalıdır.
pub fn validate_zone_selection(
    connectivity: Connectivity,
    partition_zones: &BTreeSet<u16>,
    requested: &BTreeSet<u16>,
) -> Result<(), CommandRejection> {
    if connectivity == Connectivity::Offline {
        return Err(CommandRejection::PanelOffline);
    }
    if requested.is_empty() {
        return Err(CommandRejection::NoZonesRequested);
    }
    let foreign: BTreeSet<u16> = requested.difference(partition_zones).copied().collect();
    if foreign.is_empty() {
        Ok(())
    } else {
        Err(CommandRejection::ZonesNotInPartition(foreign))
    }
}

/// Panele iletilen bir komutun sonucu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandOutcome {
    /// Panel komutu uyguladı ve onayladı.
    Succeeded,
    /// Panel komutu reddetti (ör. yanlış PIN veya panelin kendi kuralı).
    RejectedByPanel,
    /// Komut panele iletilemedi.
    NotDelivered,
    /// Komut iletildi ama süresi içinde onay gelmedi; sonuç belirsiz.
    NoAcknowledgement,
}

impl CommandOutcome {
    /// Kullanıcıya "tekrar deneyin" denebilir mi? Sonucu belirsiz bir komut otomatik olarak
    /// yeniden gönderilmez; önce panelin güncel durumu sorgulanır (BUS-02).
    pub fn is_safe_to_retry(self) -> bool {
        matches!(self, Self::NotDelivered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODES: [ArmMode; 3] = [ArmMode::Away, ArmMode::Stay, ArmMode::Night];

    fn all_states() -> Vec<PartitionState> {
        let mut states = vec![PartitionState::Disarmed, PartitionState::Alarm];
        states.extend(MODES.map(PartitionState::Armed));
        states
    }

    fn all_commands() -> Vec<Command> {
        let mut commands = vec![Command::Disarm];
        commands.extend(MODES.map(Command::Arm));
        commands
    }

    fn online(
        current: PartitionState,
        command: Command,
    ) -> Result<PartitionState, CommandRejection> {
        expected_state(Connectivity::Online, true, current, command)
    }

    fn zones(list: &[u16]) -> BTreeSet<u16> {
        list.iter().copied().collect()
    }

    #[test]
    fn disarmed_partition_can_be_armed_in_every_mode() {
        for mode in MODES {
            assert_eq!(
                online(PartitionState::Disarmed, Command::Arm(mode)),
                Ok(PartitionState::Armed(mode))
            );
        }
    }

    #[test]
    fn armed_partition_and_alarm_can_be_disarmed() {
        for state in [PartitionState::Armed(ArmMode::Away), PartitionState::Alarm] {
            assert_eq!(online(state, Command::Disarm), Ok(PartitionState::Disarmed));
        }
    }

    #[test]
    fn offline_panel_rejects_every_command() {
        for state in all_states() {
            for command in all_commands() {
                assert_eq!(
                    expected_state(Connectivity::Offline, true, state, command),
                    Err(CommandRejection::PanelOffline)
                );
            }
        }
    }

    #[test]
    fn not_ready_panel_cannot_be_armed_but_can_be_disarmed() {
        assert_eq!(
            expected_state(
                Connectivity::Online,
                false,
                PartitionState::Disarmed,
                Command::Arm(ArmMode::Away)
            ),
            Err(CommandRejection::NotReadyToArm)
        );
        assert_eq!(
            expected_state(
                Connectivity::Online,
                false,
                PartitionState::Alarm,
                Command::Disarm
            ),
            Ok(PartitionState::Disarmed)
        );
    }

    #[test]
    fn alarm_must_be_disarmed_before_arming() {
        assert_eq!(
            online(PartitionState::Alarm, Command::Arm(ArmMode::Away)),
            Err(CommandRejection::DisarmRequiredFirst)
        );
    }

    #[test]
    fn switching_mode_while_armed_requires_disarm() {
        assert_eq!(
            online(
                PartitionState::Armed(ArmMode::Stay),
                Command::Arm(ArmMode::Away)
            ),
            Err(CommandRejection::DisarmRequiredFirst)
        );
    }

    #[test]
    fn repeating_the_current_state_is_rejected() {
        assert_eq!(
            online(PartitionState::Disarmed, Command::Disarm),
            Err(CommandRejection::AlreadyInState)
        );
        assert_eq!(
            online(
                PartitionState::Armed(ArmMode::Night),
                Command::Arm(ArmMode::Night)
            ),
            Err(CommandRejection::AlreadyInState)
        );
    }

    #[test]
    fn accepted_commands_never_lead_to_alarm() {
        for state in all_states() {
            for command in all_commands() {
                if let Ok(next) = online(state, command) {
                    assert_ne!(next, PartitionState::Alarm, "{state:?} + {command:?}");
                }
            }
        }
    }

    #[test]
    fn zones_of_the_partition_can_be_selected() {
        assert_eq!(
            validate_zone_selection(Connectivity::Online, &zones(&[1, 2, 3]), &zones(&[1, 3])),
            Ok(())
        );
    }

    #[test]
    fn zones_of_another_partition_are_rejected() {
        assert_eq!(
            validate_zone_selection(
                Connectivity::Online,
                &zones(&[1, 2, 3]),
                &zones(&[2, 9, 10])
            ),
            Err(CommandRejection::ZonesNotInPartition(zones(&[9, 10])))
        );
    }

    #[test]
    fn empty_zone_selection_and_offline_panel_are_rejected() {
        assert_eq!(
            validate_zone_selection(Connectivity::Online, &zones(&[1]), &zones(&[])),
            Err(CommandRejection::NoZonesRequested)
        );
        assert_eq!(
            validate_zone_selection(Connectivity::Offline, &zones(&[1]), &zones(&[1])),
            Err(CommandRejection::PanelOffline)
        );
    }

    #[test]
    fn only_undelivered_commands_are_safe_to_retry() {
        assert!(CommandOutcome::NotDelivered.is_safe_to_retry());
        assert!(!CommandOutcome::NoAcknowledgement.is_safe_to_retry());
        assert!(!CommandOutcome::Succeeded.is_safe_to_retry());
        assert!(!CommandOutcome::RejectedByPanel.is_safe_to_retry());
    }
}
