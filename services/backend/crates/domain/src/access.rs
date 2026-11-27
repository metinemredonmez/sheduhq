//! Gün ve saat bazlı erişim penceresi.
//!
//! Kurumsal müşteriler personele yalnızca belirli gün ve saatlerde yetki verir (ör. temizlik
//! personeli hafta içi 08:00–10:00). Bu modül yalnızca "bu anda pencere açık mı?" sorusunu
//! yanıtlar; izin ve kapsam kontrolü API katmanında bununla birlikte yapılır (AZ-01).
//!
//! Hiç pencere tanımlı değilse erişim **reddedilir** (fail-closed, EXC-01).

/// Haftanın günü.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Weekday {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

impl Weekday {
    pub fn previous(self) -> Self {
        match self {
            Self::Mon => Self::Sun,
            Self::Tue => Self::Mon,
            Self::Wed => Self::Tue,
            Self::Thu => Self::Wed,
            Self::Fri => Self::Thu,
            Self::Sat => Self::Fri,
            Self::Sun => Self::Sat,
        }
    }
}

/// Günün dakikası: 0 (00:00) ile 1439 (23:59) arası.
pub type MinuteOfDay = u16;

/// Bir gündeki erişim aralığı. `start > end` ise gece yarısını aşar (ör. 22:00–06:00); bu
/// durumda aralık başladığı güne aittir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessWindow {
    pub day: Weekday,
    pub start: MinuteOfDay,
    /// Hariç: `end` dakikasında erişim kapanır.
    pub end: MinuteOfDay,
}

/// Kullanıcının bir kaynağa erişim politikası.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AccessPolicy {
    /// Bu andan önce erişim yok (Unix saniyesi).
    pub valid_from: Option<i64>,
    /// Bu andan itibaren erişim yok (Unix saniyesi).
    pub expires_at: Option<i64>,
    /// `true` ise gün ve saat kısıtı yoktur (ör. ev sahibi); geçerlilik süresi yine uygulanır.
    pub always_open: bool,
    pub windows: Vec<AccessWindow>,
}

/// Değerlendirilen an: organizasyonun yerel saat dilimine çevrilmiş gün ve dakika ile mutlak zaman.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalMoment {
    pub unix: i64,
    pub day: Weekday,
    pub minute: MinuteOfDay,
}

impl AccessPolicy {
    pub fn is_open_at(&self, at: LocalMoment) -> bool {
        if self.valid_from.is_some_and(|from| at.unix < from) {
            return false;
        }
        if self.expires_at.is_some_and(|until| at.unix >= until) {
            return false;
        }
        self.always_open || self.windows.iter().any(|window| window.contains(at))
    }
}

impl AccessWindow {
    fn contains(&self, at: LocalMoment) -> bool {
        if self.start == self.end {
            // Uzunluğu sıfır olan pencere hiçbir zaman açık değildir.
            return false;
        }
        if self.start < self.end {
            return at.day == self.day && (self.start..self.end).contains(&at.minute);
        }
        // Gece yarısını aşan pencere: başladığı gün `start`'tan sonra veya ertesi gün `end`'den önce.
        (at.day == self.day && at.minute >= self.start)
            || (at.day.previous() == self.day && at.minute < self.end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn hm(hour: u16, minute: u16) -> MinuteOfDay {
        hour * 60 + minute
    }

    fn at(day: Weekday, minute: MinuteOfDay) -> LocalMoment {
        LocalMoment {
            unix: 1_000_000,
            day,
            minute,
        }
    }

    fn weekday_mornings() -> AccessPolicy {
        AccessPolicy {
            windows: [
                Weekday::Mon,
                Weekday::Tue,
                Weekday::Wed,
                Weekday::Thu,
                Weekday::Fri,
            ]
            .map(|day| AccessWindow {
                day,
                start: hm(8, 0),
                end: hm(10, 0),
            })
            .to_vec(),
            ..AccessPolicy::default()
        }
    }

    #[test]
    fn open_inside_the_window() {
        assert!(weekday_mornings().is_open_at(at(Weekday::Tue, hm(8, 0))));
        assert!(weekday_mornings().is_open_at(at(Weekday::Fri, hm(9, 59))));
    }

    #[test]
    fn closed_outside_the_window() {
        assert!(!weekday_mornings().is_open_at(at(Weekday::Tue, hm(10, 0))));
        assert!(!weekday_mornings().is_open_at(at(Weekday::Tue, hm(7, 59))));
        assert!(!weekday_mornings().is_open_at(at(Weekday::Sat, hm(9, 0))));
    }

    #[test]
    fn no_windows_means_no_access() {
        assert!(!AccessPolicy::default().is_open_at(at(Weekday::Mon, hm(12, 0))));
    }

    #[test]
    fn overnight_window_spans_midnight() {
        let policy = AccessPolicy {
            windows: vec![AccessWindow {
                day: Weekday::Sun,
                start: hm(22, 0),
                end: hm(6, 0),
            }],
            ..AccessPolicy::default()
        };
        assert!(policy.is_open_at(at(Weekday::Sun, hm(23, 30))));
        assert!(policy.is_open_at(at(Weekday::Mon, hm(5, 59))));
        assert!(!policy.is_open_at(at(Weekday::Mon, hm(6, 0))));
        assert!(!policy.is_open_at(at(Weekday::Sun, hm(5, 0))));
    }

    #[test]
    fn validity_period_is_enforced() {
        let mut policy = weekday_mornings();
        policy.valid_from = Some(2_000_000);
        assert!(!policy.is_open_at(at(Weekday::Mon, hm(9, 0))));

        policy.valid_from = None;
        policy.expires_at = Some(1_000_000);
        assert!(!policy.is_open_at(at(Weekday::Mon, hm(9, 0))));

        policy.expires_at = Some(1_000_001);
        assert!(policy.is_open_at(at(Weekday::Mon, hm(9, 0))));
    }

    #[test]
    fn always_open_ignores_windows_but_not_validity() {
        let mut policy = AccessPolicy {
            always_open: true,
            ..AccessPolicy::default()
        };
        assert!(policy.is_open_at(at(Weekday::Sun, hm(3, 0))));

        policy.expires_at = Some(1_000_000);
        assert!(!policy.is_open_at(at(Weekday::Sun, hm(3, 0))));
    }

    #[test]
    fn zero_length_window_is_never_open() {
        let policy = AccessPolicy {
            windows: vec![AccessWindow {
                day: Weekday::Mon,
                start: hm(9, 0),
                end: hm(9, 0),
            }],
            ..AccessPolicy::default()
        };
        assert!(!policy.is_open_at(at(Weekday::Mon, hm(9, 0))));
    }
}
