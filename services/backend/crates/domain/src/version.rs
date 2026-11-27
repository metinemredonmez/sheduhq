//! Uygulama sürümü ve güncelleme kararı.
//!
//! Sürüm `MAJOR[.MINOR[.PATCH]]` biçimindedir (eksik parça 0 sayılır); her parça en fazla altı
//! hanelidir. Ön sürüm ekleri (`-beta`) ve boşluk kabul edilmez: belirsiz bir sürüm, karar
//! verilemeyen bir durum yaratmamalıdır.

use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AppVersion([u32; 3]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidVersion;

impl FromStr for AppVersion {
    type Err = InvalidVersion;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = text.split('.').collect();
        if parts.is_empty() || parts.len() > 3 {
            return Err(InvalidVersion);
        }
        let mut numbers = [0u32; 3];
        for (slot, part) in numbers.iter_mut().zip(&parts) {
            if part.is_empty() || part.len() > 6 || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(InvalidVersion);
            }
            *slot = part.parse().map_err(|_| InvalidVersion)?;
        }
        Ok(Self(numbers))
    }
}

impl fmt::Display for AppVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0[0], self.0[1], self.0[2])
    }
}

/// Bir istemci sürümü için güncelleme kararı.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateStatus {
    UpToDate,
    /// Güncelleme önerilir; uygulama kullanılmaya devam edebilir.
    Recommended,
    /// Güncelleme zorunludur; bu sürüm desteklenmez.
    Required,
}

/// `minimum` altı zorunlu, `latest` altı önerilen güncellemedir.
pub fn update_status(current: AppVersion, minimum: AppVersion, latest: AppVersion) -> UpdateStatus {
    if current < minimum {
        UpdateStatus::Required
    } else if current < latest {
        UpdateStatus::Recommended
    } else {
        UpdateStatus::UpToDate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> AppVersion {
        text.parse().expect("sürüm")
    }

    #[test]
    fn parsing() {
        assert_eq!(v("1"), v("1.0.0"));
        assert_eq!(v("1.2"), v("1.2.0"));
        assert_eq!(v("10.0.3").to_string(), "10.0.3");
        for bad in [
            "", "1.", ".1", "1..2", "1.2.3.4", "1.2-beta", "v1.2", " 1.2", "1,2", "1234567",
        ] {
            assert!(bad.parse::<AppVersion>().is_err(), "{bad}");
        }
    }

    #[test]
    fn comparison_is_numeric_not_textual() {
        assert!(v("1.10.0") > v("1.9.9"));
        assert!(v("2") > v("1.99.99"));
        assert!(v("1.2.3") < v("1.2.10"));
    }

    #[test]
    fn decision() {
        let (min, latest) = (v("1.2.0"), v("1.4.0"));
        assert_eq!(
            update_status(v("1.1.9"), min, latest),
            UpdateStatus::Required
        );
        assert_eq!(
            update_status(v("1.2.0"), min, latest),
            UpdateStatus::Recommended
        );
        assert_eq!(
            update_status(v("1.4.0"), min, latest),
            UpdateStatus::UpToDate
        );
        assert_eq!(update_status(v("2.0"), min, latest), UpdateStatus::UpToDate);
    }
}
