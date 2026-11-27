//! Parola politikası ve argon2id.
//!
//! - Tek faktörlü girişte en az 15 karakter (PWD-01); kayıt ve sıfırlama aynı kuralı kullanır.
//! - Üst sınır 128 karakter: argon2'ye sınırsız girdi verilmez (RES-01).
//! - Yaygın, tekrarlı, ardışık ve kullanıcının kendi bilgisini içeren parolalar reddedilir (PWD-03).
//!   Kontrol tamamen yereldir; parola hiçbir dış servise gönderilmez.
//! - Hash: argon2id, m=19 MiB, t=2, p=1 (PWD-04).

use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};

pub const MIN_CHARS: usize = 15;
pub const MAX_CHARS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordRejection {
    TooShort,
    TooLong,
    /// Yaygın, tekrarlı veya ardışık; ya da kullanıcının kendi bilgisini içeriyor.
    TooPredictable,
}

impl PasswordRejection {
    pub fn code(self) -> &'static str {
        match self {
            Self::TooShort => "password_too_short",
            Self::TooLong => "password_too_long",
            Self::TooPredictable => "password_too_predictable",
        }
    }
}

/// Bilinen yaygın uzun parolalar (küçük harfe çevrilmiş). Kısa yaygın parolalar zaten uzunluk
/// kuralına takılır.
const COMMON: &[&str] = &[
    "123456789012345",
    "1234567890123456",
    "12345678901234567890",
    "qwertyuiopasdfg",
    "qwertyuiopasdfgh",
    "qwertyuiopasdfghjkl",
    "passwordpassword",
    "password12345678",
    "iloveyouiloveyou",
    "sifresifresifre",
    "parolaparolaparola",
    "asdfghjklasdfghjkl",
];

/// Parolanın içinde bulunmaması gereken bağlama özgü kelimeler.
const CONTEXT_WORDS: &[&str] = &["shedu", "password", "parola", "sifre", "şifre", "alarm"];

/// Yeni parolayı politikaya göre denetler. `personal` kullanıcının kendi bilgileridir
/// (telefon, e-posta, ad); bunları içeren parola reddedilir.
pub fn validate_new(password: &str, personal: &[&str]) -> Result<(), PasswordRejection> {
    let chars: Vec<char> = password.chars().collect();
    if chars.len() < MIN_CHARS {
        return Err(PasswordRejection::TooShort);
    }
    if chars.len() > MAX_CHARS {
        return Err(PasswordRejection::TooLong);
    }

    let lower = password.to_lowercase();
    let compact: String = lower.chars().filter(|c| !c.is_whitespace()).collect();

    if COMMON.contains(&compact.as_str())
        || is_repetition(&compact)
        || is_sequence(&compact)
        || is_mostly_context_word(&compact)
    {
        return Err(PasswordRejection::TooPredictable);
    }

    for value in personal {
        let value = value.to_lowercase();
        let digits_only: String = value.chars().filter(char::is_ascii_digit).collect();
        let fragments = [
            value.split('@').next().unwrap_or_default().to_owned(),
            // Telefonun son 7 hanesi: ülke kodu olmadan yazılsa da yakalanır.
            digits_only
                .chars()
                .rev()
                .take(7)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect(),
            value,
        ];
        if fragments
            .iter()
            .any(|fragment| fragment.chars().count() >= 4 && compact.contains(fragment.as_str()))
        {
            return Err(PasswordRejection::TooPredictable);
        }
    }
    Ok(())
}

/// Kısa bir birimin tekrarı mı? (ör. "aaaaaaaaaaaaaaa", "abcabcabcabcabc")
fn is_repetition(value: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
    (1..=4).any(|unit| {
        chars.len() >= unit * 3 && chars.iter().enumerate().all(|(i, c)| *c == chars[i % unit])
    })
}

/// Bütünüyle ardışık mı? (ör. "abcdefghijklmno", "987654321098765")
fn is_sequence(value: &str) -> bool {
    let codes: Vec<i64> = value.chars().map(|c| i64::from(u32::from(c))).collect();
    let steps: Vec<i64> = codes.windows(2).map(|w| w[1] - w[0]).collect();
    let ascending = steps.iter().all(|s| *s == 1 || *s == -9);
    let descending = steps.iter().all(|s| *s == -1 || *s == 9);
    !steps.is_empty() && (ascending || descending)
}

/// Bağlama özgü bir kelime çıkarıldığında geriye anlamlı bir şey kalmıyor mu?
fn is_mostly_context_word(value: &str) -> bool {
    let mut rest = value.to_owned();
    for word in CONTEXT_WORDS {
        rest = rest.replace(word, "");
    }
    rest.len() < value.len() && rest.chars().count() < 8
}

fn hasher() -> Argon2<'static> {
    let params = Params::new(
        Params::DEFAULT_M_COST,
        Params::DEFAULT_T_COST,
        Params::DEFAULT_P_COST,
        None,
    )
    .unwrap_or_default();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

#[derive(Debug)]
pub struct HashError;

/// Parolayı argon2id ile hash'ler (PHC biçimi). CPU yoğundur; async kodda
/// `spawn_blocking` içinde çağrılmalıdır.
pub fn hash(password: &str) -> Result<String, HashError> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|_| HashError)?;
    hasher()
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| HashError)
}

/// Parolayı PHC hash'ine karşı doğrular. Hash bozuksa `false` döner.
pub fn verify(password: &str, phc: &str) -> bool {
    hasher().verify_password(password.as_bytes(), phc).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "mavi bisiklet dag yolunda";

    #[test]
    fn length_boundaries() {
        assert_eq!(
            validate_new("Kx9#mvTq2Lp4Zr", &[]),
            Err(PasswordRejection::TooShort)
        );
        assert_eq!(validate_new("Kx9#mvTq2Lp4Zr7", &[]), Ok(()));
        assert_eq!(
            validate_new(&"Kx9#".repeat(33), &[]),
            Err(PasswordRejection::TooLong)
        );
    }

    #[test]
    fn length_counts_characters_not_bytes() {
        // 15 karakter, 15'ten fazla bayt.
        assert_eq!(validate_new("çığüşöÇİĞÜŞÖ9xz", &[]), Ok(()));
    }

    #[test]
    fn long_passphrase_is_accepted() {
        assert_eq!(validate_new(GOOD, &[]), Ok(()));
    }

    #[test]
    fn predictable_passwords_are_rejected() {
        for weak in [
            "123456789012345",
            "aaaaaaaaaaaaaaa",
            "abcabcabcabcabc",
            "abcdefghijklmnop",
            "9876543210987654",
            "PasswordPassword",
            "shedushedushedu1",
        ] {
            assert_eq!(
                validate_new(weak, &[]),
                Err(PasswordRejection::TooPredictable),
                "{weak}"
            );
        }
    }

    #[test]
    fn personal_information_is_rejected() {
        assert_eq!(
            validate_new("benim numaram 5551112233", &["+905551112233"]),
            Err(PasswordRejection::TooPredictable)
        );
        assert_eq!(
            validate_new("ahmet.yilmaz kapiyi kilitle", &["ahmet.yilmaz@example.com"]),
            Err(PasswordRejection::TooPredictable)
        );
        assert_eq!(validate_new(GOOD, &["+905551112233", "Ayşe"]), Ok(()));
    }

    #[test]
    fn hash_round_trip_and_wrong_password() {
        let phc = hash(GOOD).expect("hash");
        assert!(phc.starts_with("$argon2id$"));
        assert!(verify(GOOD, &phc));
        assert!(!verify("başka bir uzun parola cümlesi", &phc));
        assert!(!verify(GOOD, "bozuk-hash"));
    }

    #[test]
    fn same_password_gets_different_salts() {
        assert_ne!(hash(GOOD).expect("hash"), hash(GOOD).expect("hash"));
    }
}
