//! SMS doğrulama kodları ve HMAC tabanlı anahtarlar.
//!
//! Kod, amaca ve telefona bağlı olarak HMAC-SHA256 ile saklanır (AUT-03): kayıt için üretilmiş
//! bir kod parola sıfırlamada, bir telefona gönderilmiş kod başka bir telefonda çalışmaz.
//! 6 haneli kodun düz SHA-256'sı kolayca kırılabileceği için gizli anahtar şarttır.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub const CODE_TTL_MINUTES: i64 = 10;
pub const MAX_ATTEMPTS: i16 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Register,
    PasswordReset,
    PhoneChange,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::PasswordReset => "password_reset",
            Self::PhoneChange => "phone_change",
        }
    }
}

#[derive(Debug)]
pub struct CodeError;

/// 000000–999999 arasında düzgün dağılımlı 6 haneli kod.
pub fn generate() -> Result<String, CodeError> {
    // Modülo yanlılığını önlemek için reddetmeli örnekleme.
    const LIMIT: u32 = u32::MAX - (u32::MAX % 1_000_000);
    loop {
        let mut bytes = [0u8; 4];
        getrandom::fill(&mut bytes).map_err(|_| CodeError)?;
        let value = u32::from_le_bytes(bytes);
        if value < LIMIT {
            return Ok(format!("{:06}", value % 1_000_000));
        }
    }
}

fn mac(secret: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret)
        .expect("HMAC her uzunlukta anahtarı kabul eder");
    for part in parts {
        // Uzunluk önekiyle birleştirme: ("ab","c") ile ("a","bc") aynı sonucu vermez.
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().to_vec()
}

/// Veritabanında saklanacak kod özeti.
pub fn code_mac(secret: &[u8], purpose: Purpose, phone: &str, code: &str) -> Vec<u8> {
    mac(
        secret,
        &[
            b"code",
            purpose.as_str().as_bytes(),
            phone.as_bytes(),
            code.as_bytes(),
        ],
    )
}

/// Gönderilen kod saklanan özetle eşleşiyor mu? Sabit zamanlı karşılaştırma.
pub fn code_matches(
    secret: &[u8],
    purpose: Purpose,
    phone: &str,
    code: &str,
    stored: &[u8],
) -> bool {
    code_mac(secret, purpose, phone, code).ct_eq(stored).into()
}

/// Deneme sayacı anahtarı: kişisel veri düz saklanmaz.
pub fn rate_key(secret: &[u8], scope: &str, value: &str) -> Vec<u8> {
    mac(secret, &[b"rate", scope.as_bytes(), value.as_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-hmac-secret-0123456789abcdefgh";

    #[test]
    fn codes_are_six_digits() {
        for _ in 0..200 {
            let code = generate().expect("kod");
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn code_is_bound_to_purpose_and_phone() {
        let stored = code_mac(SECRET, Purpose::Register, "+905551112233", "123456");
        assert!(code_matches(
            SECRET,
            Purpose::Register,
            "+905551112233",
            "123456",
            &stored
        ));
        assert!(!code_matches(
            SECRET,
            Purpose::PasswordReset,
            "+905551112233",
            "123456",
            &stored
        ));
        assert!(!code_matches(
            SECRET,
            Purpose::Register,
            "+905559998877",
            "123456",
            &stored
        ));
        assert!(!code_matches(
            SECRET,
            Purpose::Register,
            "+905551112233",
            "123457",
            &stored
        ));
        assert!(!code_matches(
            b"baska-gizli-anahtar-0123456789abcdef",
            Purpose::Register,
            "+905551112233",
            "123456",
            &stored
        ));
    }

    #[test]
    fn length_prefix_prevents_concatenation_collisions() {
        assert_ne!(rate_key(SECRET, "ab", "c"), rate_key(SECRET, "a", "bc"));
    }
}
