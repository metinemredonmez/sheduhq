//! TOTP (RFC 6238): 30 saniyelik adım, 6 hane, HMAC-SHA1 (doğrulayıcı uygulamaların ortak
//! varsayılanı). Kod, o anki adım ve bir önceki/sonraki adım için kabul edilir (saat kayması);
//! kabul edilen adım kaydedilir ve o adım veya öncesi bir daha kabul edilmez (tekrar oynatma).

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

pub const STEP_SECS: i64 = 30;
pub const SECRET_LEN: usize = 20;
const DIGITS: u32 = 6;

pub fn generate_secret() -> Result<[u8; SECRET_LEN], getrandom::Error> {
    let mut secret = [0u8; SECRET_LEN];
    getrandom::fill(&mut secret)?;
    Ok(secret)
}

pub fn step_at(unix: i64) -> i64 {
    unix.div_euclid(STEP_SECS)
}

/// RFC 4226 HOTP kodu; `step` sayaçtır.
pub fn code_at(secret: &[u8], step: i64) -> String {
    let Ok(mut mac) = <Hmac<Sha1>>::new_from_slice(secret) else {
        return String::new();
    };
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    format!("{:06}", binary % 10u32.pow(DIGITS))
}

/// Kodu `now_step` etrafındaki pencerede (−1, 0, +1) arar; eşleşen adımı döner. Karşılaştırma
/// sabit sürelidir. Tekrar oynatma kontrolü çağıranın işidir (`last_step`).
pub fn matching_step(secret: &[u8], code: &str, now_step: i64) -> Option<i64> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut found = None;
    for step in [now_step - 1, now_step, now_step + 1] {
        let expected = code_at(secret, step);
        if bool::from(expected.as_bytes().ct_eq(code.as_bytes())) {
            found = Some(step);
        }
    }
    found
}

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 Base32, dolgu olmadan (doğrulayıcı uygulamaların beklediği biçim).
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

pub fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for c in text.bytes().filter(|c| *c != b'=') {
        let value = ALPHABET.iter().position(|a| *a == c.to_ascii_uppercase())?;
        buffer = (buffer << 5) | u32::try_from(value).ok()?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// Doğrulayıcı uygulamaya eklenecek `otpauth://` adresi.
pub fn otpauth_uri(secret: &[u8], account: &str) -> String {
    let account: String = account
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    format!(
        "otpauth://totp/Shedu:{account}?secret={}&issuer=Shedu&algorithm=SHA1&digits=6&period=30",
        base32_encode(secret)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc4226_hotp_vectors() {
        let expected = ["755224", "287082", "359152", "969429", "338314"];
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(code_at(RFC_SECRET, counter as i64), *code);
        }
    }

    #[test]
    fn rfc6238_sha1_vectors_last_six_digits() {
        for (unix, code) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
        ] {
            assert_eq!(code_at(RFC_SECRET, step_at(unix)), code, "{unix}");
        }
    }

    #[test]
    fn window_accepts_neighbours_only() {
        let now = step_at(1_234_567_890);
        for offset in [-1, 0, 1] {
            let code = code_at(RFC_SECRET, now + offset);
            assert_eq!(matching_step(RFC_SECRET, &code, now), Some(now + offset));
        }
        for offset in [-2, 2] {
            assert_eq!(
                matching_step(RFC_SECRET, &code_at(RFC_SECRET, now + offset), now),
                None
            );
        }
        assert_eq!(matching_step(RFC_SECRET, "12345", now), None);
        assert_eq!(matching_step(RFC_SECRET, "12a456", now), None);
    }

    #[test]
    fn base32_round_trip_and_vectors() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_decode("MZXW6YTBOI").as_deref(), Some(&b"foobar"[..]));
        assert_eq!(base32_decode("mzxw6ytboi").as_deref(), Some(&b"foobar"[..]));
        assert_eq!(base32_decode("MZ1W"), None);
        let secret = generate_secret().expect("rastgele");
        assert_eq!(
            base32_decode(&base32_encode(&secret)).as_deref(),
            Some(&secret[..])
        );
    }

    #[test]
    fn uri_escapes_account() {
        let uri = otpauth_uri(b"foobar", "+90***2233");
        assert!(uri.starts_with("otpauth://totp/Shedu:%2B90%2A%2A%2A2233?secret=MZXW6YTBOI&"));
    }
}
