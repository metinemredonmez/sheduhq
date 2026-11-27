//! Veritabanında saklanan faktör sırlarının şifrelenmesi (KEY-04).
//!
//! XChaCha20-Poly1305: bütünlük korumalı şifreleme, her kayıt için rastgele 24 baytlık nonce
//! (rastgele nonce bu boyda güvenle kullanılır). Anahtar, yapılandırmadaki veri anahtarından
//! amaca özel olarak türetilir; anahtar sürümü veriyle birlikte saklanır. Ek doğrulanmış veri
//! (AAD) kaydı sahibine bağlar: bir kullanıcının şifreli sırrı başka kullanıcının satırına
//! taşınırsa çözülmez. Bozulmuş veri, yanlış anahtar veya yanlış sürüm sessizce kabul edilmez.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const NONCE_LEN: usize = 24;

/// Şifreli kayıt: anahtar sürümü, nonce ve şifreli metin (etiket dahil).
pub struct Sealed {
    pub key_version: i16,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub struct CryptoError;

pub struct DataKey {
    version: i16,
    cipher: XChaCha20Poly1305,
}

impl DataKey {
    /// `secret`: yapılandırmadaki veri anahtarı. `purpose`: amaç etiketi (ör. `totp-secret`).
    pub fn derive(secret: &[u8], version: i16, purpose: &str) -> Result<Self, CryptoError> {
        let mut mac = <Hmac<Sha256>>::new_from_slice(secret).map_err(|_| CryptoError)?;
        mac.update(b"shedu/data-key/v1/");
        mac.update(purpose.as_bytes());
        let derived: [u8; 32] = mac.finalize().into_bytes().into();
        let cipher = XChaCha20Poly1305::new(&derived.into());
        Ok(Self { version, cipher })
    }

    pub fn version(&self) -> i16 {
        self.version
    }

    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Sealed, CryptoError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| CryptoError)?;
        let ciphertext = self
            .cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError)?;
        Ok(Sealed {
            key_version: self.version,
            nonce,
            ciphertext,
        })
    }

    pub fn open(
        &self,
        key_version: i16,
        aad: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if key_version != self.version {
            return Err(CryptoError);
        }
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError)?;
        self.cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> DataKey {
        DataKey::derive(b"test-data-key-0123456789abcdefghijkl", 1, "totp-secret").expect("anahtar")
    }

    #[test]
    fn round_trip() {
        let sealed = key().seal(b"user-1", b"gizli").expect("şifre");
        assert_ne!(sealed.ciphertext.as_slice(), b"gizli");
        let opened = key()
            .open(1, b"user-1", &sealed.nonce, &sealed.ciphertext)
            .expect("çöz");
        assert_eq!(opened, b"gizli");
    }

    #[test]
    fn nonces_are_unique() {
        let a = key().seal(b"u", b"x").expect("şifre");
        let b = key().seal(b"u", b"x").expect("şifre");
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn tampering_wrong_owner_key_or_version_is_rejected() {
        let sealed = key().seal(b"user-1", b"gizli").expect("şifre");
        let mut tampered = sealed.ciphertext.clone();
        tampered[0] ^= 1;
        assert!(key().open(1, b"user-1", &sealed.nonce, &tampered).is_err());
        assert!(
            key()
                .open(1, b"user-2", &sealed.nonce, &sealed.ciphertext)
                .is_err()
        );
        assert!(
            key()
                .open(2, b"user-1", &sealed.nonce, &sealed.ciphertext)
                .is_err()
        );
        let other = DataKey::derive(b"other-data-key-0123456789abcdefghijk", 1, "totp-secret")
            .expect("anahtar");
        assert!(
            other
                .open(1, b"user-1", &sealed.nonce, &sealed.ciphertext)
                .is_err()
        );
        let other_purpose =
            DataKey::derive(b"test-data-key-0123456789abcdefghijkl", 1, "başka").expect("anahtar");
        assert!(
            other_purpose
                .open(1, b"user-1", &sealed.nonce, &sealed.ciphertext)
                .is_err()
        );
        assert!(
            key()
                .open(1, b"user-1", &sealed.nonce[..12], &sealed.ciphertext)
                .is_err()
        );
    }
}
