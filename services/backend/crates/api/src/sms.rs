//! SMS gönderimi.
//!
//! Sağlayıcı İleti Merkezi'dir (`providers::iletimerkezi`). Üretimde sağlayıcı yoksa API başlamaz
//! (fail-closed). Geliştirme göndericisi kodu konsola yazar; bu yüzden yalnızca geliştirme
//! ortamında kullanılabilir.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

pub type SmsFuture<'a> = Pin<Box<dyn Future<Output = Result<(), SmsError>> + Send + 'a>>;

#[derive(Debug)]
pub struct SmsError;

pub trait SmsSender: Send + Sync {
    fn send<'a>(&'a self, to: &'a str, text: &'a str) -> SmsFuture<'a>;
}

/// Yalnızca geliştirme: mesajı standart çıktıya yazar.
pub struct DevConsoleSms;

impl SmsSender for DevConsoleSms {
    fn send<'a>(&'a self, to: &'a str, text: &'a str) -> SmsFuture<'a> {
        Box::pin(async move {
            println!("[geliştirme SMS] {} -> {text}", mask_phone(to));
            Ok(())
        })
    }
}

/// Testler için: gönderilen mesajları bellekte tutar.
#[derive(Default, Clone)]
pub struct RecordingSms {
    sent: Arc<Mutex<Vec<(String, String)>>>,
}

impl RecordingSms {
    pub fn messages_to(&self, to: &str) -> Vec<String> {
        self.sent
            .lock()
            .map(|sent| {
                sent.iter()
                    .filter(|(phone, _)| phone == to)
                    .map(|(_, text)| text.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl SmsSender for RecordingSms {
    fn send<'a>(&'a self, to: &'a str, text: &'a str) -> SmsFuture<'a> {
        Box::pin(async move {
            if let Ok(mut sent) = self.sent.lock() {
                sent.push((to.to_owned(), text.to_owned()));
            }
            Ok(())
        })
    }
}

/// Log için telefonu maskeler: `+905551112233` → `+90******2233` (LOG-02).
pub fn mask_phone(phone: &str) -> String {
    let chars: Vec<char> = phone.chars().collect();
    if chars.len() <= 7 {
        return "***".to_owned();
    }
    let head: String = chars[..3].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}{}{tail}", "*".repeat(chars.len() - 7))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phone_is_masked() {
        assert_eq!(mask_phone("+905551112233"), "+90******2233");
        assert_eq!(mask_phone("+12345"), "***");
    }
}
