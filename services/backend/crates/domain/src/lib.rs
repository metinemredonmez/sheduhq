//! Shedu domain kuralları.
//!
//! Bu crate'in hiçbir bağımlılığı yoktur; veritabanına, ağa veya AI servisine erişemez.
//! Kimlik doğrulama burada yapılmaz, API katmanında yapılır. Burada yalnızca iş kuralları vardır:
//!
//! - [`panel`]: bölüm (partition) durumları, komutlar ve komut sonuçları (BUS-01).
//! - [`alarm`]: panelden gelen bildirimler ve öncelikleri.
//! - [`access`]: gün ve saat bazlı erişim penceresi (AZ-01).

pub mod access;
pub mod alarm;
pub mod panel;
