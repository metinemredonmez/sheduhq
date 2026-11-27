# 0001 — Teknoloji yığını

- **Durum:** Kabul edildi
- **Tarih:** 2026-11-26

## Bağlam

Shedu; mobil uygulama, web ve yönetim arayüzleri, alarm panelleriyle 7/24 konuşan bir backend ve bir AI
katmanından oluşuyor. Alarm yolu güvenilir olmalı: kaybolan ya da geciken bir alarm bir güvenlik olayıdır.

## Karar

| Katman | Teknoloji |
|---|---|
| Backend (API, gateway, domain) | **Rust** — Axum, Tokio, SQLx, PostgreSQL, Redis |
| AI servisi | **Python** — FastAPI ve resmi LLM sağlayıcı SDK'sı |
| Web ve admin | **Next.js** |
| Mobil | **Expo** (React Native, TypeScript) |

## Gerekçe

- Rust: bellek ve eşzamanlılık güvenliği, öngörülebilir gecikme, düşük kaynak tüketimi; `match` ile panel
  durumlarının eksiksiz ele alınmasının derleyici tarafından zorlanması.
- Python (AI): resmi LLM SDK'ları ve makine öğrenmesi ekosistemi.
- Expo + Next.js: aynı dil (TypeScript) ve aynı ekip; iOS ve Android tek kod tabanından.

## Değerlendirilen seçenekler

- **Go backend:** daha hızlı geliştirme, daha kolay işe alım; Rust'ın derleme zamanı garantileri yok.
- **Python backend:** AI ile tek dil; ama 7/24 çok sayıda panel bağlantısı ve ikili protokol çözme için
  daha zayıf.
- **Karma:** alarm çekirdeği (gateway, yönlendirici) Rust, iş tarafı Python. İş tarafı büyüdükçe yeniden
  değerlendirilebilir.

## Sonuçlar

- Üç dil (Rust, Python, TypeScript): üç araç zinciri, üç CI hattı, üç bağımlılık seti.
- Rust öğrenme eğrisi: Rust kodu bilerek sade tutulur (düz Axum + SQLx, karmaşık generic ve makrolardan
  kaçınılır).
- **Kontrol noktası:** ilk 2–3 haftada giriş ve panel listesi uç noktaları Rust ile yazılır; ekip
  zorlanıyorsa API katmanı için bu karar yeniden açılır.
