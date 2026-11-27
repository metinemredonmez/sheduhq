# Mimari

## Bileşenler

```
[Mobil (Expo)] ─┐
[Web (Next.js)] ├─HTTPS / WSS──> [API (Rust, Axum)] ──> PostgreSQL
[Admin (Next.js)]┘                    │   │                Redis
                                      │   └─iç kuyruk──> [Gateway (Rust)] <──TLS──> [Alarm panelleri]
                                      │
                                      └─iç ağ, servis kimliği──> [AI servisi (Python)] ──HTTPS──> [LLM sağlayıcısı]

[Bildirim servisi] ──> FCM / APNs
```

| Bileşen | Teknoloji | Görev |
|---|---|---|
| `apps/mobile` | Expo, TypeScript | Ev ve kurumsal kullanıcı uygulaması (iOS + Android) |
| `apps/web` | Next.js | Müşteri web sitesi ve kurumsal portal (planlandı) |
| `apps/admin` | Next.js | Yönetim paneli; ayrı alt alan adında, MFA zorunlu (planlandı) |
| `services/backend/crates/api` | Rust, Axum | REST + WebSocket, kimlik, yetki, komut kabulü |
| `services/backend/crates/gateway` | Rust | Panellerle bağlantı, protokol çözme, komut iletimi |
| `services/backend/crates/domain` | Rust | Panel durum makinesi, komut kuralları, ortak tipler |
| `services/ai` | Python, FastAPI | Olay özeti, alarm önceliklendirme önerisi, destek asistanı |

## Temel kurallar

1. **Alarm yolu AI'ya bağımlı değildir.** Panel → gateway → alarm yönlendirici → bildirim ve operatör
   ekranı zinciri AI olmadan çalışır. AI yalnızca yan yolda, asenkron olarak ek bilgi üretir. AI çökerse
   ya da yavaşlarsa alarm aynı hızla iletilir (ARC-05, EXC-01).
2. **İstemciler MQTT broker'ına ya da panellere doğrudan bağlanmaz.** Kurma ve kapatma komutları
   `POST /panels/{id}/commands` ile API'ye gelir; yetki sunucuda kontrol edilir, onaylanan komut iç
   kuyruktan gateway'e geçer (AZ-01, API-04).
3. **AI servisi veritabanına erişmez.** API, AI servisine yalnızca o isteğin gerektirdiği, azaltılmış ve
   tek kiracıya ait veriyi gönderir. AI servisinin araçları yalnızca okuma yapar; alarmı kuramaz,
   kapatamaz, polis çağıramaz (AI-01, AI-02).
4. **Kiracı (organizasyon) kimliği istemciden alınmaz.** Token'dan çıkarılır ve veri katmanında ikinci
   bir bariyerle (ör. PostgreSQL Row-Level Security) zorlanır (AZ-01, AZ-02).
5. **Sözleşme önce gelir.** API, OpenAPI şemasını kendisi üretir; mobil ve web istemcileri bu şemadan
   üretilir.

## Komut akışı (kurma / kapatma)

1. Kullanıcı uygulamada komutu verir; kapatma için PIN ve isteğe bağlı biyometri istenir.
2. API token'ı doğrular, kullanıcının o panelde, o bölümde, o saatte yetkisi olup olmadığına bakar.
3. Komut bir idempotency anahtarıyla kaydedilir; aynı komut iki kez işlenmez (BUS-01, BUS-02).
4. `domain` crate'indeki durum makinesi komutun geçerli olup olmadığını kontrol eder.
5. Gateway komutu panele iletir; sonuç (başarılı, reddedildi, panel çevrimdışı) WebSocket ve push ile döner.
6. Her adım denetim kaydına yazılır: kim, hangi panel, ne zaman, hangi sonuç (LOG-01). Log'larda PIN ve token yer almaz (LOG-02).
