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
5. **Tarayıcıda token tutulmaz.** Admin ve web, Next.js sunucu tarafında çalışan bir BFF üzerinden
   API'ye bağlanır; oturum HttpOnly, Secure, SameSite çerezde durur, durum değiştiren isteklerde
   CSRF koruması vardır (SES-01, WEB-05). Mobil uygulama token'ı cihazın güvenli deposunda tutar.
6. **Kullanıcının verdiği adreslere giden istekler kalkandan geçer.** Kamera akışı ve webhook
   adresleri izin listesi, özel ağ ve metadata adreslerinin engellenmesi, DNS yeniden bağlama ve
   yönlendirme kontrolünden geçer (EXT-01, EXT-02).
7. **Sözleşme önce gelir.** API, OpenAPI şemasını kendisi üretir; mobil ve web istemcileri bu şemadan
   üretilir.

## Veritabanı

Şema: [`services/backend/migrations/`](../services/backend/migrations/). Testler:
[`services/backend/tests/sql/`](../services/backend/tests/sql/), çalıştırmak için
`services/backend/scripts/test-db.sh` (geçici bir veritabanında, süper kullanıcıyla).

- **Roller:** migration'lar tablo sahibi rolle çalışır. Uygulama, RLS'yi aşamayan `shedu_app`
  rolüne üye bir kullanıcıyla bağlanır. Yönetici CLI'ı gibi kiracılar arası işler ayrı, `BYPASSRLS`
  yetkili bir rolle ve yalnızca denetim kaydı yazarak yapılır.
- **Kiracı bağlamı:** API her işlemde `SET LOCAL app.org_id = '<token'dan gelen organizasyon>'`
  yapar. Ayar yoksa hiçbir kiracı satırı görünmez; geçersiz değer hata verir.
- **Kiracılar arası bağlantı:** bölüm, zon, yetki ve komut kayıtları bileşik yabancı anahtarla
  aynı organizasyonun aynı paneline bağlanmak zorundadır.
- **Komutlar:** `(user_id, idempotency_key)` tekildir; bir bölümde aynı anda yalnızca bir komut
  yolda olabilir.
- **Denetim kaydı:** yalnızca eklenir; tetikleyici güncellemeyi, silmeyi ve TRUNCATE'i engeller.
- **Saklanmayanlar:** panel PIN'i hiç saklanmaz; parola argon2id, refresh token SHA-256, SMS
  kodu HMAC-SHA256 olarak tutulur.

## Giriş ve oturum

Uç noktalar (`/v1`): `auth/register/start`, `auth/register/complete`, `auth/login`, `auth/refresh`,
`auth/logout`, `auth/sessions` (liste ve `DELETE auth/sessions/{id}`), `auth/password-reset/start`,
`auth/password-reset/complete`, `me`.

- **Kayıt ve sıfırlama:** SMS ile 6 haneli kod; 10 dakika geçerli, tek kullanımlık, en fazla 5
  deneme; amaca ve telefona bağlı HMAC olarak saklanır. Başlatma her zaman 202 döner, hesabın var
  olup olmadığı belli olmaz.
- **Parola:** en az 15, en fazla 128 karakter; yaygın, tekrarlı, ardışık ve kişisel bilgi içeren
  parolalar reddedilir; argon2id.
- **Access token:** HS256, 10 dakika, `iss`/`aud`/`typ` zorunlu. Her istekte kullanıcının etkin ve
  oturumun iptal edilmemiş olduğu veritabanından kontrol edilir; çıkış anında etkilidir.
- **Refresh token:** 30 gün, her kullanımda yenilenir. Kullanılmış bir token yeniden gelirse bütün
  oturum ailesi iptal edilir ve denetim kaydına yazılır. İstemci aynı oturumun yenilemesini tek
  seferde yapmalıdır (single-flight).
- **Deneme sınırları:** hesap, IP ve bütün sistem için ayrı sayaçlar; PostgreSQL'de, bütün API
  kopyalarında ortak ve atomik. Kalıcı kilit yok; parola sıfırlama ayrı sayaçla çalışır.
- **Dışarıya açılma:** API varsayılan olarak yalnızca `127.0.0.1`'i dinler. Dışarıdan yalnızca
  TLS'li ters vekil üzerinden erişilir; doğrudan erişime kapalıdır (NET-02). Ters vekil arkasında
  gerçek istemci IP'si için güvenilir vekil listesi henüz yapılandırılmadı (NET-03).
- **Üretim koruması:** üretimde SMS sağlayıcısı yoksa, veritabanı bağlantısı TLS istemiyorsa veya
  sırlar kısa ya da aynıysa API başlamaz.

## Panel ve komut API'si

Uç noktalar (`/v1/organizations/{org_id}`): `panels` (liste), `panels/{panel_id}` (ayrıntı: bölümler,
zonlar, yöneticiye çıkışlar), `demo-panel` (sanal panel oluştur), `panels/{panel_id}/commands`
(komut ver), `commands/{command_id}` (komut durumu), `events` (WebSocket).

- **Yetki:** organizasyon kimliği yoldan gelir ama tek başına yetki vermez; her istekte üyelik
  kontrol edilir. `owner`/`admin` bütün panellerde tam yetkili. Diğerleri yalnızca yetki kaydı olan
  panelleri ve bölümleri görür; kurma, kapatma ve bypass ayrıca gün/saat penceresine bağlıdır.
  Görme yetkisi olmayan biri panelin var olduğunu da öğrenemez (404); görebilen ama yetkisi
  olmayan 403 alır.
- **Komut türleri:** `arm_away`, `arm_stay`, `arm_night`, `disarm`, `bypass_zones`, `unbypass_zones`.
- **Kurallar:** `shedu-domain` durum makinesi uygulanır (çevrimdışı panel, aynı durum, önce kapat,
  kurmaya hazır değil, başka bölümün zonu). Reddedilen komut da `rejected` olarak kaydedilir.
- **Tekrar anahtarı:** aynı anahtar aynı istekle gelirse ilk komut döner (200), farklı istekle
  gelirse 422. Bir bölümde aynı anda tek komut yolda olabilir (409 `command_in_progress`).
- **Sanal panel:** gerçek cihaza bağlı değildir; komutu kısa bir gecikmeyle tamamlar, bölüm
  durumunu ve panel olayını yazar. Mağaza incelemesi ve deneme için; organizasyon başına bir tane.
  Gerçek panellerde bu işi gateway yapacak.
- **WebSocket:** veritabanı `shedu_events` kanalına yalnızca kimlik içeren bildirim gönderir; her
  mesaj istemcinin kendi yetkisiyle yeniden okunur. `Authorization: Bearer` zorunlu; Origin başlığı
  varsa `SHEDU_ALLOWED_ORIGINS` listesinde olmalı. Çıkış veya üyelik kaldırılınca bağlantı kapanır.
  Kaçırılan olay olursa istemciye `resync` gönderilir.
- **PIN:** panel kullanıcı kodu henüz alınmıyor; gateway ile birlikte, saklanmadan doğrudan panele
  iletilecek şekilde eklenecek.

## Komut akışı (kurma / kapatma)

1. Kullanıcı uygulamada komutu verir; kapatma için PIN ve isteğe bağlı biyometri istenir.
2. API token'ı doğrular, kullanıcının o panelde, o bölümde, o saatte yetkisi olup olmadığına bakar.
3. Komut bir idempotency anahtarıyla kaydedilir; aynı komut iki kez işlenmez (BUS-01, BUS-02).
4. `domain` crate'indeki durum makinesi komutun geçerli olup olmadığını kontrol eder.
5. Gateway komutu panele iletir; sonuç (başarılı, reddedildi, panel çevrimdışı) WebSocket ve push ile döner.
6. Her adım denetim kaydına yazılır: kim, hangi panel, ne zaman, hangi sonuç (LOG-01). Log'larda PIN ve token yer almaz (LOG-02).
