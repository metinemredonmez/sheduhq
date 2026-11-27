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
  seferde yapmalıdır (single-flight). Oturumun mutlak ömrü 90 gündür: yenileme ile uzamaz, dolunca
  access token da geçersiz olur ve yeniden giriş gerekir.
- **Deneme sınırları:** hesap, IP ve bütün sistem için ayrı sayaçlar; PostgreSQL'de, bütün API
  kopyalarında ortak ve atomik. Kalıcı kilit yok; parola sıfırlama ayrı sayaçla çalışır. Kod
  başına 5 denemeye ek olarak hesap başına 24 saatte en fazla 20 başarısız doğrulama (SMS
  kodunda telefon, ikinci adımda kullanıcı başına); dolunca o hesapta doğru kod da kabul edilmez.
  Bu sayaçlar başkası tarafından tüketilebilir (kurbanın girişi geçici olarak engellenebilir);
  kalıcı kilit olmadığı için bilerek kabul edilen bir dengedir.
- **Dışarıya açılma:** API varsayılan olarak yalnızca `127.0.0.1`'i dinler. Dışarıdan yalnızca
  TLS'li ters vekil üzerinden erişilir; doğrudan erişime kapalıdır (NET-02). Ters vekil arkasında
  gerçek istemci IP'si için güvenilir vekil listesi henüz yapılandırılmadı (NET-03).
- **Üretim koruması:** üretimde SMS sağlayıcısı yoksa, veritabanı bağlantısı TLS istemiyorsa veya
  sırlar (`SHEDU_JWT_SECRET`, `SHEDU_HMAC_SECRET`, `SHEDU_DATA_KEY`) kısa ya da aynıysa API
  başlamaz. Üretimde `SHEDU_DB_ROLE` zorunludur ve her ortamda açılışta bağlantı rolü denetlenir:
  süper kullanıcı, BYPASSRLS yetkili rol veya tabloların sahibi RLS'den muaf olduğu için API ve
  `shedu-admin` böyle bir rolle başlamaz. Kiracı sorgularında organizasyon filtresi ayrıca açıkça
  yazılır; RLS ikinci değil, iki bariyerden biridir.

## İki adımlı doğrulama (MFA)

Uç noktalar (`/v1/auth/mfa`): `GET` (durum), `POST totp/setup`, `POST totp/confirm`,
`POST totp/disable`, `POST recovery-codes`, `POST verify` (girişin ikinci adımı).

- **Faktör:** TOTP (doğrulayıcı uygulama, 30 saniye, 6 hane) ve 10 tek kullanımlık kurtarma kodu.
  Kurulum parolayla yeniden doğrulama ister ve bir kodla onaylanınca açılır; kapatma parola ve
  geçerli bir kod ister. Açma, kapatma ve kurtarma koduyla giriş kullanıcıya SMS ile bildirilir.
- **Saklama:** TOTP sırrı XChaCha20-Poly1305 ile şifreli; anahtar `SHEDU_DATA_KEY`'den amaca özel
  türetilir, anahtar sürümü kayıtla saklanır, şifreli metin kullanıcıya bağlıdır. Kullanılan
  zaman adımı kaydedilir, aynı kod ikinci kez geçmez. Kurtarma kodlarının yalnızca HMAC özeti
  saklanır.
- **Giriş:** faktörü açık kullanıcı parolayı doğrulayınca oturum almaz; 5 dakikalık, tek
  kullanımlık, 5 denemelik bir biletle (`mfa_token`) ikinci adımı tamamlar. Kişi başına ve kaynak
  başına deneme sınırı vardır.
- **Zorunluluk:** işletme ve izleme merkezi organizasyonlarının sahibi, yöneticileri ve
  operatörleri (personel), ikinci adımı tamamlanmamış oturumla o organizasyona hiçbir istekte,
  WebSocket'te veya push bildiriminde erişemez. Ev kullanıcıları ve işletmedeki sıradan üyeler
  için isteğe bağlıdır. MFA kapatılınca bütün oturumların doğrulaması düşer.

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

## Olaylar ve push bildirimleri

Uç noktalar: `GET …/panels/{panel_id}/events` (geçmiş; `before`, `limit`, `from`, `to`),
`POST …/panels/{panel_id}/panic` (`police`, `medical`, `fire`), `POST …/panels/{panel_id}/simulate-alarm`
(yalnızca sanal panel, yönetici), `PUT`/`DELETE /v1/devices/current/push-token`.

- **Geçmiş:** yeniden eskiye, imleçli sayfalama; üye yalnızca yetkili bölümlerinin olaylarını ve
  panel düzeyindeki olayları (bağlantı, güç, panik) görür.
- **Dağıtım:** panel olayı yazılınca dağıtıcı olayı `FOR UPDATE SKIP LOCKED` ile alır, alıcıları
  yetkiye göre bulur, gönderir, `push_deliveries`'e teslim kaydı yazar ve olayı bildirildi
  işaretler. Birden fazla API kopyası aynı olayı iki kez göndermez; süreç çökerse 15 saniyelik
  tarama bekleyen olayları yeniden dener. Alarm bildirimi kaybolmaz.
- **Alıcılar:** yöneticiler ve o bölümü görmeye yetkili üyeler; yalnızca etkin oturumu olan ve
  token'ı kayıtlı cihazlar. Çıkışta, oturum kapatmada ve parola sıfırlamada token silinir. Aynı
  token başka hesaba kaydedilirse eski hesaptan kaldırılır.
- **Öncelik:** alarm `critical` (iOS kritik uyarı, Android alarm kanalı), bağlantı kopması ve güç
  sorunu `warning`, kurma/kapatma `info`.
- **Sağlayıcı:** FCM/APNs henüz bağlanmadı; geliştirmede konsola yazılır, üretimde sağlayıcı yoksa
  API başlamaz.
- **Sanal alarm:** hırsızlık zonu yalnızca kurulu bölümde, yangın/gaz/su/panik/tıbbi/sabotaj zonu
  her zaman alarm verir; bypass edilmiş zon alarm vermez.
- **Bildirim tercihleri:** `GET`/`PATCH /v1/organizations/{org_id}/notification-preferences`.
  Kişi her organizasyon için dört kategoriden üçünü kapatabilir: bağlantı (kopma/yeniden
  bağlanma), güç, kurma/kapatma. Alarm kategorisi (bütün alarm türleri) kapatılamaz; veritabanı
  da bu kategoriyi saklamaz. Kayıt yoksa kategori açıktır. Tercih yalnızca push'u etkiler; olay
  geçmişi ve WebSocket akışı değişmez. Tercih değişikliği denetim kaydına yazılır ("haber
  verildi mi?" sorusunun kanıtı); üyelik silinince tercihler de silinir. Bilinmeyen olay türü
  her zaman gönderilir.

## Bildirim merkezi

Uç noktalar (`/v1`): `GET notifications` (`before`, `limit` 1–100, `unread_only`),
`GET notifications/unread-count`, `POST notifications/read` (`{"all": true}` isteğe bağlı
`organization_id` ile ya da `{"event_ids": [...]}` en fazla 100).

- **Tek akış:** kişinin bütün organizasyonlarındaki olaylar yeniden eskiye, okundu bilgisiyle;
  başlık ve metin push ile aynıdır. Bildirimler ayrıca saklanmaz, her istekte olaylardan kişinin o
  anki yetkisiyle türetilir: yöneticiler ve operatör bütün paneli, üye yalnızca görme yetkisi olan
  bölümleri görür. Yetkisini veya üyeliğini kaybeden kişi eski bildirimleri de göremez.
- **Okundu bilgisi:** organizasyon başına "buraya kadar hepsi okundu" sınırı ve sınırın üstünde
  tek tek okunanlar; sınır ilerleyince tekil kayıtlar silinir. Organizasyona katılmadan önceki
  olaylar okunmuş sayılır. Görülemeyen olay okundu yapılamaz (sessizce yok sayılır). Okunmamış
  sayısı 999'da kesilir.
- **MFA:** işletme personelinin ikinci adımı tamamlanmamış oturumunda o organizasyonun
  bildirimleri gösterilmez; yanıtta `locked` listesinde `mfa_required` olarak belirtilir.
- **Tercihler:** bildirim tercihleri yalnızca push'u etkiler; merkezde bütün olaylar görünür.

## Üyeler, davetler ve panel yetkileri

Uç noktalar (`/v1/organizations/{org_id}` altında): `GET /members`, `PATCH`/`DELETE
/members/{user_id}`, `POST /ownership-transfer`, `GET`/`POST /invitations`, `DELETE /invitations/{id}`, `GET`/`POST
/members/{user_id}/grants`, `PUT`/`DELETE /grants/{grant_id}`. Davet edilen taraf: `GET /v1/invitations`,
`POST /v1/invitations/{id}/accept`, `POST /v1/invitations/{id}/decline`.

- **Roller:** `owner` (tek, organizasyonu açan kişi), `admin`, `member`, `operator`. Herkes
  yalnızca kendinden alt roldeki birini yönetir ve yalnızca kendinden alt bir rol atar: sahip
  yöneticiyi, üyeyi ve operatörü; yönetici yalnızca üyeyi ve operatörü. Kimse kendi rolünü
  değiştiremez. Sahip çıkarılamaz, rolü değiştirilemez, ayrılamaz; veritabanı da her
  organizasyonda tek sahip olmasını ve uygulamanın sahip üyeliğine doğrudan dokunamamasını zorlar.
- **Sahiplik devri:** sahip, güncel parolasıyla yeniden doğrulayarak sahipliği bir yöneticiye
  devreder; önceki sahip yönetici olur. Devir veritabanındaki tek bir fonksiyonla, tek adımda
  yapılır. Önceki sahibin açık yönetici davetleri iptal edilir.
- **Operatör:** izleme personeli; yalnızca işletme ve izleme merkezi organizasyonlarında olur
  (veritabanı da zorlar). Organizasyondaki bütün panelleri, bölümleri, zonları ve olayları görür,
  alarm bildirimlerini alır; kimseyi yönetemez, çıkışları göremez, kurma/kapatma/bypass için yetki
  kaydı gerekir. Bir izleme merkezinin müşteri organizasyonlarını izlemesi (organizasyonlar arası
  erişim) henüz yok; izleme merkezi modeli netleşince tasarlanacak.
- **Davet:** telefon numarasına bağlıdır; bağlantı veya kod taşımaz. Kişi o numarayla (SMS koduyla
  doğrulanmış) oturum açınca daveti uygulamada görür. 7 gün geçerlidir, tek kez kabul, ret veya
  iptal edilir. Davet SMS'i sabit bir metindir; organizasyon veya kişi adı içermez, böylece
  platform adına oltalama mesajı gönderilemez. Davet oluşturma yanıtı numaranın kayıtlı olup
  olmadığını belli etmez. Sınırlar: organizasyon başına günde 20, kullanıcı başına saatte 10, bir
  numaraya bütün organizasyonlardan günde 3 davet SMS'i; bu sayaç kayıt kodunu etkilemez.
- **Davet edenin yetkisi:** yönetici rolünü kaybeden veya çıkarılan kişinin açık davetleri iptal
  edilir; ayrıca kabul anında davet edenin o rolü verme yetkisi yeniden doğrulanır.
- **Panel yetkisi:** üye başına panel veya bölüm; görme, kurma, kapatma, bypass; geçerlilik süresi
  ve haftalık pencereler. Yalnızca yöneticiler verir; yöneticilere yetki verilmez (zaten tam
  yetkilidirler), böylece kimse kendine yetki veremez. Kurma/kapatma görme yetkisi olmadan
  verilemez. Kapsam (kişi, panel, bölüm) sonradan değişmez.
- **Etki hemen:** rol, üyelik ve yetki her istekte, her WebSocket mesajında ve her push
  gönderiminde veritabanından okunur. Üyelik silinince yetki kayıtları da silinir.

## Kişisel veriler (KVKK)

Uç noktalar (`/v1`): `PATCH me` (görünen ad), `POST me/phone/start`, `POST me/phone/complete`,
`POST me/data-export`, `POST me/delete`, `GET`/`POST me/consents` (rıza defteri). KVKK md. 11'deki bilgi alma, düzeltme ve silme
haklarının teknik karşılığıdır; aydınlatma metni ve hukuki kararlar açık sorulardadır.

- **Ortak koşul:** dışa aktarma, numara değişimi ve silme parolayla yeniden doğrulama ister; MFA
  açıksa oturumda ikinci adım tamamlanmış olmalıdır. Ele geçirilmiş bir access token ile bütün
  kişisel veri alınamaz, numara değiştirilemez, hesap silinemez.
- **Dışa aktarma:** JSON (`shedu-personal-data/v1`): profil, üyelikler, cihazlar (push token'ı
  olmadan), oturumlar, MFA durumu (sır olmadan), kendi panel yetkileri, kendi komutları ve
  kendisinin yaptığı veya ona yönelik güvenlik olayları (ayrıldığı organizasyonlar dahil, en çok
  10.000 satır). Başka kişilerin kimliği, numarası ve olay ayrıntısı girmez. Dosya sunucuda
  tutulmaz, yanıt önbelleğe alınmaz; kullanıcı başına günde 3 kez.
- **Düzeltme:** görünen ad doğrudan değişir. Numara değişimi yeni numaraya giden SMS koduyla
  tamamlanır; kod değişimi başlatan kullanıcıya bağlıdır. Yeni numara başka hesaptaysa kod
  gönderilmez, yanıt aynıdır. Değişiklik eski numaraya bildirilir. Günde 3 başlatma.
- **Silme talebi (30 gün geri alınabilir):** talep hesabı hemen kapatır: bütün oturumlar biter,
  push token'ları silinir, hesap bildirim almaz. Kalıcı silme 30 gün sonraya planlanır ve kişiye
  SMS ile bildirilir. Bu sürede tam doğrulamayla (parola ve MFA açıksa ikinci adım) giriş yapan
  kişinin talebi iptal olur; yalnızca parola yetmez. Parolasını unutan kişi bu sürede parola
  sıfırlayıp giriş yapabilir. Başka üyesi olan organizasyonun sahibi talep edemez, önce
  sahipliği devretmelidir (yanıt hangi organizasyonlar olduğunu söyler).
- **Kalıcı silme (anonimleştirme ve yok etme):** API'deki silme işi saatte bir süresi dolan
  talepleri bulur (birden fazla kopyada `SKIP LOCKED` ile tek kez) ve veritabanındaki
  `erase_account()`'ı tek işlemde çalıştırır. Kişinin tek başına sahibi olduğu organizasyonlar
  bütün verisiyle (paneller, olaylar, komutlar, davetler) silinir. Diğer organizasyonlardaki
  üyelikler ve yetkiler silinir. Numarasına gelmiş davetler, cihazlar, oturumlar, MFA kayıtları
  silinir. Başka organizasyonlardaki güvenlik kayıtları (komut, bildirim teslimi, denetim kaydı)
  ve rıza kayıtları korunur; kullanıcı satırı ad, numara, e-posta ve parola olmadan "Silinmiş
  kullanıcı" olarak kalır, böylece bu kayıtlar kişiye bağlanamaz. Silme kullanıcıya SMS ile
  bildirilir. Aynı numarayla yeniden kayıt olunabilir; bu yeni bir hesaptır.
- **Rıza defteri:** amaçlar (`consent_purposes`) ve güncel metin sürümleri veritabanındadır;
  başlangıçta `privacy_notice` (aydınlatma metninin gösterildiği kaydı, geri çekilmez) ve
  `marketing` (açık rıza) var, sürümleri taslaktır. Her verme ve geri çekme ayrı bir kayıttır;
  kayıtlar değiştirilemez ve silinemez. Güncel durum son kayıttır; eski metin sürümüne verilen
  yanıt kabul edilmez, metin değişince istemci yeniden sorar (`up_to_date`). Dışa aktarmada
  bütün geçmiş yer alır.

## Platform yöneticisi aracı (`shedu-admin`)

Pilotta müşteri organizasyonu açma, panel atama ve olay anında kullanıcıyı kapatma işleri sunucuda
çalışan `shedu-admin` komut satırı aracıyla yapılır; API'de karşılığı yoktur. Admin paneli
(Next.js) gelince aynı kurallarla onun arkasına taşınacaktır.

```
shedu-admin org list
shedu-admin org show <ORG_ID>
shedu-admin org create --name "Örnek AŞ" --kind business --owner-phone +90… --owner-name "…" --reason "…"
shedu-admin panel add --org <ORG_ID> --name Merkez --brand acme --serial SN-1 --layout panel.json --reason "…"
shedu-admin user disable --phone +90… --reason "…"
shedu-admin user enable --phone +90… --reason "…"
```

- **Ayrı rol:** araç `shedu_admin` veritabanı rolüyle bağlanır (gerçek giriş rolü bu role üye
  yapılır, parolası API'ninkinden ayrıdır: `CREATE ROLE … LOGIN; GRANT shedu_admin TO …`). Bu
  rol uygulama rolünün yetkilerini miras alır ve RLS'ye aynen tabidir; ek olarak yalnızca bütün
  organizasyonların özetini veren fonksiyonu çalıştırabilir ve bayrak ile sürüm politikası
  yazabilir. API'nin rolü bu fonksiyonu çalıştıramaz; ancak kimlik tabloları (kullanıcılar,
  üyelikler) RLS dışında olduğundan, API ele geçirilirse organizasyon kimlikleri yine okunabilir.
  Ayrımın amacı yönetim işlemlerini sınırlamaktır, ele geçirilmiş API'ye karşı tam bir kalkan
  değildir.
- **Gerekçe ve iz:** her değişiklik `--reason` (10–300 karakter) ister; işlemi yapan kişi
  (`--operator` ya da sunucudaki kullanıcı adı) ve gerekçe denetim kaydına yazılır. Telefon
  numarası denetim kaydına yazılmaz, ekranda maskelenir.
- **Sahip:** yeni organizasyonun sahibi kayıtlı değilse parolasız bir hesap açılır; kişi
  parolasını uygulamadaki parola sıfırlama (SMS kodu) ile kendisi belirler. Araç parola
  belirlemez ve göstermez.
- **Panel:** bölüm ve zon düzeni JSON dosyasından okunur (bilinmeyen alan reddedilir); panel
  çevrimdışı ve "kurmaya hazır değil" başlar, gateway bağlanana kadar komut kabul edilmez. Demo
  panellerin markası gerçek panele verilemez; aynı marka ve seri numarası ikinci kez eklenemez.
- **Kullanıcıyı kapatma:** bütün oturumlar ve push token'ları hemen iptal edilir; yeniden
  açılınca kişi normal giriş yapar.
- **Üretim:** `DATABASE_URL` TLS (`sslmode=verify-full` veya `require`) istemiyorsa araç
  başlamaz. Sunucuya erişim (SSH, anahtar, yetki) dağıtım tarafında kısıtlanır (OPS-02).

## Özellik bayrakları

Uç nokta: `GET /v1/organizations/{org_id}/features` → `{"features": {"camera_live": true, …}}`.
Uygulama hangi ekranı göstereceğine bununla karar verir; sunucu tarafında `features::is_enabled`
kullanılır. Bayrakları yalnızca platform yöneticisi değiştirir:

```
shedu-admin flag list
shedu-admin flag set camera_live --state on --rollout 0 --description "Canlı kamera" --reason "…"
shedu-admin flag override camera_live --org <ORG_ID> --state on|off|clear --reason "…"
```

- **Değerlendirme:** kapalı bayrak her organizasyonda kapalıdır (acil kapatma, organizasyon
  ayarını da ezer). Açıksa organizasyona özel ayar varsa o geçerlidir; yoksa organizasyonun
  bayrak için sabit kovası (anahtar ve kimlikten SHA-256) ile yüzde uygulanır. Yüzde artınca
  önceden açık organizasyonlar açık kalır. Tanımsız bayrak kapalıdır.
- **Pilot:** açık, yüzde 0, pilot organizasyonlara `override … --state on`.
- **Sınırlar:** bayrak yetki vermez, yalnızca özelliği gösterir veya gizler. API'nin rolü
  bayrak yazamaz ve bütün organizasyon ayarlarını okuyamaz; her organizasyon yalnızca kendi
  ayarını görür. Her değişiklik gerekçeli ve denetim kaydındadır.

## Zorunlu güncelleme kontrolü

- **Kontrol:** `GET /v1/app-version?platform=ios&version=1.4.2` giriş gerektirmez; yanıt
  `up_to_date`, `update_recommended` veya `update_required`, en düşük ve en güncel sürüm ve mağaza
  adresidir. Uygulama açılışta sorar; zorunluysa güncelleme ekranını gösterir.
- **API'de engel:** istemci `X-Shedu-App: ios/1.4.2` başlığını gönderir. En düşük sürümün
  altındaki istemcinin bütün istekleri (giriş dahil) 426 `update_required` ile reddedilir; kontrol
  ucu ve `/health` bunun dışındadır. Başlıksız istemciler (web arka yüzü, araçlar) etkilenmez;
  bozuk başlık 400'dür. Başlık taklit edilebilir, bu bir güvenlik sınırı değildir; amaç dürüst eski
  istemcileri bilinen hatalı sürümlerden uzaklaştırmaktır.
- **Sürüm:** `MAJOR[.MINOR[.PATCH]]`, sayısal karşılaştırılır (1.10 > 1.9); ön sürüm eki kabul
  edilmez. Politika yoksa hiçbir şey zorlanmaz. API politikayı 60 saniyelik önbellekle okur.
- **Yönetim:** `shedu-admin app-version set --platform ios --minimum 1.2.0 --latest 1.4.0
  --store-url https://apps.apple.com/… --reason "…"`. Mağaza adresi yalnızca
  `https://apps.apple.com/` veya `https://play.google.com/` ile başlayabilir (API ve veritabanı
  ayrı ayrı denetler); kullanıcıya sahte bir "güncelle" bağlantısı gösterilemez. API'nin rolü
  politikayı değiştiremez.

## Komut akışı (kurma / kapatma)

1. Kullanıcı uygulamada komutu verir; kapatma için PIN ve isteğe bağlı biyometri istenir.
2. API token'ı doğrular, kullanıcının o panelde, o bölümde, o saatte yetkisi olup olmadığına bakar.
3. Komut bir idempotency anahtarıyla kaydedilir; aynı komut iki kez işlenmez (BUS-01, BUS-02).
4. `domain` crate'indeki durum makinesi komutun geçerli olup olmadığını kontrol eder.
5. Gateway komutu panele iletir; sonuç (başarılı, reddedildi, panel çevrimdışı) WebSocket ve push ile döner.
6. Her adım denetim kaydına yazılır: kim, hangi panel, ne zaman, hangi sonuç (LOG-01). Log'larda PIN ve token yer almaz (LOG-02).
