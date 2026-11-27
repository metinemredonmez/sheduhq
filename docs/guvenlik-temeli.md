# Güvenlik temeli

Shedu'da güvenlik sonradan eklenmez; giriş, oturum, yetki, API, dosya yükleme ve güvenlik başlıkları ilk
kurulumda aşağıdaki kontrollere göre yapılır. Kontrol kimlikleri, OWASP ASVS 5.0.0 ile eşlenmiş iç
güvenlik kataloğumuzdan gelir. Önce P0'lar karşılanır.

Durum dili: **Doğrulanacak / Geçti / Kaldı / Uygulanmaz / Risk kabul edildi / Engellendi.** Kanıtsız
"Geçti" yazılmaz.

| Alan | Kontrol | Shedu'da nasıl | Durum |
|---|---|---|---|
| Kimlik | AUT-01 | Personel (işletme/izleme merkezinde sahip, yönetici, operatör) için MFA zorunlu; yalnızca parolalı oturuma ayrıcalık yok | Doğrulanacak |
| Kimlik | AUT-04, KEY-04 | Faktör ekleme/kaldırmada yeniden doğrulama; tek kullanımlık kurtarma kodu; TOTP sırrı şifreli | Doğrulanacak |
| Kimlik | AUT-02, RES-01 | Giriş ve SMS kodu uç noktalarında çok boyutlu hız sınırı ve kota | Doğrulanacak |
| Kimlik | AUT-03 | Sıfırlama ve davet kodları tek kullanımlık, kısa ömürlü | Doğrulanacak |
| Parola | PWD-01, PWD-03, PWD-04 | Minimum uzunluk, sızmış parola kontrolü, argon2id | Doğrulanacak |
| Oturum | SES-01, SES-02 | Tek oturum taşıma biçimi; girişte ve yetki değişiminde yenileme | Doğrulanacak |
| Oturum | SES-04, SES-05 | Çıkışta, cihaz silmede ve rol düşürmede iptal; refresh token ailesi | Doğrulanacak |
| Token | TOK-01, TOK-02 | JWT'de algoritma listesi sabit; `exp`, `aud`, `iss` zorunlu; anahtar güvenilir kaynaktan | Doğrulanacak |
| Yetki | AZ-01, AZ-02, AZ-04 | Her komutta izin + kapsam + nesne + durum birlikte; veri katmanında ikinci bariyer | Doğrulanacak |
| Yetki | AZ-05 | Rol hiyerarşisi: yalnızca alt rol yönetilir; tek ve korunan sahip; kendine yetki yok | Doğrulanacak |
| Yönetim | AZ-05, OPS-02, LOG-01 | Platform yöneticisi ayrı araç ve ayrı veritabanı rolüyle; her değişiklik gerekçeli ve kayıtlı | Doğrulanacak |
| API | API-02 | Alan düzeyinde yazma izni; istemci izinsiz alan gönderemez | Doğrulanacak |
| API | API-04 | WebSocket'te kimlik, origin ve mesaj başına yetki | Doğrulanacak |
| İş mantığı | BUS-01, BUS-02 | Komut durum makinesi (`domain` crate'i), idempotency, atomik geçiş | Doğrulanacak |
| Ağ | NET-01 | Her bağlantıda TLS; panel bağlantıları dahil | Doğrulanacak |
| Sırlar | KEY-02 | Sır yönetimi; istemci uygulamasında ve depoda sır yok | Doğrulanacak |
| Log | LOG-01, LOG-02 | Yapılandırılmış güvenlik olayı; log'da PIN, token, telefon yok | Doğrulanacak |
| Veri | DAT-01, DAT-02, AZ-03 | Kişisel veri dışa aktarma yalnızca kişinin kendi verisi; yeniden doğrulama, günlük sınır, dosya sunucuda tutulmaz | Doğrulanacak |
| Veri | DAT-05 | Hesap silme: 30 gün geri alınabilir talep, sonra anonimleştirme ve yok etme tek işlemde; güvenlik kayıtları kimliksiz kalır; rıza defteri yalnızca eklenir | Doğrulanacak |
| AI | AI-01, AI-02, AI-03 | Modelin aracı yok; yalnızca görünür ve kimliksiz veri; kesin bilgi koddan; sonuçtan bağımsız maliyet defteri ve bütçe; bayrakla kapalı | Doğrulanacak |
| Üretim | OPS-01 | Güvenli üretim profili; debug ve sunucu seçici yok; varsayılan dinleme adresi `127.0.0.1` | Doğrulanacak |
| Build | OPS-04 | CODEOWNERS, korumalı `main`, Dependabot, en az yetkili CI | Doğrulanacak |
| Hata | ARC-05, EXC-01 | Arıza halinde güvenli davranış: belirsizse komut reddedilir | Doğrulanacak |

### Kanıt notları

- **AZ-02, AZ-04, BUS-02, LOG-03 (şema düzeyi):** `services/backend/tests/sql/001_tenancy_and_integrity.sql`
  bağlamsız erişimin boş döndüğünü, kiracılar arası okuma, yazma ve bağlantının engellendiğini,
  bölüm başına tek yoldaki komutu ve denetim kaydının değiştirilemezliğini test eder. Testlerin
  bozulunca kaldığı (RLS kapatma, yanlış beklenti) yerelde doğrulandı. API katmanı henüz bu
  bağlamı kullanmadığı için durumlar "Doğrulanacak" kalır.
- **KEY-02:** CI'da gitleaks ile `main`'e her push'ta ve her pull request'te sır taraması yapılır.
- **AUT-02, AUT-03, PWD-01, SES-02, SES-04, SES-05, TOK-01 (kod düzeyi):**
  `services/backend/crates/api/tests/auth.rs` (17 entegrasyon testi, gerçek PostgreSQL, uygulama
  rolüyle) ve birim testleri; kod tek kullanımı ve 5 deneme sınırı, amaca bağlılık, hesabın
  varlığının belli olmaması, hesap başına sınırın başka hesabı ve parola sıfırlamayı etkilememesi,
  refresh yeniden kullanımında ailenin iptali, çıkışta access token'ın hemen geçersizleşmesi,
  başkasının oturumunun kapatılamaması, yanlış `alg`/`iss`/`aud`/`typ`/süre ile token reddi.
  Üretim ortamında çok kopyalı doğrulama yapılmadığı için durumlar "Doğrulanacak" kalır.
- **AZ-01, AZ-04, BUS-01, BUS-02, API-04, SES-04 (panel ve komut):**
  `services/backend/crates/api/tests/panels.rs` (12 entegrasyon testi): başka organizasyonun
  paneli ne okunabilir ne yönetilebilir; üye yalnızca yetkili bölümü görür; kapatma yetkisi yoksa
  403, pencere kapalıysa 403; aynı anahtarla tekrar aynı komut, farklı istekle 422; bölüm başına
  tek yoldaki komut; reddedilen komutun kaydı; başka bölümün zonu bypass edilemez; WebSocket'te
  token zorunlu, yabancı origin reddi, başka organizasyonun olayı gelmez, çıkıştan sonra bağlantı
  kapanır.
- **Olay ve push (AZ-01, BUS-02, SES-04, LOG-01):** `services/backend/crates/api/tests/events.rs`
  (8 entegrasyon testi): geçmişte kiracı ve bölüm izolasyonu; alarm bildirimi yalnızca yetkili
  cihazlara ve kritik öncelikle; çıkış yapılmış cihaza bildirim gitmez; token el değiştirince eski
  hesaptan kalkar; iki dağıtıcı aynı olayı tek kez gönderir; kaçırılan olay taramayla yakalanır;
  teslim kaydı tutulur.
- **Üyelik, davet ve yetki (AUT-03, AZ-01, AZ-02, AZ-04, AZ-05, API-02, SES-04, RES-01, LOG-01):**
  `services/backend/crates/api/tests/members.rs` (7 entegrasyon testi) ve
  `services/backend/tests/sql/003_members_invitations.sql`: davet yalnızca o numarayla doğrulanmış
  hesaba görünür ve tek kez kabul edilir; başka hesap kimliği bilse de kabul edemez; iptal edilen
  ve yetkisini kaybetmiş kişinin daveti geçersizdir (API dışında rol düşürülse de); davet SMS'inde
  kullanıcı metni, bağlantı ve kod yoktur; bir numaraya günde en fazla 3 davet SMS'i gider ve bu
  kayıt kodunu engellemez; yönetici başkasını yönetici yapamaz, sahibe ve kendine dokunamaz; rol
  düşürme ve üyelikten çıkarma aynı access token'la bir sonraki istekte geçerlidir; çıkarılan
  üyenin yetki kayıtları silinir; başka kiracının paneli, bölümü veya üye olmayan biri yetkiye
  bağlanamaz; yetki kapsamı değiştirme isteğiyle taşınamaz; reddedilen denemeler denetim kaydına
  girer. Üç koruma (kabul anındaki yeniden doğrulama, rol karşılaştırması, üyelik-yetki bağı)
  tek tek bozulduğunda ilgili testin kaldığı yerelde doğrulandı.
- **Sahiplik devri ve operatör (AZ-05, AUT-02):** aynı dosyada 2 entegrasyon testi ve
  `services/backend/tests/sql/004_ownership_operator.sql`: sahiplik yalnızca sahip tarafından,
  yalnızca yöneticiye ve parola doğrulamasından sonra devredilir; yanlış parolada devir olmaz ve
  deneme kaydedilir; her an tek sahip vardır; uygulama rolü devir fonksiyonu dışında sahip
  üyeliğine dokunamaz. Operatör ev organizasyonunda olamaz; bütün panelleri görür ama yetki kaydı
  olmadan kuramaz, kimseyi yönetemez, alarm bildirimini alır. Parola doğrulaması ve operatör tür
  kontrolü bozulduğunda testlerin kaldığı yerelde doğrulandı.
- **İki adımlı doğrulama (AUT-01, AUT-04, KEY-04, AUT-02, LOG-01):**
  `services/backend/crates/api/tests/mfa.rs` (3 entegrasyon testi), `tests/sql/005_mfa.sql` ve
  `crypto.rs`/`totp.rs` birim testleri (RFC 4226/6238 test vektörleri; bozulmuş şifreli metin,
  yanlış kullanıcı, yanlış anahtar, yanlış sürüm reddi): kurulum yanlış parolayla başlamaz; sır
  veritabanında düz durmaz; faktörü açık kullanıcı parolayla oturum alamaz; kullanılmış kod,
  kullanılmış kurtarma kodu ve kullanılmış bilet reddedilir; 5 yanlış denemede bilet tükenir;
  kişi başına deneme sınırı 429 verir; işletme personeli yalnızca parolalı oturumla (MFA'dan önce
  açılmış oturum dahil) organizasyona erişemez ve alarm push'u o oturumun cihazına gitmez; kapatma
  parola ve kod ister, kapatınca personel erişimi kalkar; açma, kapatma ve kurtarma koduyla giriş
  bildirilir. Zorunluluk, tekrar oynatma koruması ve push kuralı tek tek bozulduğunda ilgili
  testin kaldığı yerelde doğrulandı.
- **Kişisel veriler (DAT-01, DAT-02, DAT-05, AZ-03, AUT-04, RES-01, LOG-02):**
  `services/backend/crates/api/tests/privacy.rs` (6 entegrasyon testi),
  `services/backend/tests/sql/006_privacy.sql` ve `007_consent_deferred_erasure.sql`: dışa aktarma yanlış parola ve fazladan alanla
  çalışmaz; yalnızca kişinin kendi komutlarını ve yetkilerini içerir, sahibin numarası ve kimliği
  girmez, push token'ı girmez; ayrıldıktan sonra da kendi komutu gelir; günde 3'ten fazlası 429.
  MFA açıkken yalnızca parolalı oturumla dışa aktarma, numara değişimi ve silme yapılamaz.
  Başka üyesi olan organizasyonun sahibi silemez (409 ve organizasyon listesi); silinen hesapta
  oturum ve giriş kapanır, tek üyeli organizasyon bütün verisiyle silinir, ortak organizasyondaki
  komut ve denetim kaydı kalır ama kişi kimliksizdir, numarasına gelen davet silinir, denetim
  kaydına numara yazılmaz; aynı numarayla yeniden kayıt olunur. Numara değişimi başka hesabın
  numarasına kod göndermez, başkasının değişim kodunu kabul etmez, eski numaraya bildirir.
  Silme talebi oturumu hemen kapatır ve push token'ını siler; süre dolmadan silme işi dokunmaz,
  dolunca bir kez siler; süre içinde giriş talebi iptal eder, MFA açıksa yalnızca parola iptal
  etmez. Rıza defterinde bilinmeyen amaç, eski metin sürümü ve aydınlatma kaydının geri
  çekilmesi reddedilir; kayıtlar uygulama rolüyle de tablo sahibiyle de değiştirilemez ve
  silinemez; hesap silinince rıza kayıtları kalır.
  Dışa aktarmadaki kullanıcı filtresi, parola şartı, numara kodunun kullanıcıya bağı,
  veritabanındaki sahip kontrolü, MFA'da iptalin ikinci adıma bağlılığı, metin sürümü kontrolü,
  silme işinin süre kontrolü ve defterin değiştirilemezlik tetikleyicisi tek tek bozulduğunda
  ilgili testin kaldığı yerelde doğrulandı.
- **Bildirim tercihleri (AZ-02, API-02, LOG-01):** `services/backend/crates/api/tests/notifications.rs`
  (2 entegrasyon testi), `tests/sql/008_notification_preferences.sql` ve domain birim testi:
  varsayılan hepsi açık; alarmı kapatma isteği reddedilir ve aynı istekteki başka değişiklik de
  uygulanmaz; bilinmeyen alan reddedilir; üye olmayan göremez ve yazamaz; tercih organizasyon
  başınadır; kurmayı kapatan üyeye kurma bildirimi gitmez ama alarm gider, geri açınca kapatma
  bildirimi gider. Veritabanında alarm kategorisi yazılamaz, kişi başkası adına veya üyesi
  olmadığı organizasyona tercih yazamaz, üyelik silinince tercih silinir. Dağıtıcı filtresi, alarm
  koruması ve kişi başına yazma politikası bozulduğunda ilgili testin kaldığı yerelde doğrulandı.
- **Platform yöneticisi (AZ-05, OPS-02, LOG-01, SES-04, EXC-01):** `services/backend/crates/api/tests/admin.rs`
  (3 entegrasyon testi), `tests/sql/009_platform_admin.sql`, `admin.rs` ve `shedu-admin` birim
  testleri ve aracın yerel veritabanında uçtan uca çalıştırılması: gerekçesiz veya kısa gerekçeli
  değişiklik reddedilir; açılan sahip parolasız başlar ve ancak SMS kodlu parola sıfırlamayla
  girer; işletme sahibi MFA'dan sonra paneli görür; yeni panel çevrimdışıdır ve komut reddedilir;
  ayrılmış marka (büyük/küçük harf farkıyla da) ve tekrar eden seri reddedilir, başarısız ekleme
  iz bırakmaz; uygulama rolü organizasyon listesini alamaz, yönetici rolü RLS'ye tabidir ve
  denetim kaydını silemez; kapatılan kullanıcının açık oturumu hemen kapanır, push token'ı silinir;
  denetim kaydında işlemi yapan ve gerekçe vardır, numara yoktur; üretimde TLS'siz bağlantıyla
  araç başlamaz. Rol ayrımı, push token silme ve ayrılmış marka kontrolü bozulduğunda ilgili
  testin kaldığı yerelde doğrulandı.
- **Özellik bayrakları (AZ-02, AZ-05, LOG-01):** `services/backend/crates/api/tests/features.rs`
  (2 entegrasyon testi), `tests/sql/010_feature_flags.sql`, birim testleri ve aracın yerel
  çalıştırılması: tanımsız bayrak kapalıdır; pilot ayarı yalnızca o organizasyonda açar; üye
  aynı değeri görür, üye olmayan göremez; organizasyon ayarı bayrağı kapatabilir ve kaldırılabilir;
  acil kapatma pilot ayarını da ezer; kovalar sabit ve dengelidir; açıklamasız yeni bayrak,
  geçersiz anahtar ve yüzde reddedilir; API rolü bayrak yazamaz ve bütün ayarları okuyamaz;
  yönetici de RLS'ye tabidir. Acil kapatmanın önceliği ve rol ayrımı bozulduğunda ilgili testin
  kaldığı yerelde doğrulandı.
- **Zorunlu güncelleme (EXT, AZ-05, API-02, LOG-01):** `services/backend/crates/api/tests/app_version.rs`
  (3 entegrasyon testi), `tests/sql/011_app_versions.sql`, domain ve birim testleri ve aracın
  yerel çalıştırılması: politika yokken her sürüm güncel; geçersiz platform, sürüm ve bilinmeyen
  parametre reddedilir; sürümler sayısal karşılaştırılır; eski istemcinin istekleri ve girişi 426
  alır, sürüm kontrolü ve sağlık ucu açık kalır; başlıksız istemci etkilenmez, bozuk başlık 400;
  en düşük sürüm yükselince önceki istemci hemen reddedilir; mağaza adresi resmi mağaza dışına
  (alt alan, `@`, yol içinde adres, http) gidemez; API rolü politikayı yazamaz. API'deki engel ve
  sayısal karşılaştırma bozulduğunda ilgili testin kaldığı yerelde doğrulandı.
- **Bildirim merkezi (AZ-01, AZ-02, AZ-03, AUT-01, SES-04):** `services/backend/crates/api/tests/inbox.rs`
  (2 entegrasyon testi) ve `tests/sql/012_notification_center.sql`: sahip bütün, üye yalnızca
  yetkili bölümün olaylarını görür; görülemeyen olay okundu yapılamaz; başkasının okuması
  etkilemez; sayfalama, yalnızca okunmamış süzgeci ve hepsini okundu yapma çalışır; katılmadan
  önceki olay okunmuş sayılır; üyelik silinince bildirimler ve okundu bilgisi gider; işletme
  personelinin MFA'sız oturumunda olaylar gösterilmez, kilitli denir; okundu bilgisi başkası
  adına yazılamaz, başka organizasyonun olayına bağlanamaz. Görünürlük kuralı, katılma zamanı ve
  MFA kilidi bozulduğunda ilgili testin kaldığı yerelde doğrulandı.
- **27 Kasım denetim düzeltmeleri (AZ-02, EXC-01, AZ-01, API-04, SES-03, SES-04, DAT-01, AUT-02):**
  bağımsız kod denetiminin 1 yüksek ve 4 orta bulgusu düzeltildi; her biri için önce açığı
  gösteren, düzeltmeden önce kalan test yazıldı (`services/backend/crates/api/tests/hardening.rs`,
  `panels.rs`): RLS'yi aşan rolle açılış reddi ve RLS olmadan da kiracı filtrelerinin tuttuğu
  (panel listesi ve ayrıntısı, geçmiş, komut, başka kiracının paneline komut, bildirim merkezi);
  WebSocket'te bölüm yetkisi; MFA açılınca diğer oturumların ve cihaz bildirimlerinin kapanması;
  90 günlük mutlak oturum ömrü; silme talebinde gönderilmiş davetlerin iptali, etkin olmayan
  kişinin davetinin kabul edilmemesi ve kalıcı silmenin takılmaması; hesap başına 24 saatte 20
  başarısız doğrulama sınırı (SMS ve ikinci adım).
- **AI olay özeti (AI-01, AI-02, AI-03, LOG-02, ARC-04):**
  `services/backend/crates/api/tests/ai.rs` (5 entegrasyon testi, gerçek PostgreSQL ve yerel
  sahte AI servisi), `services/backend/tests/sql/013_ai_usage.sql`, `014_audit_fixes.sql` ve
  `services/ai/tests` (104 test, sahte model istemcisi): bayrak kapalıyken 403, servis yokken 503, üye olmayana 404;
  AI servisine kimlik, telefon ve görünmeyen bölümün olayı gitmez; sayılar ve dikkat işareti
  AI'nın yanlış değerlerinden değil SQL'den gelir; 500 olay sınırında sayılar yine kesin; ret,
  hata ve düşen servis sabit kodlara döner ve harcaması deftere yazılır; bağlanılamayınca
  harcama yazılmaz; saatlik sınır ve maliyet sınırı (kullanıcı ve sistem) dolunca model
  çağrılmaz; defter yalnızca eklenir, başkası adına yazılamaz, satırları okunamaz, tablo sahibi
  bile değiştiremez, yabancı anahtarı yoktur. AI servisinde: veri bloğunu kapatmaya çalışan zon
  adı kaçışlanır, tanımsız alan ve kimlik reddedilir, yedek model denemeleri faturaya katılır,
  fiyatsız modelle başlanmaz. Bütçe kontrolü, ret harcaması ve bölüm filtresi bozulduğunda ilgili
  testin kaldığı yerelde doğrulandı. Rust API'si gerçek AI servisine (sahte model yazıcısıyla)
  bağlanarak yeni sözleşme uçtan uca doğrulandı (27 Kasım 2026). Gerçek modelle çağrı yapılmadı.
- **İkinci denetim (27 Kasım 2026, commit `aec05ed` üzerinde, Codex):** 20 bulgu kodda doğrulandı;
  hepsi düzeltildi veya aşağıda kalan risk olarak yazıldı. Regresyon testleri:
  `services/backend/crates/api/tests/audit_fixes.rs` (ilk 11 test), `ai.rs`, `hardening.rs`,
  `config.rs` birim testleri, `tests/sql/014_audit_fixes.sql`, `services/ai/tests`. Hesap başına
  hata sınırının kilidi kaldırılınca paralel deneme testinin kaldığı yerelde doğrulandı.

  | No | Kontrol | Düzeltme | Durum |
  |---|---|---|---|
  | S01 | BUS-02, ARC-05 | Kalıcı push teslim kuyruğu: gönderim işlem dışında, süreli iş alma, geçici hatada yeniden deneme, kalıcı hatada log, olay başına `collapse_key` | Geçti (yerel) |
  | S02 | SES-04, SES-05 | `session_families`: yenileme ve iptal aile satırını kilitler; kimlik bilgisi sürümü; sıfırlama ve faktör değişimi bekleyen ikinci adım biletlerini geçersiz kılar | Geçti (yerel) |
  | S03 | AUT-03 | Numara değişimi eski numaranın sıfırlama kodlarını iptal eder; sıfırlama güncel numarayı satır kilidiyle ister | Geçti (yerel) |
  | S04 | AI-03 | Çağrı öncesi atomik rezervasyon (`ai_reserve`), `may_be_billed`, açık rezervasyon tahminle sayılır, çağrı ayrı görevde, SDK yeniden denemesi kapalı | Geçti (yerel) |
  | S05 | SES-04 | Tek oturum kuralı (`session_active`): HTTP, WebSocket, push, oturum listesi, dışa aktarma | Geçti (yerel) |
  | S06 | AUT-01, DAT-02 | Personelin dışa aktarması ikinci adım ister; `/v1/me` yalnızca üyelik özeti (belgelendi) | Geçti (yerel) |
  | S07 | AUT-02, RES-01 | Hata sınırı aynı işlemde kilitli; ikinci adımda havuzdan ikinci bağlantı istenmez | Geçti (yerel) |
  | S08 | AZ-05 | Her ikili kendi rolünü doğrular (API uygulama rolü, CLI yönetim rolü) | Geçti (yerel); veritabanında zorunlu yönetim denetim kaydı kaldı |
  | S09 | AZ-03, DAT-05 | Devralan etkin olmalı; devir, davet kabulü ve silme talebi hesap satırı kilidiyle sıralanır | Geçti (yerel) |
  | S10 | AZ-04, BUS-02 | Paylaşılan zonda bypass her bölümde yetki ister; alarm her bölüme ayrı olay | Geçti (yerel) |
  | S11 | BUS-01, ARC-05 | Takılan sanal komut açılışta ve dakikada bir tamamlanır | Geçti (yerel) |
  | S12 | AUT-03 | Hesaba bağlı parola kuralı kod doğrulandıktan sonra; kurala takılan istek kodu tüketmez | Geçti (yerel) |
  | S13 | DAT-05 | Silme talebi süresi dolunca geri alınamaz, giriş reddedilir | Geçti (yerel) |
  | S14 | AZ-02, AZ-05 | Bütün ayrıcalıklı yordamlarda `pg_temp` en sonda, PUBLIC'e kapalı; katalog testi | Geçti (yerel) |
  | S15 | AZ-04, AI-02 | Paylaşılan zonun görünmeyen bölüm kimliği yanıttan çıkar; zon olayı bölüme bağlı, bağlantı olayı panel düzeyinde (kısıt); AI bağlantı sorgusu bölümsüz olaylarla sınırlı | Geçti (yerel) |
  | S16 | NET-01 | Ayrıştırılmış etkin TLS modu denetlenir, yalnızca `verify-full` | Geçti (yerel) |
  | S17 | RES-01, ARC-04 | AI servisinde gövde okunmadan kimlik doğrulama, 1 MiB sınır, doğrulama hatasında içerik yansıtılmaz | Geçti (yerel) |
  | S18 | AI-01, AI-02 | Kesin sayılar ve güncel bağlantı durumu API'den modele gider; liste ve sayılar tek sorguda | Geçti (yerel) |
  | S19 | AZ-05, BUS-01 | Üyelik ve yetki satırları işlem boyunca paylaşımlı kilitli; karar anı `clock_timestamp()`, saniye yuvarlaması güvenli yöne | Geçti (yerel) |
  | S20 | OPS-04 | CI aksiyonları commit SHA'sına, PostgreSQL imajları özete, Rust ve uv kesin sürüme sabitlendi | Geçti (CI, `ab6fa85`) |
- **Doğrulama denetimi (27 Kasım 2026, commit `ab6fa85` üzerinde, Codex):** ilk 20 bulgunun 10'u
  kapanmış, 10'u kısmen kapanmış bulundu; kalan kısımlar ve 11 yeni bulgu (Y01–Y11) kodda
  doğrulandı ve düzeltildi. Aynı sürümün genel incelemesindeki komut tekrarı bulgusu da eklendi.
  Regresyon testleri: `audit_fixes.rs` (doğrulama bölümü), `ai.rs`, `hardening.rs`,
  `commands.rs` birim testi, `tests/sql/015_verification_fixes.sql`, `services/ai/tests`.
  Gönderim anındaki alıcı denetimi kaldırılınca kuyruk testinin kaldığı yerelde doğrulandı.
  Migration 0017'nin eski veri düzeltmeleri (karma oturum ailesi, bölümsüz zon olayı, bölümlü
  bağlantı olayı, bölümü belirlenemeyen olayda durma) yerelde 0016 sonrası eski veriyle denendi.

  | No | Kontrol | Düzeltme | Durum |
  |---|---|---|---|
  | Y01 | AZ-04, SES-04 | Alıcı kuralı tek yerde (`push_recipient_eligible`); gönderimden hemen önce yeniden uygulanır, uygun olmayan iş iptal edilir | Geçti (yerel) |
  | Y02 | AZ-04, BUS-02 | Eski olaylar düzeltilip kısıtlar doğrulandı (bölümü belirlenemeyen olayda göç durur); tarama her kaydı ayrı ele alır | Geçti (yerel) |
  | Y03 | BUS-02 | Deneme hakkı biten iş alınmaz; yaş olaydan ölçülür; her taramada bitmesi gereken işler kapanır; geç dağıtılan eski olay için iş yazılmaz; gönderim 20 sn ile sınırlı; token yalnızca işin sahibi olan deneme silebilir | Geçti (yerel) |
  | Y04 | SES-04, AUT-01 | Karma eski aileler kapandı; yönetim aracı hesabı kapatınca sürüm artar ve biletler tükenir; sürüm faktörden önce denetlenir | Geçti (yerel) |
  | Y05 | BUS-02, AZ-05 | Ortak kilit sırası (bkz. mimari), kullanıcı satırı `FOR NO KEY UPDATE`, sanal panel bölüm → komut, numara değişimi kod → kullanıcı, sahiplik devrinde parola işlem dışında; 40P01/40001 → 409 `concurrent_update` | Geçti (yerel); eşzamanlı kilitlenme yükle sınanmadı |
  | Y06 | AUT-01, DAT-05 | Dışa aktarmada personel denetimi verinin okunduğu işlemde, üyelikler paylaşımlı kilitli; silme iptali `clock_timestamp()` | Geçti (yerel) |
  | Y07 | AZ-04 | Paylaşılan zonda bütün bölümler yetki kayıtları kilitlendikten sonra tek karar anıyla değerlendirilir | Geçti (yerel); sınırdaki eşzamanlı durum sınanmadı |
  | Y08 | AZ-02, AZ-05 | Üretimde giriş rolü (`session_user`) de denetlenir: süper kullanıcı, BYPASSRLS, tablo sahibine geçebilen rol, API'de yönetim rolüne geçebilen rol reddedilir | Geçti (yerel) |
  | Y09 | AI-03 | Boş dönem modelsiz ve rezervasyonsuz; bütçe reddinde sıklık kaydı kalır | Geçti (yerel) |
  | Y10 | AI-03 | Uygulama deftere doğrudan yazamaz (`ai_settle`); sert üst sınırlar; eksik/negatif kullanım tahminle kapanır; commit ve çağrı aynı görevde; sağlayıcının 5xx'i (529 hariç) faturalanmış olabilir sayılır | Geçti (yerel) |
  | Y11 | AI-02 | Son bağlantı durumu sayılarla aynı sorguda | Geçti (yerel) |
  | K01 | BUS-01 | Reddedilen komutun tekrarı ilk yanıtla aynı 409 ve kodu döner | Geçti (yerel) |
- **Bilinen eksikler:**
  - PWD-03: yalnızca yerel yaygın parola listesi var; büyük sızıntı listesiyle (gizlilik
    korumalı) kontrol eklenecek.
  - AUT-02: kademeli doğrulama (ör. CAPTCHA) yok; yalnızca pencere bazlı sınır var.
  - KEY-03: JWT anahtarı tek; planlı rotasyon için `kid` ile anahtar kümesi eklenecek.
  - NET-03: ters vekil arkasında gerçek IP için güvenilir vekil listesi yok; dağıtımdan önce
    çözülmeli (aksi halde bütün IP sayaçları tek vekil adresinde birleşir).
  - AUT-02 (denetim, düşük): hesap başına sayaçlar başkası tarafından tüketilebilir; kurbanın
    girişi veya sıfırlama kodu pencere boyunca engellenebilir. Kalıcı kilit olmadığı için bilerek
    kabul edildi; kademeli doğrulama (CAPTCHA) ile hafifletilecek.
  - RES-01 (denetim, düşük): WebSocket'te kullanıcı başına bağlantı sınırı yok; her olayda her
    bağlantı için veritabanı işlemi açılıyor. Bağlantı sınırı ve olay başına toplu yetki
    hesaplaması eklenecek.
  - ARC-04 (denetim, düşük): kimlik tabloları RLS dışında olduğundan ele geçirilmiş API
    organizasyon kimliklerini okuyabilir; `shedu-admin`'de işlemi yapanın adı doğrulanmaz
    (sunucu hesabına güvenilir).
  - AZ-01: izleme merkezinin müşteri organizasyonlarına erişimi (organizasyonlar arası operatör)
    yok; izleme merkezi modeli netleşince ayrı politika olarak tasarlanacak.
  - AUT-01/PKY: passkey (oltalamaya dayanıklı faktör) yok; yalnızca TOTP. Shedu'nun kendi
    platform yöneticileri (admin paneli) henüz tanımlı değil; tanımlanınca aynı oturum kuralı
    zorunlu olacak.
  - KEY-04: veri anahtarı tek sürüm; anahtar değişiminde eski kayıtları yeniden şifreleyen araç
    yok (bilinmeyen sürüm güvenli tarafta reddedilir).
  - AUT-04: kullanıcı hem doğrulayıcıyı hem kurtarma kodlarını kaybederse destek eliyle kurtarma
    akışı yok; yazılırken ayrı yetki, denetim kaydı ve kullanıcı bildirimiyle yapılacak.
  - OPS-02: `shedu-admin`'in çalışacağı sunucuya erişim (SSH anahtarı, ayrı servis kullanıcısı,
    yönetim ağı) ve yönetici giriş rolünün parolası dağıtım kurulurken tanımlanacak. İşlemi
    yapan kişinin adı sunucudaki kullanıcı adından gelir; kişi başına ayrı sunucu hesabı
    gerekir.
  - DAT-05: yedekler henüz yok; yedekten geri dönüşte silinmiş hesapların yeniden canlanmaması
    için silme kayıtlarının (denetim kaydındaki `privacy.account_erased`) yeniden uygulanması
    yedekleme kurulurken tanımlanacak.
  - DAT-01: saklama süreleri (komut, olay, denetim kaydı, bildirim teslimi, rıza kayıtları) ve
    süresi dolan verinin otomatik silinmesi yok; süreler hukuki kararla belirlenecek (açık
    sorular).
  - Rıza amaçları ve metin sürümleri taslaktır (`taslak-1`); aydınlatma metni ve rıza metinleri
    onaylanınca migration'la güncellenecek. Ticari ileti onayı için İYS (İleti Yönetim Sistemi)
    entegrasyonu yok.
  - AI-03: rezervasyon tahmini giriş token'ını istek baytının yarısıyla sayar; bu tokenleştirme
    için kesin bir üst sınır değil, temkinli bir tahmindir (gerçek kullanımın birkaç katı). Gerçek
    harcama her zaman sağlayıcının bildirdiği kullanımla yazılır; tahmin yalnızca sonucu bilinmeyen
    çağrıda ve rezervasyon sırasında kullanılır. Tahmin AI servisinin `max_tokens` ve en pahalı
    fiyat değerine dayanır; bunlar iki yerde tutulur (`ai.rs`, `pricing.py`). Fiyat tablosu elle
    güncellenir. Sonucu bilinmeyen iki büyük çağrı (500 olay) kullanıcının günlük bütçesini
    doldurabilir (temkinli taraf).
  - AZ-05, LOG-01 (ikinci denetim, S08): yönetim rolü bayrak ve sürüm tablolarına doğrudan
    yazabilir; gerekçe ve denetim kaydı yönetim aracında aynı işlemde yazılır ama veritabanında
    zorunlu değildir. Yönetim yazıları gerekçe isteyen ayrıcalıklı yordamlara taşınacak.
  - BUS-02 (ikinci denetim): push teslimi en az bir kezdir; sağlayıcı kabulü ile sonucun yazılması
    arasındaki kesintide bildirim ikinci kez gidebilir. Sağlayıcı bağdaştırıcısı `collapse_key`'i
    kullanmalı; çekirdek gönderimi 20 saniyeyle sınırlar (iş süresi 30 sn). Bağdaştırıcılar henüz
    yazılmadı.
  - AZ-04, SES-04 (doğrulama denetimi, Y01): alıcı gönderimden hemen önce denetlenir; denetim ile
    sağlayıcı çağrısı arasındaki kısa pencerede (saniyeler) düşen yetki o bildirimi durdurmaz.
  - AZ-04 (doğrulama denetimi, Y02): veritabanı, olayın bölümünün gerçekten o zona bağlı olduğunu
    zorlamıyor; olayı yazan üreticiler (sanal panel, ileride gateway) bunu sağlar. Gateway
    yazılırken aynı kural testle eklenecek.
  - AI-03 (doğrulama denetimi, Y10): harcama AI servisinin bildirdiği kullanıma dayanır (iç servis
    güvenilir sayılır; eksik veya geçersiz alan tahmine dönüşür). Görev paniği veya süreç kesintisi
    halinde rezervasyon kapanmaz ve 24 saat tahminiyle sayılır (temkinli taraf).
  - RES-01, BUS-02 (doğrulama denetimi, Y05): kilit sırası kodda tek düzene getirildi, ama
    eşzamanlı yük altında kilit bekleme, MultiXact büyümesi ve havuz doygunluğu ölçülmedi;
    WebSocket ve bildirim merkezi okumaları da paylaşımlı kilit alır. Pilot öncesi yük testiyle
    ölçülecek.
  - AZ-05 (ikinci denetim, S19): üyelik ve yetki satırlarının paylaşımlı kilidi okuma isteklerinde
    de alınır (satır başlığına yazar); yük artınca yalnızca yazan isteklere daraltılabilir.
  - Belge ve kod (ikinci denetim): bildirim merkezinde toplu "okundu" sınırı, sonradan görünür
    olan bölümün eski olaylarını da okunmuş sayar; sürüm politikasında `minimum <= latest` yalnızca
    yönetim aracında denetlenir, SQL kısıtı yok; kalıcı silmeden sonra güvenlik kayıtlarında kişi
    kimliği takma ad olarak kalır (serbest metinli yönetim gerekçelerine kişisel veri yazılmamalı).
  - OPS-04 (ikinci denetim): `infra/docker-compose.yml`'deki geliştirme imajı, `runs-on:
    ubuntu-latest` ve Python yama sürümü sabit değil; servis imajı özetleri ve Rust/uv sürümleri
    Dependabot'la değil elle güncellenir.
  - AI-02: istemciler (web, mobil) henüz yok; özet metninin düz metin olarak basılması ve "yapay
    zekâ ile üretildi" etiketi istemci yazılırken test edilecek.
  - KVKK: `ai_event_summary` bayrağı, yurt dışına aktarım ve rıza kararı (açık sorular 5, 11,
    12) verilene kadar açılmayacak. Model sağlayıcısıyla veri saklama koşulları da bu kararla
    birlikte ele alınacak.
  - DAT-01: silinen kullanıcının eski numarasını içeren SMS sağlayıcısı kayıtları ve push
    sağlayıcısındaki cihaz kayıtları Shedu'nun dışındadır; sağlayıcılar bağlanırken
    sözleşmeyle ele alınacak.

## Değişmez kurallar

- İstemciden gelen IP, organizasyon, rol, fiyat, durum veya Host değerine yetki kararında güvenilmez.
- Test yalnızca izinli ortamda yapılır; gerçek müşteri verisi kullanılmaz.
- Kanıtlarda token, IP, e-posta, oturum kimliği ve sırlar maskelenir; kanıt depoya commit'lenmez.
- Yetki veya kimlik akışını değiştiren her değişiklik en az bir olumlu ve bir olumsuz test içerir.
