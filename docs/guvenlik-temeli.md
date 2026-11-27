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
| API | API-02 | Alan düzeyinde yazma izni; istemci izinsiz alan gönderemez | Doğrulanacak |
| API | API-04 | WebSocket'te kimlik, origin ve mesaj başına yetki | Doğrulanacak |
| İş mantığı | BUS-01, BUS-02 | Komut durum makinesi (`domain` crate'i), idempotency, atomik geçiş | Doğrulanacak |
| Ağ | NET-01 | Her bağlantıda TLS; panel bağlantıları dahil | Doğrulanacak |
| Sırlar | KEY-02 | Sır yönetimi; istemci uygulamasında ve depoda sır yok | Doğrulanacak |
| Log | LOG-01, LOG-02 | Yapılandırılmış güvenlik olayı; log'da PIN, token, telefon yok | Doğrulanacak |
| AI | AI-01, AI-02, AI-03 | Araçlar yalnızca okuma; kiracı izolasyonu; maliyet bütçesi | Doğrulanacak |
| Üretim | OPS-01 | Güvenli üretim profili; debug ve sunucu seçici yok; varsayılan dinleme adresi `127.0.0.1` | Doğrulanacak |
| Build | OPS-04 | CODEOWNERS, korumalı `main`, Dependabot, en az yetkili CI | Doğrulanacak |
| Hata | ARC-05, EXC-01 | Arıza halinde güvenli davranış: belirsizse komut reddedilir | Doğrulanacak |

### Kanıt notları

- **AZ-02, AZ-04, BUS-02, LOG-03 (şema düzeyi):** `services/backend/tests/sql/001_tenancy_and_integrity.sql`
  bağlamsız erişimin boş döndüğünü, kiracılar arası okuma, yazma ve bağlantının engellendiğini,
  bölüm başına tek yoldaki komutu ve denetim kaydının değiştirilemezliğini test eder. Testlerin
  bozulunca kaldığı (RLS kapatma, yanlış beklenti) yerelde doğrulandı. API katmanı henüz bu
  bağlamı kullanmadığı için durumlar "Doğrulanacak" kalır.
- **KEY-02:** CI'da gitleaks ile her push'ta sır taraması yapılır.
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
- **Bilinen eksikler:**
  - PWD-03: yalnızca yerel yaygın parola listesi var; büyük sızıntı listesiyle (gizlilik
    korumalı) kontrol eklenecek.
  - AUT-02: kademeli doğrulama (ör. CAPTCHA) yok; yalnızca pencere bazlı sınır var.
  - SES-03: mutlak oturum ömrü (refresh ailesi için üst süre) yok.
  - KEY-03: JWT anahtarı tek; planlı rotasyon için `kid` ile anahtar kümesi eklenecek.
  - NET-03: ters vekil arkasında gerçek IP için güvenilir vekil listesi yok.
  - AZ-05: sahip hesabı silinirse (KVKK silme akışı) organizasyon sahipsiz kalabilir; silme akışı
    yazılırken önce sahipliğin devri veya organizasyonun kapatılması istenecek.
  - AZ-01: izleme merkezinin müşteri organizasyonlarına erişimi (organizasyonlar arası operatör)
    yok; izleme merkezi modeli netleşince ayrı politika olarak tasarlanacak.
  - AUT-01/PKY: passkey (oltalamaya dayanıklı faktör) yok; yalnızca TOTP. Shedu'nun kendi
    platform yöneticileri (admin paneli) henüz tanımlı değil; tanımlanınca aynı oturum kuralı
    zorunlu olacak.
  - KEY-04: veri anahtarı tek sürüm; anahtar değişiminde eski kayıtları yeniden şifreleyen araç
    yok (bilinmeyen sürüm güvenli tarafta reddedilir).
  - AUT-04: kullanıcı hem doğrulayıcıyı hem kurtarma kodlarını kaybederse destek eliyle kurtarma
    akışı yok; yazılırken ayrı yetki, denetim kaydı ve kullanıcı bildirimiyle yapılacak.

## Değişmez kurallar

- İstemciden gelen IP, organizasyon, rol, fiyat, durum veya Host değerine yetki kararında güvenilmez.
- Test yalnızca izinli ortamda yapılır; gerçek müşteri verisi kullanılmaz.
- Kanıtlarda token, IP, e-posta, oturum kimliği ve sırlar maskelenir; kanıt depoya commit'lenmez.
- Yetki veya kimlik akışını değiştiren her değişiklik en az bir olumlu ve bir olumsuz test içerir.
