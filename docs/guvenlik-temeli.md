# Güvenlik temeli

Shedu'da güvenlik sonradan eklenmez; giriş, oturum, yetki, API, dosya yükleme ve güvenlik başlıkları ilk
kurulumda aşağıdaki kontrollere göre yapılır. Kontrol kimlikleri, OWASP ASVS 5.0.0 ile eşlenmiş iç
güvenlik kataloğumuzdan gelir. Önce P0'lar karşılanır.

Durum dili: **Doğrulanacak / Geçti / Kaldı / Uygulanmaz / Risk kabul edildi / Engellendi.** Kanıtsız
"Geçti" yazılmaz.

| Alan | Kontrol | Shedu'da nasıl | Durum |
|---|---|---|---|
| Kimlik | AUT-01 | Admin panelinde MFA zorunlu | Doğrulanacak |
| Kimlik | AUT-02, RES-01 | Giriş ve SMS kodu uç noktalarında çok boyutlu hız sınırı ve kota | Doğrulanacak |
| Kimlik | AUT-03 | Sıfırlama ve davet kodları tek kullanımlık, kısa ömürlü | Doğrulanacak |
| Parola | PWD-01, PWD-03, PWD-04 | Minimum uzunluk, sızmış parola kontrolü, argon2id | Doğrulanacak |
| Oturum | SES-01, SES-02 | Tek oturum taşıma biçimi; girişte ve yetki değişiminde yenileme | Doğrulanacak |
| Oturum | SES-04, SES-05 | Çıkışta, cihaz silmede ve rol düşürmede iptal; refresh token ailesi | Doğrulanacak |
| Token | TOK-01, TOK-02 | JWT'de algoritma listesi sabit; `exp`, `aud`, `iss` zorunlu; anahtar güvenilir kaynaktan | Doğrulanacak |
| Yetki | AZ-01, AZ-02, AZ-04 | Her komutta izin + kapsam + nesne + durum birlikte; veri katmanında ikinci bariyer | Doğrulanacak |
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

## Değişmez kurallar

- İstemciden gelen IP, organizasyon, rol, fiyat, durum veya Host değerine yetki kararında güvenilmez.
- Test yalnızca izinli ortamda yapılır; gerçek müşteri verisi kullanılmaz.
- Kanıtlarda token, IP, e-posta, oturum kimliği ve sırlar maskelenir; kanıt depoya commit'lenmez.
- Yetki veya kimlik akışını değiştiren her değişiklik en az bir olumlu ve bir olumsuz test içerir.
