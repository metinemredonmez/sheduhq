# Özellik havuzu

Ürüne özgü olmayan, her uygulamada gereken genel özellikler. Hangi faza girdiği [mvp.md](mvp.md)
dosyasındadır. Kontrol kimlikleri için [guvenlik-temeli.md](guvenlik-temeli.md).

## Kimlik ve oturum

| Özellik | Katman | Faz | Not / kontrol |
|---|---|---|---|
| E-posta veya telefon + parola, SMS koduyla kayıt ve parola sıfırlama | backend, mobil, web | MVP | Sıfırlama, hesabın kayıtlı olup olmadığını belli etmez (AUT-03) |
| Personel ve admin için MFA: TOTP + tek kullanımlık yedek kodlar | backend, admin | MVP | AUT-01, AUT-04 |
| Hesap ve IP bazlı kilitleme, dağıtık deneme tespiti | backend | MVP | AUT-02, RES-01 |
| Refresh token ailesi, yeniden kullanımda bütün ailenin iptali | backend | MVP | SES-05; şemada `refresh_tokens` |
| Admin ve web için BFF: token tarayıcıda değil, HttpOnly çerezde; CSRF koruması | admin, web | MVP | SES-01, WEB-05; `localStorage`'da token tutulmaz |
| Bağlı cihazlar ve açık oturumlar listesi, uzaktan kapatma, giriş geçmişi | backend, mobil, admin | MVP | SES-04 |
| Apple ve Google ile giriş | backend, mobil, web | Faz 2 | TOK-03, TOK-05 |
| Cihaz biyometrisi (Face ID / parmak izi) ile kapatma onayı | mobil | MVP | Biyometrik veri sunucuya gönderilmez |

## Yetki, denetim, operasyon

| Özellik | Katman | Faz | Not / kontrol |
|---|---|---|---|
| Roller ve gün/saat bazlı yetki | backend, admin | MVP | AZ-01; şemada `access_grants`, `access_windows` |
| Gerekçeli işlem: alarm kapatma, yetki değiştirme gibi işlemlerde gerekçe zorunlu | backend, admin | MVP | Gerekçe denetim kaydına yazılır (LOG-01) |
| Denetim kaydı ekranı | admin | MVP | Kayıt yalnızca eklenir (LOG-03) |
| Uyarı merkezi: tekrarları birleştirir, eşik ve kanal seçer, sorun bitince kendiliğinden kapanır | backend, admin | MVP | Operatör kuyruğunun temeli |
| Özellik bayrakları ve uzaktan ayarlar | backend, admin | MVP | Bayrak okunamazsa özellik kapalı kabul edilir (EXC-01) |
| Hata izleme, kişisel veri maskelemeyle | tümü | MVP | LOG-02 |
| İmzalı adresle dosya yükleme, saklama süresi dolunca otomatik silme | backend, mobil | MVP | Kamera görüntüleri; DAT-05 |
| Dış adres kalkanı: kamera akışı, webhook gibi kullanıcının verdiği adreslere istek | backend | MVP | SSRF; EXT-01, EXT-02, EXT-04 |
| Hassas alanların uygulama düzeyinde şifrelenmesi | backend | Faz 2 | KEY-04 |
| Zamanlanmış iş takibi, altyapı izleme, gecelik yedek ve geri yükleme provası | backend, admin | Faz 2 | DAT-05, LOG-05 |

## Bildirimler

| Özellik | Katman | Faz | Not / kontrol |
|---|---|---|---|
| Push, bildirim merkezi, bildirime dokununca doğru ekran | backend, mobil | MVP | |
| Tür bazlı bildirim tercihleri | backend, mobil | MVP | **Alarm türleri tercihle kapatılamaz**; kritik kanal ayrıdır |
| Toplu duyuru (bakım vb.) ve ticari ileti izni | admin | Faz 2 | Ticari ileti yalnızca açık izinle |

## Uygulama deneyimi

| Özellik | Katman | Faz | Not / kontrol |
|---|---|---|---|
| Zorunlu güncelleme kontrolü | backend, mobil | MVP | |
| Sunucunun yönettiği onboarding: panel eşleştirme (QR), adres, acil durum kişisi | backend, mobil | MVP | |
| İzin yardımcısı: bildirim, kamera, kritik uyarı izinleri | mobil | MVP | |
| TR / EN | tümü | MVP | |
| Tek tasarım sistemi: renk token'ları, erişilebilir kontrast | admin, web, mobil | Faz 2 | WCAG kontrast kontrolü |

## KVKK ve mağaza

| Özellik | Katman | Faz | Not / kontrol |
|---|---|---|---|
| Aydınlatma metni, çerez bandı, rıza defteri | tümü | MVP | Rıza ve geri çekilmesi kayıt altında |
| İlgili kişi başvurusu, veri dışa aktarma | backend, admin, web | MVP | DAT-02 |
| Hesap silme: 30 gün geri alınabilir, sonra kalıcı | backend, mobil | MVP | App Store şartı; DAT-05 |
| Mağaza inceleme hesabı ve demo veri (sanal panel) | backend | MVP | İncelemecinin gerçek paneli yoktur; demo panel gerçek bir panele bağlanamaz |

## Destek, rapor, gelir

| Özellik | Katman | Faz | Not / kontrol |
|---|---|---|---|
| Uygulama içi destek talebi, admin'den yanıt | backend, admin, mobil | Faz 2 | |
| Sayfalı tablo ve CSV dışa aktarma, grafikler, PDF rapor | admin, web, mobil | Faz 2 | Dışa aktarmada kiracı filtresi (AZ-03) |
| Abonelik kataloğu ve ödeme defteri | backend, admin, mobil | Faz 2 | Mağaza içi satın alma gerekip gerekmediği doğrulanacak |

## AI

| Özellik | Katman | Faz | Not / kontrol |
|---|---|---|---|
| Sağlayıcı yedek zinciri, maliyet defteri ve bütçe freni, sürümlü istemler | AI | Faz 2 | AI-03 |
| Olay özeti, akıllı bildirim | AI, backend | Faz 2 | Alarm yolu AI'ya bağlı değildir |
| Destek asistanı: bilgi tabanı araması, akışlı sohbet, AI yanıtını bildirme | AI, mobil, web | Faz 3 | Dış içerik talimat sayılmaz (AI-01); kiracı izolasyonu (AI-02) |

## Bilerek alınmayanlar

- Sunucuda yüz vektörü tutan yüzle giriş: biyometrik veri riski; yerine cihaz biyometrisi.
- Davet et-kazan, sadakat programı, topluluk akışı gibi güvenlik ürünüyle ilgisi olmayan özellikler.
