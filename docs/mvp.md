# MVP kapsamı

MVP'nin amacı: **"Alarmımı telefondan güvenle kurup kapatıyorum ve alarm çaldığında anında haberim oluyor."**

Geliştirme sırası: **backend → AI servisi → admin → web → mobil.** Genel özelliklerin tam listesi:
[ozellik-havuzu.md](ozellik-havuzu.md).

## Faz 1 — MVP

**Backend**
- Kimlik doğrulama: kısa ömürlü access token, her kullanımda yenilenen refresh token ailesi.
- Personel ve admin için MFA (TOTP + yedek kodlar); hesap ve IP bazlı kilitleme.
- Kullanıcı → organizasyon → panel → bölüm yetki modeli, gün ve saat bazlı pencereler.
- Komut API'si: durum makinesi ve idempotency.
- Panel gateway, olay kaydı, push servisi, SMS sağlayıcısı, denetim kaydı.
- Uyarı merkezi, özellik bayrakları, hata izleme (kişisel veri maskelenerek).
- Dış adres kalkanı (kamera akışı, webhook): SSRF'e karşı.
- KVKK: rıza defteri, veri dışa aktarma, 30 gün geri alınabilir hesap silme.
- Mağaza inceleme hesabı için sanal demo panel.

**Yönetim**
- Pilot için: müşteriye panel atama ve kullanıcı açma işleri korumalı bir yönetici CLI'ı ile.
- Ardından admin paneli (Next.js): BFF ile HttpOnly çerez, MFA, gerekçeli işlem, denetim kaydı ekranı.

**Mobil (iOS + Android)**
- Giriş, SMS koduyla kayıt ve parola sıfırlama, çıkış, hesap silme.
- Onboarding: panel eşleştirme (QR), adres, acil durum kişisi; izin yardımcısı.
- Panel ve bölüm listesi, canlı durum.
- Kur / evde / gece / kapat; PIN ve isteğe bağlı biyometri; sonucun anında gösterilmesi.
- Zon listesi ve zonu devre dışı bırakma (bypass).
- Alarm push bildirimleri (kritik öncelik, alarm sesleri), bildirim merkezi ve tür bazlı tercihler
  (alarm türleri kapatılamaz).
- Olay geçmişi (tarih filtresi).
- Panik butonları: polis, ambulans, itfaiye (basılı tutma ve onay ile).
- Bağlı cihazlar ve oturumlar; uzaktan oturum kapatma.
- Dil (TR/EN), profil, zorunlu güncelleme kontrolü.

## Faz 2

- Kameralar: liste, QR ile ekleme, canlı izleme.
- Alt kullanıcı davet etme, roller, gün ve saat bazlı yetki.
- Acil durum kişi listesi, bildirim ayarları, sensör ve çıkış adlarını düzenleme.
- Google ve Apple ile giriş, bağlı cihazlar.
- AI: olay özeti, akıllı bildirim, destek asistanı.
- Admin web paneli (Next.js).

## Faz 3

- Fatura ve cari hesap, online ödeme.
- Teknik destek ve müşteri hizmetleri talepleri.
- Kampanyalar ve içerik yönetimi.
- İzleme merkezi operatör konsolu: AI özeti, güven skoru, kamera karesi ve önerilen adımla gelen alarm.
- Kurumsal çok şubeli rapor ve anormallik tespiti.

## MVP'de bilerek olmayanlar

- Yüz tanıma (biyometrik veri; KVKK açısından özel nitelikli kişisel veri).
- AI'nın tek başına karar verdiği herhangi bir akış.
- Sosyal giriş (iOS'ta Apple ile giriş zorunluluğunu da beraberinde getirir).
