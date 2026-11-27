# MVP kapsamı

MVP'nin amacı: **"Alarmımı telefondan güvenle kurup kapatıyorum ve alarm çaldığında anında haberim oluyor."**

## Faz 1 — MVP

**Mobil (iOS + Android)**
- Giriş, SMS koduyla kayıt ve parola sıfırlama, çıkış, hesap silme.
- Panel ve bölüm listesi, canlı durum.
- Kur / evde / gece / kapat; PIN ve isteğe bağlı biyometri; sonucun anında gösterilmesi.
- Zon listesi ve zonu devre dışı bırakma (bypass).
- Alarm push bildirimleri (kritik öncelik, alarm sesleri) ve bildirim geçmişi.
- Olay geçmişi (tarih filtresi).
- Panik butonları: polis, ambulans, itfaiye (basılı tutma ve onay ile).
- Dil (TR/EN), profil, zorunlu güncelleme kontrolü.

**Backend**
- Kimlik doğrulama: kısa ömürlü access token, her kullanımda yenilenen refresh token.
- Kullanıcı → organizasyon → panel → bölüm yetki modeli.
- Komut API'si: durum makinesi ve idempotency.
- Panel gateway, olay kaydı, push servisi, SMS sağlayıcısı, denetim kaydı.

**Yönetim**
- Pilot için: müşteriye panel atama ve kullanıcı açma işleri korumalı bir yönetici CLI'ı ile.

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
