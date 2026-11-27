# Güvenlik Politikası

Shedu bir güvenlik ürünüdür; bulunan her açığı ciddiye alırız.

## Açık bildirme

- **Herkese açık issue, pull request veya tartışma açmayın.**
- GitHub'daki **Security → Report a vulnerability** düğmesiyle özel bildirim gönderin.
- Bildirimde şunlar olsun: etkilenen bileşen ve sürüm, yeniden üretme adımları, olası etki.
- Kanıtlarda token, parola, IP adresi, e-posta ve kişisel veriyi maskeleyin.

İlk yanıtı 3 iş günü içinde vermeyi hedefliyoruz.

## Kapsam

Bu depodaki kod: `apps/`, `services/`, `infra/`.

Kapsam dışı: üçüncü taraf hizmetler, sosyal mühendislik, hizmet engelleme (DoS) denemeleri ve gerçek
müşteri sistemlerine yönelik testler. Testleri yalnızca kendi yerel ortamınızda yapın.

## Desteklenen sürümler

Henüz yayınlanmış bir sürüm yoktur; yalnızca `main` dalı desteklenir.
