# Shedu

> AI-assisted remote security platform for homes and businesses.

**Shedu**, evler ve kurumlar için uzaktan alarm izleme ve yönetim platformudur. Adını Asur'da evlerin,
sarayların ve şehirlerin kapılarını koruyan ruhtan alır.

- **Ev kullanıcısı:** alarmı kurar ve kapatır, anında bildirim alır, kamerayı izler, panik butonunu kullanır.
- **Kurumsal müşteri:** bütün şubeleri tek ekranda görür, personele gün ve saat bazlı yetki verir.
- **İzleme merkezi operatörü:** gelen alarmı AI'nın hazırladığı özet ve kamera karesiyle görür; karar her zaman operatördedir.

> Durum: **iskelet aşaması.** Henüz kullanıma hazır bir sürüm yok.
>
> Geliştirme sırası: **backend → AI servisi → admin → web → mobil.**

## Yapı

```
apps/
  mobile/      Expo (React Native, TypeScript) — iOS ve Android
  web/         Next.js — müşteri web sitesi (planlandı)
  admin/       Next.js — yönetim paneli (planlandı)
services/
  backend/     Rust (Cargo workspace): api, gateway, domain
  ai/          Python (FastAPI) — yalnızca iç ağdan erişilen AI servisi
infra/         Yerel geliştirme için docker-compose (PostgreSQL, Redis, MQTT)
docs/          Mimari, MVP kapsamı, güvenlik temeli, karar kayıtları
```

## Hızlı başlangıç

| Bileşen | Gerekenler | Komut |
|---|---|---|
| Backend | Rust (stable) | `cd services/backend && cargo test && cargo run -p shedu-api` |
| Veritabanı şeması | PostgreSQL 19 (CI: 19 ve 18; geçici, süper kullanıcı) | `PGHOST=… PGDATABASE=… services/backend/scripts/test-db.sh` |
| AI servisi | [uv](https://docs.astral.sh/uv/) | `cd services/ai && uv sync && uv run pytest` |
| Altyapı | Docker | `cd infra && cp .env.example .env && docker compose up -d` |

API varsayılan olarak yalnızca `127.0.0.1:8080` adresini dinler; sağlık kontrolü: `GET /health`.

## Dokümanlar

- [Mimari](docs/mimari.md)
- [MVP kapsamı](docs/mvp.md)
- [Özellik havuzu](docs/ozellik-havuzu.md)
- [Güvenlik temeli](docs/guvenlik-temeli.md)
- [Karar kayıtları](docs/kararlar/)
- [Açık sorular](docs/acik-sorular.md)

## Güvenlik

Bir güvenlik açığı bulduysanız lütfen herkese açık issue açmayın; [SECURITY.md](SECURITY.md) dosyasındaki
yolu izleyin.

## Lisans

Tüm hakları saklıdır. Bu depo açık kaynak lisansıyla dağıtılmamaktadır.
