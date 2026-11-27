"""Shedu AI servisi.

Kurallar (bkz. docs/mimari.md):
- Bu servis kullanıcıya açık değildir; yalnızca iç ağdan, servis kimliğiyle API çağırır (ARC-04).
- Veritabanına erişmez; API yalnızca o isteğe ait, azaltılmış ve tek kiracılı veriyi
  gönderir (AI-02).
- Araçları yalnızca okuma yapar; alarmı kuramaz, kapatamaz, kimseyi çağıramaz (AI-01).
- Kullanıcı ve organizasyon başına maliyet bütçesi uygulanır (AI-03).
- PIN, token veya telefon numarası prompt'a girmez (LOG-02).

AI özellikleri Faz 2'dedir; şimdilik yalnızca sağlık kontrolü vardır.
"""

from fastapi import FastAPI

app = FastAPI(
    title="Shedu AI",
    version="0.1.0",
    # İç servis: herkese açık dokümantasyon sayfası yayınlanmaz.
    docs_url=None,
    redoc_url=None,
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
