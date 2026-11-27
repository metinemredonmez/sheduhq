# infra

Yalnızca yerel geliştirme içindir. Bütün portlar `127.0.0.1`'e bağlanır.

```bash
cp .env.example .env            # parolaları değiştirin
docker run --rm -v "$PWD/mosquitto:/mosquitto/config" eclipse-mosquitto:2.1-alpine \
  mosquitto_passwd -c -b /mosquitto/config/passwd shedu-dev "yerel-bir-parola"
docker compose up -d
```

`.env` ve `mosquitto/passwd` commit'lenmez.
