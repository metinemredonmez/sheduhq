-- İki adımlı doğrulama (TOTP) ve kurtarma kodları.
--
-- Kurallar (AUT-01, AUT-04, KEY-04):
--  * TOTP sırrı şifreli saklanır; anahtar sürümü ve nonce kayıtla birlikte durur. Son kabul edilen
--    zaman adımı tutulur, aynı kod ikinci kez kabul edilmez.
--  * Kurtarma kodlarının yalnızca HMAC özeti saklanır; her kod tek kullanımlıktır.
--  * Parolası doğrulanan kullanıcı, ikinci adımı kısa ömürlü bir biletle tamamlar; bilet en fazla
--    5 dakika ve 5 deneme geçerlidir, tek kullanımlıktır.
--  * İkinci adımı tamamlanmış oturum (refresh ailesi) ayrıca kaydedilir; ayrıcalıklı işlemler
--    yalnızca bu oturumlara açılır.
--  Bu tablolar kimlik tablolarıdır; giriş akışında kiracı bağlamı olmadan okunur, RLS dışındadır
--  ve API her zaman kullanıcı kimliğiyle filtreler.

CREATE TABLE user_totp (
    user_id       uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    key_version   smallint NOT NULL CHECK (key_version > 0),
    nonce         bytea NOT NULL CHECK (length(nonce) = 24),
    -- 20 baytlık sır + 16 baytlık doğrulama etiketi.
    secret_ct     bytea NOT NULL CHECK (length(secret_ct) = 36),
    -- NULL: kurulum başladı, henüz bir kodla onaylanmadı (girişte istenmez).
    confirmed_at  timestamptz,
    last_step     bigint,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE recovery_codes (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash   bytea NOT NULL UNIQUE CHECK (length(code_hash) = 32),
    created_at  timestamptz NOT NULL DEFAULT now(),
    used_at     timestamptz
);
CREATE INDEX recovery_codes_user_idx ON recovery_codes (user_id) WHERE used_at IS NULL;

CREATE TABLE mfa_challenges (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash   bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    -- Oturum, ikinci adım tamamlanınca bu cihaz bilgisiyle açılır.
    platform     text NOT NULL CHECK (platform IN ('ios', 'android', 'web')),
    device_name  text CHECK (length(device_name) <= 100),
    attempts     smallint NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    consumed_at  timestamptz,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes')
);
CREATE INDEX mfa_challenges_user_idx ON mfa_challenges (user_id);

CREATE TABLE session_factors (
    family_id    uuid PRIMARY KEY,
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    method       text NOT NULL CHECK (method IN ('totp', 'recovery_code')),
    verified_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX session_factors_user_idx ON session_factors (user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON user_totp, recovery_codes, mfa_challenges, session_factors
    TO shedu_app;
