-- Giriş ve oturum desteği.

-- İsteği yapan doğrulanmış kullanıcı. API, token'ı doğruladıktan sonra her işlemde
-- `SET LOCAL app.user_id` ile verir. Ayarlanmamışsa NULL döner.
CREATE FUNCTION app_current_user() RETURNS uuid
    LANGUAGE sql STABLE
AS $$
    SELECT nullif(current_setting('app.user_id', true), '')::uuid
$$;

-- Kullanıcı, üyesi olduğu organizasyonların adını kiracı bağlamı seçmeden de görebilir
-- ("hangi evlerim / şirketlerim var?"). Yalnızca okuma; yazma için kiracı bağlamı şart.
CREATE POLICY member_read ON organizations FOR SELECT
    USING (id IN (SELECT organization_id FROM memberships WHERE user_id = app_current_user()));

-- Deneme sayaçları (AUT-02, RES-01). Bütün API kopyaları aynı sayaçları atomik olarak paylaşır.
-- Anahtar, sunucudaki gizli bir anahtarla HMAC'lenmiş kapsam + değerdir (ör. telefon, IP);
-- düz kişisel veri saklanmaz.
CREATE TABLE rate_limit_buckets (
    key           bytea NOT NULL CHECK (length(key) = 32),
    window_start  timestamptz NOT NULL,
    hits          integer NOT NULL CHECK (hits > 0),
    PRIMARY KEY (key, window_start)
);
CREATE INDEX rate_limit_buckets_window_idx ON rate_limit_buckets (window_start);

GRANT SELECT, INSERT, UPDATE, DELETE ON rate_limit_buckets TO shedu_app;
