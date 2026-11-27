-- Shedu ilk şeması.
--
-- Kurallar:
--  * Kiracı (organizasyon) verisi taşıyan her tabloda organization_id vardır ve Row-Level Security
--    açıktır (AZ-02). API kiracı kimliğini istemciden almaz; doğruladığı token'dan çıkarıp her
--    işlemde `SET LOCAL app.org_id = '<uuid>'` ile verir. Ayar yoksa hiçbir satır görünmez
--    (fail-closed, EXC-01).
--  * Uygulama veritabanına tablo sahibi olmayan `shedu_app` rolüyle bağlanır; bu rol RLS'yi
--    aşamaz. Giriş yapan gerçek kullanıcı (parolası sır yönetiminden gelir) bu role üye yapılır;
--    parola bu dosyada yoktur (KEY-02).
--  * Alt kayıtlar bileşik yabancı anahtarla üst kaydın organizasyonuna ve paneline bağlanır;
--    başka bir kiracının paneline bölüm, zon veya yetki bağlanamaz (AZ-04).
--  * Parola, refresh token ve doğrulama kodlarının yalnızca hash'i saklanır. Panel PIN'i hiç
--    saklanmaz.
--  * Kimlik tabloları (users, memberships, user_devices, refresh_tokens, verification_codes)
--    giriş akışında kiracı bağlamı olmadan okunduğu için RLS dışındadır; API bunları her zaman
--    kullanıcı kimliğiyle filtreler.

-- Roller küme genelidir; aynı kümede birden fazla veritabanı eşzamanlı kurulurken (ör. paralel
-- testler) iki oturum aynı anda oluşturmaya çalışabilir. İkincisinin hatası yok sayılır.
DO $$
BEGIN
    CREATE ROLE shedu_app NOLOGIN;
EXCEPTION
    WHEN duplicate_object OR unique_violation THEN
        NULL;
END
$$;

-- İşlemin kiracısı. Ayarlanmamışsa NULL döner ve RLS politikaları hiçbir satırı eşleştirmez.
CREATE FUNCTION app_current_org() RETURNS uuid
    LANGUAGE sql STABLE
AS $$
    SELECT nullif(current_setting('app.org_id', true), '')::uuid
$$;

-- ---------------------------------------------------------------------------------------------
-- Organizasyonlar ve kimlik
-- ---------------------------------------------------------------------------------------------

CREATE TABLE organizations (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- İzleme firması → müşteri → şube gibi hiyerarşiler için.
    parent_id   uuid REFERENCES organizations (id),
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    kind        text NOT NULL CHECK (kind IN ('home', 'business', 'monitoring_center')),
    -- Erişim pencereleri bu saat dilimine göre değerlendirilir (IANA adı).
    time_zone   text NOT NULL DEFAULT 'Europe/Istanbul' CHECK (length(time_zone) BETWEEN 1 AND 64),
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email          text CHECK (email = lower(email) AND email ~ '^[^@\s]+@[^@\s]+$' AND length(email) <= 254),
    -- E.164 biçimi, ör. +905551112233
    phone          text CHECK (phone ~ '^\+[1-9][0-9]{6,14}$'),
    display_name   text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 100),
    -- PHC biçiminde argon2id hash'i (PWD-04). Sosyal girişle açılan hesaplarda boş olabilir.
    password_hash  text CHECK (password_hash LIKE '$argon2id$%'),
    status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CHECK (email IS NOT NULL OR phone IS NOT NULL)
);
CREATE UNIQUE INDEX users_email_key ON users (email) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX users_phone_key ON users (phone) WHERE phone IS NOT NULL;

CREATE TABLE memberships (
    user_id          uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    organization_id  uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    role             text NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'operator')),
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, organization_id)
);
CREATE INDEX memberships_organization_idx ON memberships (organization_id);

-- Kullanıcının oturum açtığı cihazlar ("bağlı cihazlar" ekranı ve push hedefi).
CREATE TABLE user_devices (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    platform      text NOT NULL CHECK (platform IN ('ios', 'android', 'web')),
    name          text CHECK (length(name) <= 100),
    push_token    text CHECK (length(push_token) <= 4096),
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz
);
CREATE INDEX user_devices_user_idx ON user_devices (user_id);
CREATE UNIQUE INDEX user_devices_push_token_key ON user_devices (push_token) WHERE push_token IS NOT NULL;

-- Refresh token'lar her kullanımda yenilenir. Aynı ailedeki kullanılmış bir token yeniden
-- gelirse çalınmış sayılır ve bütün aile iptal edilir (SES-05).
CREATE TABLE refresh_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id   uuid REFERENCES user_devices (id) ON DELETE CASCADE,
    family_id   uuid NOT NULL,
    -- Token'ın kendisi değil, SHA-256 özeti saklanır.
    token_hash  bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    revoked_at  timestamptz,
    CHECK (expires_at > created_at)
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_user_idx ON refresh_tokens (user_id);

-- SMS doğrulama kodları: tek kullanımlık, en fazla 15 dakika geçerli, en fazla 5 deneme (AUT-03).
-- code_hash, sunucudaki gizli bir anahtarla HMAC-SHA256'dır; 6 haneli kodun düz SHA-256'sı
-- kolayca kırılabileceği için kullanılmaz.
CREATE TABLE verification_codes (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    purpose      text NOT NULL CHECK (purpose IN ('register', 'password_reset', 'phone_change')),
    phone        text NOT NULL CHECK (phone ~ '^\+[1-9][0-9]{6,14}$'),
    user_id      uuid REFERENCES users (id) ON DELETE CASCADE,
    code_hash    bytea NOT NULL CHECK (length(code_hash) = 32),
    attempts     smallint NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    consumed_at  timestamptz,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes')
);
CREATE INDEX verification_codes_active_idx ON verification_codes (phone, purpose) WHERE consumed_at IS NULL;

-- ---------------------------------------------------------------------------------------------
-- Paneller, bölümler, zonlar, çıkışlar
-- ---------------------------------------------------------------------------------------------

CREATE TABLE panels (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid NOT NULL REFERENCES organizations (id),
    name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    brand            text NOT NULL CHECK (length(brand) BETWEEN 1 AND 50),
    model            text CHECK (length(model) <= 50),
    -- Panelin donanım / ağ kimliği.
    device_serial    text NOT NULL CHECK (length(device_serial) BETWEEN 1 AND 100),
    -- Varsayılan çevrimdışı: panel kendini bildirene kadar komut kabul edilmez (EXC-01).
    connectivity     text NOT NULL DEFAULT 'offline' CHECK (connectivity IN ('online', 'offline')),
    ready_to_arm     boolean NOT NULL DEFAULT false,
    last_seen_at     timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, organization_id),
    UNIQUE (brand, device_serial)
);
CREATE INDEX panels_organization_idx ON panels (organization_id);

CREATE TABLE partitions (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   uuid NOT NULL,
    panel_id          uuid NOT NULL,
    number            smallint NOT NULL CHECK (number BETWEEN 1 AND 255),
    name              text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    state             text NOT NULL DEFAULT 'disarmed'
                      CHECK (state IN ('disarmed', 'armed_away', 'armed_stay', 'armed_night', 'alarm')),
    state_changed_at  timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (panel_id, organization_id) REFERENCES panels (id, organization_id) ON DELETE CASCADE,
    UNIQUE (panel_id, number),
    UNIQUE (id, panel_id)
);

CREATE TABLE zones (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid NOT NULL,
    panel_id         uuid NOT NULL,
    number           smallint NOT NULL CHECK (number BETWEEN 1 AND 9999),
    name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    kind             text NOT NULL DEFAULT 'intrusion'
                     CHECK (kind IN ('intrusion', 'fire', 'gas', 'flood', 'panic', 'medical', 'tamper', 'other')),
    bypassed         boolean NOT NULL DEFAULT false,
    FOREIGN KEY (panel_id, organization_id) REFERENCES panels (id, organization_id) ON DELETE CASCADE,
    UNIQUE (panel_id, number),
    UNIQUE (id, panel_id)
);

-- Bir zon birden fazla bölüme ait olabilir. Zon ve bölüm aynı panelde olmak zorundadır.
CREATE TABLE zone_partitions (
    organization_id  uuid NOT NULL,
    panel_id         uuid NOT NULL,
    zone_id          uuid NOT NULL,
    partition_id     uuid NOT NULL,
    PRIMARY KEY (zone_id, partition_id),
    FOREIGN KEY (panel_id, organization_id) REFERENCES panels (id, organization_id) ON DELETE CASCADE,
    FOREIGN KEY (zone_id, panel_id) REFERENCES zones (id, panel_id) ON DELETE CASCADE,
    FOREIGN KEY (partition_id, panel_id) REFERENCES partitions (id, panel_id) ON DELETE CASCADE
);
CREATE INDEX zone_partitions_partition_idx ON zone_partitions (partition_id);

-- Panel çıkışları (siren, röle, kapı açma vb.).
CREATE TABLE outputs (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid NOT NULL,
    panel_id         uuid NOT NULL,
    number           smallint NOT NULL CHECK (number BETWEEN 1 AND 999),
    name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    FOREIGN KEY (panel_id, organization_id) REFERENCES panels (id, organization_id) ON DELETE CASCADE,
    UNIQUE (panel_id, number)
);

-- ---------------------------------------------------------------------------------------------
-- Yetkiler: kim, hangi panelde / bölümde, ne yapabilir, hangi gün ve saatlerde
-- ---------------------------------------------------------------------------------------------

CREATE TABLE access_grants (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid NOT NULL,
    user_id          uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    panel_id         uuid NOT NULL,
    -- NULL: panelin bütün bölümleri.
    partition_id     uuid,
    can_arm          boolean NOT NULL DEFAULT false,
    can_disarm       boolean NOT NULL DEFAULT false,
    can_bypass       boolean NOT NULL DEFAULT false,
    can_view_events  boolean NOT NULL DEFAULT true,
    -- true: gün/saat kısıtı yok (ör. ev sahibi). false ve hiç pencere yoksa erişim yok.
    always_open      boolean NOT NULL DEFAULT false,
    valid_from       timestamptz,
    expires_at       timestamptz,
    created_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (panel_id, organization_id) REFERENCES panels (id, organization_id) ON DELETE CASCADE,
    FOREIGN KEY (partition_id, panel_id) REFERENCES partitions (id, panel_id) ON DELETE CASCADE,
    UNIQUE (id, organization_id),
    CHECK (valid_from IS NULL OR expires_at IS NULL OR expires_at > valid_from)
);
CREATE UNIQUE INDEX access_grants_scope_key ON access_grants (user_id, panel_id, partition_id) NULLS NOT DISTINCT;

CREATE TABLE access_windows (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid NOT NULL,
    grant_id         uuid NOT NULL,
    -- ISO 8601: 1 = Pazartesi, 7 = Pazar.
    day              smallint NOT NULL CHECK (day BETWEEN 1 AND 7),
    start_minute     smallint NOT NULL CHECK (start_minute BETWEEN 0 AND 1439),
    -- Hariç. start_minute'tan küçükse pencere gece yarısını aşar.
    end_minute       smallint NOT NULL CHECK (end_minute BETWEEN 0 AND 1439),
    FOREIGN KEY (grant_id, organization_id) REFERENCES access_grants (id, organization_id) ON DELETE CASCADE,
    CHECK (start_minute <> end_minute)
);
CREATE INDEX access_windows_grant_idx ON access_windows (grant_id);

-- ---------------------------------------------------------------------------------------------
-- Komutlar, olaylar, denetim kaydı
-- ---------------------------------------------------------------------------------------------

CREATE TABLE commands (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   uuid NOT NULL,
    panel_id          uuid NOT NULL,
    partition_id      uuid NOT NULL,
    user_id           uuid NOT NULL REFERENCES users (id),
    kind              text NOT NULL
                      CHECK (kind IN ('arm_away', 'arm_stay', 'arm_night', 'disarm', 'bypass_zones', 'unbypass_zones')),
    zones             smallint[],
    -- İstemcinin ürettiği tekrar anahtarı: aynı istek iki kez işlenmez (BUS-02).
    idempotency_key   text NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 128),
    status            text NOT NULL DEFAULT 'accepted'
                      CHECK (status IN ('accepted', 'rejected', 'sent', 'succeeded',
                                        'rejected_by_panel', 'not_delivered', 'no_acknowledgement')),
    rejection_reason  text CHECK (length(rejection_reason) <= 200),
    requested_at      timestamptz NOT NULL DEFAULT now(),
    completed_at      timestamptz,
    FOREIGN KEY (panel_id, organization_id) REFERENCES panels (id, organization_id),
    FOREIGN KEY (partition_id, panel_id) REFERENCES partitions (id, panel_id),
    UNIQUE (user_id, idempotency_key),
    -- Zon listesi yalnızca bypass komutlarında ve boş olmayan şekilde bulunur.
    CHECK ((kind IN ('bypass_zones', 'unbypass_zones')) = (zones IS NOT NULL AND cardinality(zones) > 0)),
    CHECK ((status = 'rejected') = (rejection_reason IS NOT NULL))
);
CREATE INDEX commands_panel_idx ON commands (panel_id, requested_at DESC);
-- Bir bölümde aynı anda yalnızca bir komut yolda olabilir; eşzamanlı kur/kapat yarışı
-- veritabanı düzeyinde engellenir (BUS-02).
CREATE UNIQUE INDEX commands_one_in_flight_per_partition ON commands (partition_id)
    WHERE status IN ('accepted', 'sent');

-- Panelden gelen olaylar. Zon ve bölüm numarayla tutulur; zon silinse de geçmiş korunur.
CREATE TABLE panel_events (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id   uuid NOT NULL,
    panel_id          uuid NOT NULL,
    partition_number  smallint,
    zone_number       smallint,
    kind              text NOT NULL
                      CHECK (kind IN ('alarm', 'armed', 'disarmed', 'connected', 'disconnected', 'power_problem')),
    alarm_kind        text CHECK (alarm_kind IN ('intrusion', 'keypad_or_keyfob', 'panic', 'fire', 'medical', 'tamper')),
    arm_mode          text CHECK (arm_mode IN ('away', 'stay', 'night')),
    priority          text NOT NULL CHECK (priority IN ('info', 'warning', 'critical')),
    occurred_at       timestamptz NOT NULL,
    received_at       timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (panel_id, organization_id) REFERENCES panels (id, organization_id) ON DELETE CASCADE,
    CHECK ((kind = 'alarm') = (alarm_kind IS NOT NULL)),
    CHECK ((kind = 'armed') = (arm_mode IS NOT NULL)),
    -- Alarm her zaman kritiktir; domain kuralıyla aynı (alarm.rs).
    CHECK (kind <> 'alarm' OR priority = 'critical')
);
CREATE INDEX panel_events_panel_time_idx ON panel_events (organization_id, panel_id, occurred_at DESC);

-- Denetim kaydı: yalnızca eklenir, güncellenemez ve silinemez (LOG-01, LOG-03).
-- Kullanıcı veya organizasyon silinse de kayıt kalsın diye yabancı anahtar yoktur.
-- details alanına PIN, token, parola veya telefon numarası yazılmaz (LOG-02).
CREATE TABLE audit_log (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- NULL: kiracıdan bağımsız kimlik olayları (ör. başarısız giriş).
    organization_id  uuid,
    actor_user_id    uuid,
    action           text NOT NULL CHECK (action ~ '^[a-z_]+(\.[a-z_]+)+$'),
    target_type      text CHECK (length(target_type) <= 50),
    target_id        text CHECK (length(target_id) <= 100),
    outcome          text NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
    details          jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_org_time_idx ON audit_log (organization_id, created_at DESC);

CREATE FUNCTION audit_log_is_append_only() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_log yalnızca eklemeye açıktır';
END
$$;

CREATE TRIGGER audit_log_no_update_or_delete
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_is_append_only();

CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_is_append_only();

-- ---------------------------------------------------------------------------------------------
-- Row-Level Security: kiracı izolasyonu (AZ-02)
-- ---------------------------------------------------------------------------------------------

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON organizations
    USING (id = app_current_org())
    WITH CHECK (id = app_current_org());

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['panels', 'partitions', 'zones', 'zone_partitions', 'outputs',
                             'access_grants', 'access_windows', 'commands', 'panel_events']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I
                 USING (organization_id = app_current_org())
                 WITH CHECK (organization_id = app_current_org())', t);
    END LOOP;
END
$$;

-- Denetim kaydı: kiracı yalnızca kendi kayıtlarını görür; kiracısız kimlik olayları eklenebilir
-- ama uygulama tarafından okunamaz.
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON audit_log FOR SELECT
    USING (organization_id = app_current_org());
CREATE POLICY tenant_insert ON audit_log FOR INSERT
    WITH CHECK (organization_id IS NULL OR organization_id = app_current_org());

-- ---------------------------------------------------------------------------------------------
-- Uygulama rolünün yetkileri: en az yetki (ARC-04, DAT-04)
-- ---------------------------------------------------------------------------------------------

GRANT USAGE ON SCHEMA public TO shedu_app;

GRANT SELECT, INSERT, UPDATE ON organizations TO shedu_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON
    users, memberships, user_devices, refresh_tokens, verification_codes,
    panels, partitions, zones, zone_partitions, outputs, access_grants, access_windows
    TO shedu_app;
-- Komutlar silinmez; yalnızca durumları güncellenir.
GRANT SELECT, INSERT, UPDATE ON commands TO shedu_app;
-- Olaylar ve denetim kaydı yalnızca eklenir.
GRANT SELECT, INSERT ON panel_events, audit_log TO shedu_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO shedu_app;
