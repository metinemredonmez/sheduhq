-- Rıza defteri ve 30 gün içinde geri alınabilir hesap silme (KVKK).
--
-- Kurallar:
--  * Hesap silme talebi hesabı hemen kapatır (oturumlar ve bildirimler biter) ve silmeyi 30 gün
--    sonraya planlar. Kişi bu sürede tam doğrulamayla (parola ve varsa ikinci adım) giriş yaparsa
--    talep iptal olur. Süre dolunca API'deki silme işi `erase_account()`'ı çalıştırır.
--  * Rıza defteri yalnızca eklenir: her verme ve geri çekme ayrı bir kayıttır, kayıtlar
--    değiştirilemez ve silinemez (kanıt). Hangi amaçların bulunduğu ve güncel metin sürümü
--    `consent_purposes` tablosundadır; amaç listesi hukuki karara göre migration'la değişir.
--    Hesap silindiğinde kayıtlar, kimliksizleşmiş kullanıcı satırına bağlı olarak kalır.

-- ---------------------------------------------------------------------------------------------
-- Silme bekleyen hesap
-- ---------------------------------------------------------------------------------------------

ALTER TABLE users DROP CONSTRAINT users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check
    CHECK (status IN ('active', 'disabled', 'pending_deletion', 'deleted'));
ALTER TABLE users ADD COLUMN deletion_due_at timestamptz;
-- Bekleyen talepte tarih zorunlu, etkin hesapta yok; silinmiş hesapta planlanan tarih kayıt
-- olarak kalabilir.
ALTER TABLE users ADD CONSTRAINT users_deletion_due_check
    CHECK (CASE status
               WHEN 'pending_deletion' THEN deletion_due_at IS NOT NULL
               WHEN 'deleted' THEN true
               ELSE deletion_due_at IS NULL
           END);
CREATE INDEX users_deletion_due_idx ON users (deletion_due_at) WHERE status = 'pending_deletion';

-- ---------------------------------------------------------------------------------------------
-- Yalnızca eklenen tablolar için ortak tetikleyici
-- ---------------------------------------------------------------------------------------------

CREATE FUNCTION append_only() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% yalnızca eklemeye açıktır', TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END
$$;

-- ---------------------------------------------------------------------------------------------
-- Rıza defteri
-- ---------------------------------------------------------------------------------------------

CREATE TABLE consent_purposes (
    code             text PRIMARY KEY CHECK (code ~ '^[a-z_]{2,40}$'),
    -- Kişiye gösterilen metnin güncel sürümü; eski sürüme verilen yanıt kabul edilmez.
    current_version  text NOT NULL CHECK (length(current_version) BETWEEN 1 AND 40),
    -- explicit_consent: açık rıza (verilebilir, geri çekilebilir).
    -- notice_acknowledgement: aydınlatma metninin gösterildiği/okunduğu kaydı (geri çekilmez).
    kind             text NOT NULL CHECK (kind IN ('explicit_consent', 'notice_acknowledgement')),
    description      text NOT NULL CHECK (length(description) BETWEEN 1 AND 300)
);

-- Başlangıç listesi: metinler hukuken onaylanınca sürümler güncellenir (açık sorular 8–12).
INSERT INTO consent_purposes (code, current_version, kind, description) VALUES
    ('privacy_notice', 'taslak-1', 'notice_acknowledgement',
     'Kişisel verilerin işlenmesine ilişkin aydınlatma metni gösterildi ve okundu.'),
    ('marketing', 'taslak-1', 'explicit_consent',
     'Kampanya, duyuru ve tanıtım iletileri (SMS, e-posta, uygulama bildirimi).');

CREATE TABLE consent_records (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- Zincirleme silme yok: kullanıcı satırı hiçbir zaman fiziksel olarak silinmez.
    user_id      uuid NOT NULL REFERENCES users (id),
    purpose      text NOT NULL REFERENCES consent_purposes (code),
    version      text NOT NULL CHECK (length(version) BETWEEN 1 AND 40),
    granted      boolean NOT NULL,
    platform     text CHECK (platform IN ('ios', 'android', 'web')),
    recorded_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX consent_records_user_idx ON consent_records (user_id, purpose, recorded_at DESC);

CREATE TRIGGER consent_records_append_only
    BEFORE UPDATE OR DELETE ON consent_records
    FOR EACH ROW EXECUTE FUNCTION append_only();
CREATE TRIGGER consent_records_no_truncate
    BEFORE TRUNCATE ON consent_records
    FOR EACH STATEMENT EXECUTE FUNCTION append_only();

GRANT SELECT ON consent_purposes TO shedu_app;
GRANT SELECT, INSERT ON consent_records TO shedu_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO shedu_app;
