-- Üyeler, davetler ve yetki yönetimi.
--
-- Kurallar:
--  * Her organizasyonun tam olarak bir sahibi vardır. Sahibin üyeliği doğrudan silinemez ve rolü
--    değiştirilemez; organizasyon veya kullanıcı silinirken zincirleme silme serbesttir (AZ-05).
--  * Panel yetkisi yalnızca o organizasyonun üyesine verilebilir; üyelik silinince yetkileri de
--    silinir (SES-04, AZ-04).
--  * Davet bir telefon numarasına bağlıdır; bağlantı veya kod taşımaz. Kabul eden kişi o numarayı
--    SMS koduyla doğrulamış hesabın sahibidir. Davet en fazla 7 gün geçerlidir ve tek kez
--    sonuçlanır (AUT-03).

-- ---------------------------------------------------------------------------------------------
-- Sahiplik
-- ---------------------------------------------------------------------------------------------

CREATE UNIQUE INDEX memberships_one_owner ON memberships (organization_id) WHERE role = 'owner';

CREATE FUNCTION memberships_protect_owner() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    -- Tetikleyici derinliği 1'den büyükse işlem bir zincirleme silmedir (organizasyon veya
    -- kullanıcı silinmesi); buna izin verilir.
    IF OLD.role = 'owner' AND pg_trigger_depth() = 1 AND (
           TG_OP = 'DELETE'
           OR NEW.role IS DISTINCT FROM 'owner'
           OR NEW.user_id IS DISTINCT FROM OLD.user_id
           OR NEW.organization_id IS DISTINCT FROM OLD.organization_id) THEN
        RAISE EXCEPTION 'organizasyon sahibinin üyeliği değiştirilemez'
            USING ERRCODE = 'restrict_violation';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER memberships_protect_owner
    BEFORE UPDATE OR DELETE ON memberships
    FOR EACH ROW EXECUTE FUNCTION memberships_protect_owner();

-- ---------------------------------------------------------------------------------------------
-- Yetki kaydı yalnızca üyeye
-- ---------------------------------------------------------------------------------------------

-- Üyesi olmayan kullanıcıya verilmiş eski yetkiler zaten etkisizdir (her istek üyeliği doğrular);
-- kısıt eklenmeden önce temizlenir.
DELETE FROM access_grants g
 WHERE NOT EXISTS (SELECT 1 FROM memberships m
                    WHERE m.user_id = g.user_id AND m.organization_id = g.organization_id);

ALTER TABLE access_grants
    ADD CONSTRAINT access_grants_membership_fkey
    FOREIGN KEY (user_id, organization_id) REFERENCES memberships (user_id, organization_id)
    ON DELETE CASCADE;

-- ---------------------------------------------------------------------------------------------
-- Davetler
-- ---------------------------------------------------------------------------------------------

CREATE TABLE invitations (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    phone            text NOT NULL CHECK (phone ~ '^\+[1-9][0-9]{6,14}$'),
    -- Sahiplik davetle devredilmez.
    role             text NOT NULL CHECK (role IN ('admin', 'member')),
    invited_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    accepted_at      timestamptz,
    accepted_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    declined_at      timestamptz,
    revoked_at       timestamptz,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '7 days'),
    -- Davet en fazla bir kez sonuçlanır: kabul, ret veya iptal.
    CHECK (num_nonnulls(accepted_at, declined_at, revoked_at) <= 1)
);
-- Aynı numaraya aynı organizasyondan aynı anda tek açık davet. Süresi dolan açık davet, yenisi
-- oluşturulmadan önce API tarafından kapatılır.
CREATE UNIQUE INDEX invitations_one_open ON invitations (organization_id, phone)
    WHERE accepted_at IS NULL AND declined_at IS NULL AND revoked_at IS NULL;
CREATE INDEX invitations_phone_idx ON invitations (phone)
    WHERE accepted_at IS NULL AND declined_at IS NULL AND revoked_at IS NULL;

-- İşlemi yapan kullanıcının doğrulanmış telefon numarası. Kullanıcı bağlamı yoksa NULL.
CREATE FUNCTION app_current_user_phone() RETURNS text
    LANGUAGE sql STABLE
AS $$
    SELECT phone FROM users WHERE id = app_current_user()
$$;

-- Organizasyon davetleri yönetir; davet edilen kişi yalnızca kendi numarasına gelen daveti görür
-- ve yanıtlar (AZ-02).
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON invitations
    USING (organization_id = app_current_org())
    WITH CHECK (organization_id = app_current_org());
CREATE POLICY invitee_read ON invitations FOR SELECT
    USING (phone = app_current_user_phone());
CREATE POLICY invitee_respond ON invitations FOR UPDATE
    USING (phone = app_current_user_phone())
    WITH CHECK (phone = app_current_user_phone());

-- Davet edilen kişi, kendisine açık davet gönderen organizasyonun adını görebilir.
CREATE POLICY invitee_read ON organizations FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM invitations i
         WHERE i.organization_id = organizations.id
           AND i.phone = app_current_user_phone()
           AND i.accepted_at IS NULL AND i.declined_at IS NULL AND i.revoked_at IS NULL
           AND i.expires_at > now()));

GRANT SELECT, INSERT ON invitations TO shedu_app;
-- Davetin kapsamı (organizasyon, numara, rol) oluşturulduktan sonra değiştirilemez.
GRANT UPDATE (accepted_at, accepted_by, declined_at, revoked_at) ON invitations TO shedu_app;
