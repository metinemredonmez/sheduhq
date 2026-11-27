-- Sahiplik devri ve operatör rolü.
--
-- Kurallar:
--  * Uygulama rolü sahibin üyeliğini doğrudan değiştiremez ve silemez. Sahiplik yalnızca
--    `transfer_ownership` fonksiyonuyla devredilir: işlemi yapan kullanıcı o organizasyonun
--    sahibi olmalı, devralan kişi yönetici olmalı; iki değişiklik tek adımda olur ve
--    organizasyonda her an tam olarak bir sahip bulunur (AZ-05). Zincirleme silmeler (tablo
--    sahibi yetkisiyle çalışır) serbesttir.
--  * Operatör (izleme personeli) yalnızca işletme ve izleme merkezi organizasyonlarında olabilir.

-- ---------------------------------------------------------------------------------------------
-- Sahip koruması: tetikleyici derinliği yerine işlemi yapan rol
-- ---------------------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION memberships_protect_owner() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    -- Tablonun sahibi (migration, zincirleme silme, SECURITY DEFINER devir fonksiyonu) serbesttir;
    -- uygulama rolü sahip üyeliğine dokunamaz.
    IF OLD.role = 'owner'
       AND NOT pg_has_role(current_user, (SELECT relowner FROM pg_class WHERE oid = TG_RELID), 'MEMBER')
       AND (TG_OP = 'DELETE'
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

-- ---------------------------------------------------------------------------------------------
-- Sahiplik devri
-- ---------------------------------------------------------------------------------------------

-- İşlemin kullanıcı ve kiracı bağlamıyla çalışır: bağlamdaki kullanıcı sahip olmalı, devralan
-- yönetici olmalı. Önceki sahip yönetici olur.
CREATE FUNCTION transfer_ownership(new_owner uuid) RETURNS void
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
DECLARE
    org uuid := app_current_org();
    actor uuid := app_current_user();
BEGIN
    IF org IS NULL OR actor IS NULL OR new_owner IS NULL OR new_owner = actor THEN
        RAISE EXCEPTION 'geçersiz devir' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    UPDATE memberships SET role = 'admin'
     WHERE organization_id = org AND user_id = actor AND role = 'owner';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'yalnızca sahip devredebilir' USING ERRCODE = 'insufficient_privilege';
    END IF;
    UPDATE memberships SET role = 'owner'
     WHERE organization_id = org AND user_id = new_owner AND role = 'admin';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'devralan kişi yönetici olmalı' USING ERRCODE = 'invalid_parameter_value';
    END IF;
END
$$;

REVOKE ALL ON FUNCTION transfer_ownership(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION transfer_ownership(uuid) TO shedu_app;

-- ---------------------------------------------------------------------------------------------
-- Operatör rolü
-- ---------------------------------------------------------------------------------------------

ALTER TABLE invitations DROP CONSTRAINT invitations_role_check;
ALTER TABLE invitations ADD CONSTRAINT invitations_role_check
    CHECK (role IN ('admin', 'member', 'operator'));

-- Organizasyon türü RLS'den bağımsız okunmalı (ör. davet kabul edilirken kiracı bağlamı yoktur).
CREATE FUNCTION operator_requires_business() RETURNS trigger
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.role = 'operator' AND NOT EXISTS (
           SELECT 1 FROM organizations
            WHERE id = NEW.organization_id AND kind IN ('business', 'monitoring_center')) THEN
        RAISE EXCEPTION 'operatör yalnızca işletme ve izleme merkezi organizasyonlarında olabilir'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER memberships_operator_requires_business
    BEFORE INSERT OR UPDATE OF role ON memberships
    FOR EACH ROW EXECUTE FUNCTION operator_requires_business();
CREATE TRIGGER invitations_operator_requires_business
    BEFORE INSERT ON invitations
    FOR EACH ROW EXECUTE FUNCTION operator_requires_business();
