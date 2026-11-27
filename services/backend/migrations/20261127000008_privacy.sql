-- Kişisel veriler (KVKK): hesap silme ve kişisel verilerin dışa aktarılması.
--
-- Kurallar (DAT-01, DAT-02, AZ-03):
--  * Hesap silme anonimleştirme ve yok etmedir. Kullanıcının tek başına sahibi olduğu
--    organizasyonlar bütün verisiyle silinir. Başka organizasyonlardaki güvenlik kayıtları
--    (komutlar, bildirim teslimleri, denetim kaydı) korunur; kullanıcı satırı kimliksiz bir kayda
--    dönüşür (ad, telefon, e-posta, parola silinir), böylece bu kayıtlar kişiye bağlanamaz.
--    Denetim kaydına telefon, PIN, token veya parola hiç yazılmaz (LOG-02).
--  * Başka üyesi olan bir organizasyonun sahibi hesabını silemez; önce sahipliği devretmelidir
--    (organizasyon sahipsiz kalmaz, AZ-05).
--  * Dışa aktarma yalnızca kullanıcının kendi verisini döndürür; ayrıldığı organizasyonlardaki
--    kendi komutları ve kendisiyle ilgili güvenlik olayları dahil. Başka kişilerin kişisel verisi
--    (kimlikleri, numaraları, olay ayrıntıları) dışarı çıkmaz.
--  Fonksiyonlar tablo sahibinin yetkisiyle çalışır ve yalnızca işlemin kullanıcı bağlamına
--  (`app_current_user()`) göre işler; başka bir kullanıcı adına çağrılamaz.

-- ---------------------------------------------------------------------------------------------
-- Silinmiş kullanıcı
-- ---------------------------------------------------------------------------------------------

ALTER TABLE users DROP CONSTRAINT users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check
    CHECK (status IN ('active', 'disabled', 'deleted'));
ALTER TABLE users ADD COLUMN deleted_at timestamptz;

ALTER TABLE users DROP CONSTRAINT users_check;
ALTER TABLE users ADD CONSTRAINT users_identifier_check
    CHECK (status = 'deleted' OR email IS NOT NULL OR phone IS NOT NULL);
-- Silinmiş kullanıcıda tanımlayıcı veri ve parola kalmaz.
ALTER TABLE users ADD CONSTRAINT users_deleted_check
    CHECK ((status = 'deleted') = (deleted_at IS NOT NULL)
           AND (status <> 'deleted' OR (phone IS NULL AND email IS NULL AND password_hash IS NULL)));

-- Kişinin kendi denetim kayıtlarını dışa aktarmak için.
CREATE INDEX audit_log_actor_idx ON audit_log (actor_user_id, created_at DESC);

-- ---------------------------------------------------------------------------------------------
-- Hesap silme
-- ---------------------------------------------------------------------------------------------

CREATE FUNCTION erase_account() RETURNS jsonb
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
DECLARE
    actor uuid := app_current_user();
    actor_phone text;
    sole_orgs uuid[];
    removed_memberships integer;
    removed_invitations integer := 0;
BEGIN
    IF actor IS NULL THEN
        RAISE EXCEPTION 'kullanıcı bağlamı yok' USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT phone INTO actor_phone FROM users WHERE id = actor AND status <> 'deleted' FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'hesap bulunamadı' USING ERRCODE = 'no_data_found';
    END IF;

    -- Üyelikler kilitlenir: silme sürerken başka biri organizasyona katılamaz veya devralamaz.
    PERFORM 1 FROM memberships m
      WHERE m.organization_id IN (SELECT organization_id FROM memberships WHERE user_id = actor)
      FOR UPDATE;
    IF EXISTS (SELECT 1 FROM memberships m
                WHERE m.user_id = actor AND m.role = 'owner'
                  AND EXISTS (SELECT 1 FROM memberships o
                               WHERE o.organization_id = m.organization_id AND o.user_id <> actor)) THEN
        RAISE EXCEPTION 'önce sahiplik devredilmeli' USING ERRCODE = 'restrict_violation';
    END IF;

    SELECT coalesce(array_agg(organization_id), '{}') INTO sole_orgs
      FROM memberships WHERE user_id = actor AND role = 'owner';
    IF EXISTS (SELECT 1 FROM organizations WHERE parent_id = ANY (sole_orgs)) THEN
        RAISE EXCEPTION 'alt organizasyonu olan organizasyon silinemez'
            USING ERRCODE = 'restrict_violation';
    END IF;

    -- Tek üyeli organizasyonlar bütün verisiyle: komutlar panele zincirleme bağlı olmadığı için
    -- önce komutlar, sonra paneller (bölüm, zon, olay, yetki, teslim kaydı), sonra organizasyon
    -- (üyelik, davet).
    DELETE FROM commands WHERE organization_id = ANY (sole_orgs);
    DELETE FROM panels WHERE organization_id = ANY (sole_orgs);
    DELETE FROM organizations WHERE id = ANY (sole_orgs);

    -- Diğer organizasyonlardaki üyelikler; panel yetkileri yabancı anahtarla silinir.
    DELETE FROM memberships WHERE user_id = actor;
    GET DIAGNOSTICS removed_memberships = ROW_COUNT;

    -- Gönderdiği açık davetler iptal edilir; numarasına gelmiş bütün davetler silinir.
    UPDATE invitations SET revoked_at = now()
     WHERE invited_by = actor
       AND accepted_at IS NULL AND declined_at IS NULL AND revoked_at IS NULL;
    IF actor_phone IS NOT NULL THEN
        DELETE FROM invitations WHERE phone = actor_phone;
        GET DIAGNOSTICS removed_invitations = ROW_COUNT;
        DELETE FROM verification_codes WHERE phone = actor_phone;
    END IF;

    -- Kimlik ve oturum verileri.
    DELETE FROM session_factors WHERE user_id = actor;
    DELETE FROM mfa_challenges WHERE user_id = actor;
    DELETE FROM recovery_codes WHERE user_id = actor;
    DELETE FROM user_totp WHERE user_id = actor;
    DELETE FROM verification_codes WHERE user_id = actor;
    DELETE FROM refresh_tokens WHERE user_id = actor;
    DELETE FROM user_devices WHERE user_id = actor;

    UPDATE users
       SET display_name = 'Silinmiş kullanıcı', phone = NULL, email = NULL, password_hash = NULL,
           status = 'deleted', deleted_at = now(), updated_at = now()
     WHERE id = actor;

    RETURN jsonb_build_object(
        'organizations_deleted', cardinality(sole_orgs),
        'memberships_removed', removed_memberships,
        'invitations_removed', removed_invitations);
END
$$;

REVOKE ALL ON FUNCTION erase_account() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION erase_account() TO shedu_app;

-- ---------------------------------------------------------------------------------------------
-- Dışa aktarma
-- ---------------------------------------------------------------------------------------------

-- Kullanıcının verdiği komutlar, bütün organizasyonlarda (ayrıldıkları dahil). En fazla 10.000.
CREATE FUNCTION privacy_my_commands(max_rows integer)
    RETURNS TABLE (id uuid, organization_id uuid, panel_id uuid, partition_id uuid, kind text,
                   zones smallint[], status text, rejection_reason text,
                   requested_at timestamptz, completed_at timestamptz)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
    SELECT c.id, c.organization_id, c.panel_id, c.partition_id, c.kind, c.zones, c.status,
           c.rejection_reason, c.requested_at, c.completed_at
      FROM commands c
     WHERE app_current_user() IS NOT NULL AND c.user_id = app_current_user()
     ORDER BY c.requested_at DESC
     LIMIT least(greatest(max_rows, 0), 10000)
$$;

-- Kullanıcının yaptığı veya ona yönelik güvenlik olayları. Başka bir kişinin kimliği ve olay
-- ayrıntıları döndürülmez. En fazla 10.000.
CREATE FUNCTION privacy_my_audit(max_rows integer)
    RETURNS TABLE (organization_id uuid, action text, outcome text, by_me boolean,
                   created_at timestamptz)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
    SELECT a.organization_id, a.action, a.outcome, a.actor_user_id IS NOT DISTINCT FROM app_current_user(),
           a.created_at
      FROM audit_log a
     WHERE app_current_user() IS NOT NULL
       AND (a.actor_user_id = app_current_user()
            OR (a.target_type = 'user' AND a.target_id = app_current_user()::text))
     ORDER BY a.created_at DESC
     LIMIT least(greatest(max_rows, 0), 10000)
$$;

REVOKE ALL ON FUNCTION privacy_my_commands(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION privacy_my_audit(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION privacy_my_commands(integer) TO shedu_app;
GRANT EXECUTE ON FUNCTION privacy_my_audit(integer) TO shedu_app;
