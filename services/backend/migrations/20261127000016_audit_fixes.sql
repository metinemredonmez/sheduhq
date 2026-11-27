-- Denetim düzeltmeleri (27 Kasım 2026): oturum aileleri ve kimlik bilgisi sürümü, kalıcı push
-- teslim kuyruğu, AI harcama rezervasyonu, sahiplik devrinde etkin hesap, takılan sanal komutlar,
-- olay kapsamı ve ayrıcalıklı yordamların arama yolu.

-- ---------------------------------------------------------------------------------------------
-- Oturum aileleri (SES-04, SES-05)
-- ---------------------------------------------------------------------------------------------

-- Her giriş bir aile açar; yenilemeler aynı ailede yeni refresh token üretir. Yenileme ve iptal
-- bu satırı kilitleyerek sıralanır: iptalle yarışan bir yenileme, iptal edilmiş ailede yeni
-- token bırakamaz. Oturumun etkin olup olmadığı tek kuralla (`session_active`) belirlenir.
CREATE TABLE session_families (
    id          uuid PRIMARY KEY,
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id   uuid REFERENCES user_devices (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz
);
CREATE INDEX session_families_user_idx ON session_families (user_id);
CREATE INDEX session_families_device_idx ON session_families (device_id);

INSERT INTO session_families (id, user_id, device_id, created_at, revoked_at)
SELECT family_id, user_id, (array_agg(device_id ORDER BY created_at))[1], min(created_at),
       CASE WHEN bool_and(revoked_at IS NOT NULL) THEN max(revoked_at) END
  FROM refresh_tokens
 GROUP BY family_id, user_id;

ALTER TABLE refresh_tokens ADD CONSTRAINT refresh_tokens_family_fkey
    FOREIGN KEY (family_id) REFERENCES session_families (id) ON DELETE CASCADE;
DELETE FROM session_factors f WHERE NOT EXISTS (SELECT 1 FROM session_families s WHERE s.id = f.family_id);
ALTER TABLE session_factors ADD CONSTRAINT session_factors_family_fkey
    FOREIGN KEY (family_id) REFERENCES session_families (id) ON DELETE CASCADE;

GRANT SELECT, INSERT, UPDATE (revoked_at) ON session_families TO shedu_app;

-- Oturum etkin mi? Bütün yüzeyler (HTTP, WebSocket, push alıcısı, oturum listesi, dışa aktarma)
-- bu kuralı kullanır: aile iptal edilmemiş, en fazla 90 günlük (auth::tokens::SESSION_MAX_DAYS),
-- kullanıcı etkin ve ailede yenilenebilir (kullanılmamış, süresi dolmamış) bir token var.
CREATE FUNCTION session_active(family uuid, account uuid) RETURNS boolean
    LANGUAGE sql
    STABLE
    SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1
          FROM public.session_families f
          JOIN public.users u ON u.id = f.user_id
         WHERE f.id = family AND f.user_id = account AND f.revoked_at IS NULL
           AND u.status = 'active'
           AND f.created_at > now() - interval '90 days'
           AND EXISTS (SELECT 1 FROM public.refresh_tokens r
                        WHERE r.family_id = f.id AND r.revoked_at IS NULL AND r.used_at IS NULL
                          AND r.expires_at > now()))
$$;

-- Kimlik bilgisi sürümü: parola sıfırlama ve ikinci faktör değişikliği artırır. Parola veya ikinci
-- adım doğrulandıktan sonra oturum açılırken sürüm yeniden okunur (satır kilidiyle); arada
-- değiştiyse oturum açılmaz.
ALTER TABLE users ADD COLUMN credential_version integer NOT NULL DEFAULT 0;
ALTER TABLE mfa_challenges ADD COLUMN credential_version integer NOT NULL DEFAULT 0;

-- ---------------------------------------------------------------------------------------------
-- Kalıcı push teslim kuyruğu (BUS-02, ARC-05)
-- ---------------------------------------------------------------------------------------------

-- Olay dağıtılınca her alıcı cihaz için `pending` bir teslim işi yazılır ve olay "dağıtıldı"
-- işaretlenir. Gönderim veritabanı işlemi dışında yapılır: iş kısa bir işlemde süreli olarak
-- alınır (`sending`, `lease_until`), sonuç ayrı işlemde yazılır. Geçici hata yeniden denenir;
-- süreç gönderim sırasında kesilirse süre dolunca iş yeniden alınır (en az bir kez teslim;
-- sağlayıcı aynı bildirimi `collapse` anahtarıyla cihazda tekilleştirir).
ALTER TABLE push_deliveries DROP CONSTRAINT push_deliveries_status_check;
ALTER TABLE push_deliveries ADD CONSTRAINT push_deliveries_status_check
    CHECK (status IN ('pending', 'sending', 'sent', 'failed', 'cancelled'));
ALTER TABLE push_deliveries
    ADD COLUMN attempts         smallint NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 20),
    ADD COLUMN next_attempt_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN lease_until      timestamptz,
    ADD COLUMN sent_at          timestamptz,
    ADD COLUMN updated_at       timestamptz NOT NULL DEFAULT now();
UPDATE push_deliveries
   SET attempts = 1, sent_at = CASE WHEN status = 'sent' THEN created_at END;
CREATE INDEX push_deliveries_due_idx ON push_deliveries (next_attempt_at)
    WHERE status IN ('pending', 'sending');
GRANT UPDATE (status, attempts, next_attempt_at, lease_until, sent_at, updated_at)
    ON push_deliveries TO shedu_app;

-- Zamanı gelmiş teslim işleri (bütün kiracılar): bekleyenler ve süresi dolmuş alınmış işler.
-- Yalnızca kimlik döner; iş kendi kiracı bağlamında koşullu güncellemeyle alınır.
CREATE FUNCTION due_push_deliveries(max_rows integer)
    RETURNS TABLE (id bigint, organization_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT d.id, d.organization_id
      FROM public.push_deliveries d
     WHERE ((d.status = 'pending' AND d.next_attempt_at <= now())
            OR (d.status = 'sending' AND d.lease_until < now()))
       AND d.created_at > now() - interval '1 day'
     ORDER BY d.next_attempt_at
     LIMIT least(max_rows, 500)
$$;
GRANT EXECUTE ON FUNCTION due_push_deliveries(integer) TO shedu_app;

-- ---------------------------------------------------------------------------------------------
-- AI harcama rezervasyonu (AI-03)
-- ---------------------------------------------------------------------------------------------

-- Çağrıdan önce en kötü durum tahmini `reserved` satırı olarak yazılır; çağrı bitince gerçek
-- harcama `reservation_id` ile ayrı satır olarak eklenir (defter yalnızca eklenir). Toplamda
-- kapatılmış rezervasyon yerine gerçek harcama sayılır; kapatılmamış rezervasyon (süreç kesildi,
-- kayıt yazılamadı) tahminiyle sayılmaya devam eder.
ALTER TABLE ai_usage DROP CONSTRAINT ai_usage_outcome_check;
ALTER TABLE ai_usage ADD CONSTRAINT ai_usage_outcome_check
    CHECK (outcome IN ('reserved', 'success', 'refused', 'failed', 'unknown'));
ALTER TABLE ai_usage ADD COLUMN reservation_id bigint;
ALTER TABLE ai_usage ADD CONSTRAINT ai_usage_id_owner_key UNIQUE (id, organization_id, user_id);
ALTER TABLE ai_usage ADD CONSTRAINT ai_usage_reservation_fkey
    FOREIGN KEY (reservation_id, organization_id, user_id)
    REFERENCES ai_usage (id, organization_id, user_id);
ALTER TABLE ai_usage ADD CONSTRAINT ai_usage_reservation_shape
    CHECK (outcome <> 'reserved' OR reservation_id IS NULL);
CREATE UNIQUE INDEX ai_usage_reservation_key ON ai_usage (reservation_id)
    WHERE reservation_id IS NOT NULL;

CREATE OR REPLACE FUNCTION ai_spend_last_day()
    RETURNS TABLE (user_microusd bigint, org_microusd bigint, global_microusd bigint)
    LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    me  uuid := app_current_user();
    org uuid := app_current_org();
BEGIN
    IF me IS NULL OR org IS NULL THEN
        RAISE EXCEPTION 'kullanıcı ve organizasyon bağlamı gerekli'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN QUERY
    SELECT coalesce(sum(u.cost_microusd) FILTER (WHERE u.user_id = me), 0)::bigint,
           coalesce(sum(u.cost_microusd) FILTER (WHERE u.organization_id = org), 0)::bigint,
           coalesce(sum(u.cost_microusd), 0)::bigint
      FROM public.ai_usage u
     WHERE u.occurred_at > now() - interval '24 hours'
       AND NOT (u.outcome = 'reserved'
                AND EXISTS (SELECT 1 FROM public.ai_usage s WHERE s.reservation_id = u.id));
END
$$;

-- Bütçeyi denetler ve tahmini ayırır; sınır aşılıyorsa NULL döner. Bütün rezervasyonlar tek bir
-- işlem kilidiyle sıralanır: eşzamanlı çağrılar aynı boş bütçeyi iki kez ayıramaz. Kilit, çağıran
-- işlem bitene kadar tutulur; bu yüzden işlemin son adımı olmalıdır.
CREATE FUNCTION ai_reserve(feature text, estimate bigint, user_limit bigint, org_limit bigint,
                           global_limit bigint)
    RETURNS bigint
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    me  uuid := app_current_user();
    org uuid := app_current_org();
    spent record;
    reservation bigint;
BEGIN
    IF me IS NULL OR org IS NULL THEN
        RAISE EXCEPTION 'kullanıcı ve organizasyon bağlamı gerekli'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF estimate IS NULL OR estimate < 0 THEN
        RAISE EXCEPTION 'geçersiz tahmin' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('shedu.ai_budget', 0));
    SELECT * INTO spent FROM public.ai_spend_last_day();
    IF spent.user_microusd + estimate > user_limit
       OR spent.org_microusd + estimate > org_limit
       OR spent.global_microusd + estimate > global_limit THEN
        RETURN NULL;
    END IF;
    INSERT INTO public.ai_usage (organization_id, user_id, feature, model, input_tokens,
                                 output_tokens, cost_microusd, outcome)
    VALUES (org, me, feature, NULL, 0, 0, estimate, 'reserved')
    RETURNING id INTO reservation;
    RETURN reservation;
END
$$;
GRANT EXECUTE ON FUNCTION ai_reserve(text, bigint, bigint, bigint, bigint) TO shedu_app;

-- ---------------------------------------------------------------------------------------------
-- Sahiplik devri: devralan hesap etkin olmalı (AZ-03, DAT-05)
-- ---------------------------------------------------------------------------------------------

-- Silme talebi bekleyen veya kapatılmış hesap sahip yapılamaz. Hesap satırı paylaşımlı kilitlenir:
-- devralanın aynı anda başlattığı silme talebi devirden sonra sıralanır ve organizasyonun sahibi
-- olduğunu görür.
CREATE OR REPLACE FUNCTION transfer_ownership(new_owner uuid) RETURNS void
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    org uuid := app_current_org();
    actor uuid := app_current_user();
BEGIN
    IF org IS NULL OR actor IS NULL OR new_owner IS NULL OR new_owner = actor THEN
        RAISE EXCEPTION 'geçersiz devir' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM 1 FROM public.users WHERE id = new_owner AND status = 'active' FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'devralan hesap etkin değil' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    UPDATE public.memberships SET role = 'admin'
     WHERE organization_id = org AND user_id = actor AND role = 'owner';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'yalnızca sahip devredebilir' USING ERRCODE = 'insufficient_privilege';
    END IF;
    UPDATE public.memberships SET role = 'owner'
     WHERE organization_id = org AND user_id = new_owner AND role = 'admin';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'devralan kişi yönetici olmalı' USING ERRCODE = 'invalid_parameter_value';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------------------------
-- Hesap silme: oturum aileleri de silinir
-- ---------------------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION erase_account() RETURNS jsonb
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
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
    DELETE FROM session_families WHERE user_id = actor;
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

-- ---------------------------------------------------------------------------------------------
-- Takılan sanal panel komutları (BUS-01, ARC-05)
-- ---------------------------------------------------------------------------------------------

-- Süreç komutu kabul edip simülatör işini tamamlayamadan kesildiyse komut `accepted` kalır ve
-- bölümdeki bekleyen komut kısıtı sonraki komutları engeller. Düzenli tarama bunları bulur.
CREATE FUNCTION stale_simulated_commands(max_age_seconds integer, max_rows integer)
    RETURNS TABLE (id uuid, organization_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT c.id, c.organization_id
      FROM public.commands c
      JOIN public.panels p ON p.id = c.panel_id AND p.organization_id = c.organization_id
     WHERE c.status = 'accepted' AND p.simulated
       AND c.requested_at < now() - make_interval(secs => greatest(max_age_seconds, 1))
     ORDER BY c.requested_at
     LIMIT least(max_rows, 500)
$$;
GRANT EXECUTE ON FUNCTION stale_simulated_commands(integer, integer) TO shedu_app;

-- ---------------------------------------------------------------------------------------------
-- Olay kapsamı (AZ-04, AI-02)
-- ---------------------------------------------------------------------------------------------

-- Bölümsüz olay bütün panel görenlere görünür. Zon bilgisi taşıyan olay bir bölüme ait olmalı;
-- bağlantı olayları panel düzeyindedir. Yeni satırlarda zorunlu; eski satırlar dokunulmadan kalır.
ALTER TABLE panel_events ADD CONSTRAINT panel_events_zone_needs_partition
    CHECK (zone_number IS NULL OR partition_number IS NOT NULL) NOT VALID;
ALTER TABLE panel_events ADD CONSTRAINT panel_events_connectivity_is_panel_level
    CHECK (kind NOT IN ('connected', 'disconnected')
           OR (partition_number IS NULL AND zone_number IS NULL)) NOT VALID;

-- ---------------------------------------------------------------------------------------------
-- Ayrıcalıklı yordamlar (AZ-02, AZ-05)
-- ---------------------------------------------------------------------------------------------

-- Bütün SECURITY DEFINER yordamları: arama yolunda geçici şema en sonda (yoksa ilişki adlarında
-- en önce aranır ve geçici bir tablo gerçeğinin yerine geçebilir) ve PUBLIC'e kapalı. Erişim
-- yalnızca açıkça verilen rollere.
DO $$
DECLARE
    f regprocedure;
BEGIN
    FOR f IN
        SELECT p.oid::regprocedure
          FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'public' AND p.prosecdef
    LOOP
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    END LOOP;
END
$$;
