-- Doğrulama denetimi düzeltmeleri (27 Kasım 2026): eski verinin güvenli yöne çekilmesi, push
-- alıcısının gönderim anında yeniden denetlenmesi, push işlerinin bitiş durumu, AI defterine
-- yazmanın dar bir yordama taşınması.

-- ---------------------------------------------------------------------------------------------
-- Eski oturum aileleri (SES-04)
-- ---------------------------------------------------------------------------------------------

-- İptal her zaman bütün aileyi kapatır; yenileme token'ı iptal etmez, yalnızca kullanır. Ailede
-- iptal edilmiş bir token varsa aile iptal edilmiştir: 0016 öncesi bir yarış ailede iptal
-- edilmemiş bir token bıraktıysa aile ve kalan token'lar burada kapanır (güvenli yön).
UPDATE session_families f
   SET revoked_at = r.revoked_at
  FROM (SELECT family_id, max(revoked_at) AS revoked_at
          FROM refresh_tokens WHERE revoked_at IS NOT NULL GROUP BY family_id) r
 WHERE f.id = r.family_id AND f.revoked_at IS NULL;
UPDATE refresh_tokens t
   SET revoked_at = f.revoked_at
  FROM session_families f
 WHERE t.family_id = f.id AND f.revoked_at IS NOT NULL AND t.revoked_at IS NULL;

-- ---------------------------------------------------------------------------------------------
-- Eski olayların kapsamı (AZ-04)
-- ---------------------------------------------------------------------------------------------

-- 0016'daki kısıtlar eski satırları denetlemiyordu; eski uyumsuz bir satır güncellenirken
-- (ör. dağıtıldı işareti) kısıta takılabilirdi. Eski satırlar düzeltilir ve kısıtlar doğrulanır.
-- Bağlantı olayı panel düzeyindedir.
UPDATE panel_events
   SET partition_number = NULL, zone_number = NULL
 WHERE kind IN ('connected', 'disconnected')
   AND (partition_number IS NOT NULL OR zone_number IS NOT NULL);
-- Bölümsüz zon olayı: zon tek bir bölümdeyse o bölüme bağlanır.
UPDATE panel_events e
   SET partition_number = p.number
  FROM zones z
  JOIN zone_partitions zp ON zp.zone_id = z.id
  JOIN partitions p ON p.id = zp.partition_id
 WHERE e.partition_number IS NULL AND e.zone_number IS NOT NULL
   AND z.panel_id = e.panel_id AND z.number = e.zone_number
   AND (SELECT count(*) FROM zone_partitions x WHERE x.zone_id = z.id) = 1;
-- Kalan satırın bölümü bilinemez. Panel geneli saymak (bütün panel görenlere göstermek) yetkiyi
-- genişletir; bu yüzden göç durur ve satırlar elle incelenir.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM panel_events WHERE zone_number IS NOT NULL AND partition_number IS NULL) THEN
        RAISE EXCEPTION 'bölümü belirlenemeyen zon olayları var; panel_events elle düzeltilmeli'
            USING ERRCODE = 'check_violation';
    END IF;
END
$$;
ALTER TABLE panel_events VALIDATE CONSTRAINT panel_events_zone_needs_partition;
ALTER TABLE panel_events VALIDATE CONSTRAINT panel_events_connectivity_is_panel_level;

-- ---------------------------------------------------------------------------------------------
-- Push alıcısı: tek kural, dağıtımda ve gönderimde (AZ-04, SES-04)
-- ---------------------------------------------------------------------------------------------

-- Bu cihaz bu olayın bildirimini şu an alabilir mi? Dağıtımda alıcılar bununla seçilir ve
-- gönderimden hemen önce yeniden denetlenir: kuyrukta beklerken üyeliği, yetkisi, oturumu veya
-- ikinci adımı düşen kişiye bildirim gitmez. Çağıranın kiracı bağlamıyla çalışır (RLS geçerli).
-- `muteable`: kişinin kapatabildiği kategori (alarmda NULL; alarm kapatılamaz).
CREATE FUNCTION push_recipient_eligible(device uuid, account uuid, org uuid, panel uuid,
                                        partition smallint, muteable text)
    RETURNS boolean
    LANGUAGE sql
    STABLE
    SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1
          FROM public.user_devices d
          JOIN public.memberships m ON m.user_id = d.user_id AND m.organization_id = org
          JOIN public.organizations o ON o.id = m.organization_id
          JOIN public.users u ON u.id = d.user_id AND u.status = 'active'
         WHERE d.id = device AND d.user_id = account AND d.push_token IS NOT NULL
           -- Kişinin kapattığı kategori.
           AND (muteable IS NULL OR NOT EXISTS (
                  SELECT 1 FROM public.notification_preferences np
                   WHERE np.user_id = d.user_id AND np.organization_id = org
                     AND np.category = muteable AND NOT np.enabled))
           -- Cihazın oturumu etkin (HTTP ile aynı kural); personel cihazı yalnızca ikinci adımı
           -- tamamlanmış oturumla (AUT-01; kural authz::mfa_required ile aynı).
           AND EXISTS (
                  SELECT 1 FROM public.session_families f
                   WHERE f.device_id = d.id AND f.user_id = d.user_id
                     AND public.session_active(f.id, f.user_id)
                     AND (o.kind NOT IN ('business', 'monitoring_center')
                          OR m.role NOT IN ('owner', 'admin', 'operator')
                          OR EXISTS (SELECT 1 FROM public.session_factors sf
                                      WHERE sf.family_id = f.id AND sf.user_id = d.user_id)))
           -- Yönetici veya o panelde (bölümünde) geçerli görme yetkisi.
           AND (m.role IN ('owner', 'admin', 'operator') OR EXISTS (
                  SELECT 1 FROM public.access_grants g
                   WHERE g.user_id = d.user_id AND g.panel_id = panel AND g.organization_id = org
                     AND g.can_view_events
                     AND (g.valid_from IS NULL OR g.valid_from <= now())
                     AND (g.expires_at IS NULL OR g.expires_at > now())
                     AND (g.partition_id IS NULL OR partition IS NULL
                          OR g.partition_id = (SELECT p.id FROM public.partitions p
                                                WHERE p.panel_id = panel AND p.number = partition)))))
$$;

-- ---------------------------------------------------------------------------------------------
-- Push işlerinin bitiş durumu (BUS-02)
-- ---------------------------------------------------------------------------------------------

-- Deneme hakkı biten veya olayı çok eskimiş iş (bekleyen ya da süresi dolmuş alınmış) `failed`
-- olur. Yaş olayın alınma zamanından ölçülür, tarama penceresiyle sınırlı değildir: uzun bir
-- kesintiden sonra da hiçbir iş yarı yolda kalmaz. Bütün kiracılarda çalışır; yalnızca durum
-- değiştirir ve kapatılan iş sayısını döner.
CREATE FUNCTION reap_push_deliveries(max_attempts integer, max_age_minutes integer)
    RETURNS integer
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
    WITH reaped AS (
        UPDATE public.push_deliveries d
           SET status = 'failed', lease_until = NULL, updated_at = now()
          FROM public.panel_events e
         WHERE e.id = d.panel_event_id AND e.organization_id = d.organization_id
           AND (d.status = 'pending' OR (d.status = 'sending' AND d.lease_until < now()))
           AND (d.attempts >= greatest(max_attempts, 1)
                OR e.received_at < now() - make_interval(mins => greatest(max_age_minutes, 1)))
        RETURNING d.id
    )
    SELECT count(*)::integer FROM reaped
$$;
GRANT EXECUTE ON FUNCTION reap_push_deliveries(integer, integer) TO shedu_app;

-- Dağıtılmamış olaylar artık bir günlük pencereyle sınırlı değil: uzun kesintiden sonra da her olay
-- bir kez ele alınır. Çok eski olay için iş yazılmaz, olay yalnızca dağıtıldı işaretlenir
-- (uygulamadaki yaş sınırı). Kısmi indeks yalnızca dağıtılmamış satırları tutar.
CREATE OR REPLACE FUNCTION pending_panel_events(max_rows integer)
    RETURNS TABLE (id bigint, organization_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT e.id, e.organization_id
      FROM public.panel_events e
     WHERE e.notified_at IS NULL
       AND e.received_at < now() - interval '5 seconds'
     ORDER BY e.received_at
     LIMIT least(max_rows, 500)
$$;

-- ---------------------------------------------------------------------------------------------
-- AI defteri: yazma yalnızca rezervasyon ve kapanış yordamlarıyla (AI-03)
-- ---------------------------------------------------------------------------------------------

-- Uygulama deftere doğrudan satır ekleyemez. Rezervasyon `ai_reserve`, kapanış `ai_settle` ile:
-- kapanış yalnızca kişinin kendi, açık, aynı özellikteki rezervasyonuna bağlanır.
REVOKE INSERT ON ai_usage FROM shedu_app;

-- Sınırlar çağırandan gelir ama sert üst sınırları aşamaz: ele geçirilmiş bir uygulama bütçeyi
-- bu değerlerin üstüne çıkaramaz (kullanıcı 3 $, organizasyon 10 $, sistem 100.000 $ / 24 saat;
-- sistem üst sınırı yapılandırmanın izin verdiği en büyük değerdir).
CREATE OR REPLACE FUNCTION ai_reserve(feature text, estimate bigint, user_limit bigint,
                                      org_limit bigint, global_limit bigint)
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
    user_limit := least(coalesce(user_limit, 0), 3000000);
    org_limit := least(coalesce(org_limit, 0), 10000000);
    global_limit := least(coalesce(global_limit, 0), 100000000000);
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

-- Rezervasyonu gerçek (veya bilinmiyorsa tahmini) harcamayla kapatır. Yalnızca bağlamdaki
-- kullanıcının ve organizasyonun açık rezervasyonu kapatılabilir; ikinci kapanış benzersizlik
-- kısıtına takılır.
CREATE FUNCTION ai_settle(reservation bigint, model text, input_tokens bigint,
                          output_tokens bigint, cost bigint, outcome text)
    RETURNS void
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    me  uuid := app_current_user();
    org uuid := app_current_org();
    reserved_feature text;
BEGIN
    IF me IS NULL OR org IS NULL THEN
        RAISE EXCEPTION 'kullanıcı ve organizasyon bağlamı gerekli'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF outcome IS NULL OR outcome NOT IN ('success', 'refused', 'failed', 'unknown') THEN
        RAISE EXCEPTION 'geçersiz sonuç' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT u.feature INTO reserved_feature
      FROM public.ai_usage u
     WHERE u.id = reservation AND u.outcome = 'reserved'
       AND u.user_id = me AND u.organization_id = org;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'rezervasyon bulunamadı' USING ERRCODE = 'insufficient_privilege';
    END IF;
    INSERT INTO public.ai_usage (organization_id, user_id, feature, model, input_tokens,
                                 output_tokens, cost_microusd, outcome, reservation_id)
    VALUES (org, me, reserved_feature, model, input_tokens, output_tokens, cost, outcome,
            reservation);
END
$$;
GRANT EXECUTE ON FUNCTION ai_settle(bigint, text, bigint, bigint, bigint, text) TO shedu_app;

-- Yeni ayrıcalıklı yordamlar da PUBLIC'e kapalı (arama yolu tanımlarında).
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
