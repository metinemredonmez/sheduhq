-- Sahiplik, üyelik-yetki bağı ve davet izolasyonu.
\set ON_ERROR_STOP on

BEGIN;

CREATE FUNCTION public.test_expect_error(stmt text, expected text) RETURNS void
    LANGUAGE plpgsql
AS $$
BEGIN
    BEGIN
        EXECUTE stmt;
    EXCEPTION WHEN OTHERS THEN
        IF SQLSTATE = expected THEN
            RETURN;
        END IF;
        RAISE EXCEPTION 'beklenen SQLSTATE %, gelen % (%): %', expected, SQLSTATE, SQLERRM, stmt;
    END;
    RAISE EXCEPTION 'hata bekleniyordu (%): %', expected, stmt;
END
$$;

INSERT INTO organizations (id, name, kind) VALUES
    ('aaaaaaaa-0000-0000-0000-000000000001', 'Ev A', 'home'),
    ('bbbbbbbb-0000-0000-0000-000000000002', 'Şirket B', 'business'),
    ('cccccccc-0000-0000-0000-000000000003', 'Silinecek C', 'home');
INSERT INTO users (id, phone, display_name) VALUES
    ('11111111-0000-0000-0000-000000000001', '+905551110001', 'Sahip'),
    ('22222222-0000-0000-0000-000000000002', '+905551110002', 'Üye'),
    ('33333333-0000-0000-0000-000000000003', '+905551110003', 'Davetli'),
    ('44444444-0000-0000-0000-000000000004', '+905551110004', 'Başkası');
INSERT INTO memberships (user_id, organization_id, role) VALUES
    ('11111111-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001', 'owner'),
    ('22222222-0000-0000-0000-000000000002', 'aaaaaaaa-0000-0000-0000-000000000001', 'member'),
    ('44444444-0000-0000-0000-000000000004', 'bbbbbbbb-0000-0000-0000-000000000002', 'owner'),
    ('11111111-0000-0000-0000-000000000001', 'cccccccc-0000-0000-0000-000000000003', 'owner');
INSERT INTO panels (id, organization_id, name, brand, device_serial) VALUES
    ('a0000000-0000-0000-0000-0000000000a1', 'aaaaaaaa-0000-0000-0000-000000000001', 'Ev paneli', 'test', 'SN-A');
INSERT INTO invitations (id, organization_id, phone, role, invited_by, expires_at) VALUES
    ('d0000000-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001', '+905551110003',
     'member', '11111111-0000-0000-0000-000000000001', now() + interval '7 days'),
    ('d0000000-0000-0000-0000-000000000002', 'bbbbbbbb-0000-0000-0000-000000000002', '+905551110009',
     'member', '44444444-0000-0000-0000-000000000004', now() + interval '7 days');

-- ---------------------------------------------------------------------------------------------
-- 1. Sahiplik (AZ-05)
-- ---------------------------------------------------------------------------------------------
SET LOCAL ROLE shedu_app;

-- İkinci sahip olamaz.
SELECT public.test_expect_error(
    $q$UPDATE memberships SET role = 'owner'
        WHERE user_id = '22222222-0000-0000-0000-000000000002'
          AND organization_id = 'aaaaaaaa-0000-0000-0000-000000000001'$q$,
    '23505');
-- Sahibin rolü düşürülemez, üyeliği silinemez.
SELECT public.test_expect_error(
    $q$UPDATE memberships SET role = 'admin'
        WHERE user_id = '11111111-0000-0000-0000-000000000001'
          AND organization_id = 'aaaaaaaa-0000-0000-0000-000000000001'$q$,
    '23001');
SELECT public.test_expect_error(
    $q$DELETE FROM memberships
        WHERE user_id = '11111111-0000-0000-0000-000000000001'
          AND organization_id = 'aaaaaaaa-0000-0000-0000-000000000001'$q$,
    '23001');

-- ---------------------------------------------------------------------------------------------
-- 2. Yetki yalnızca üyeye; üyelik silinince yetki de silinir (AZ-04, SES-04)
-- ---------------------------------------------------------------------------------------------
SELECT set_config('app.org_id', 'aaaaaaaa-0000-0000-0000-000000000001', true);

-- Üye olmayan kullanıcıya yetki verilemez.
SELECT public.test_expect_error(
    $q$INSERT INTO access_grants (organization_id, user_id, panel_id)
       VALUES ('aaaaaaaa-0000-0000-0000-000000000001', '33333333-0000-0000-0000-000000000003',
               'a0000000-0000-0000-0000-0000000000a1')$q$,
    '23503');

INSERT INTO access_grants (organization_id, user_id, panel_id, can_disarm, always_open)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000001', '22222222-0000-0000-0000-000000000002',
            'a0000000-0000-0000-0000-0000000000a1', true, true);
DELETE FROM memberships
 WHERE user_id = '22222222-0000-0000-0000-000000000002'
   AND organization_id = 'aaaaaaaa-0000-0000-0000-000000000001';
DO $$
BEGIN
    ASSERT NOT EXISTS (SELECT 1 FROM access_grants
                        WHERE user_id = '22222222-0000-0000-0000-000000000002'),
        'üyelik silinince yetkiler de silinmeli';
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 3. Davet izolasyonu (AZ-02)
-- ---------------------------------------------------------------------------------------------
-- Organizasyon bağlamında yalnızca kendi davetleri görünür.
DO $$
BEGIN
    ASSERT (SELECT count(*) FROM invitations) = 1, 'A yalnızca kendi davetini görmeli';
END
$$;
-- Başka organizasyon adına davet oluşturulamaz.
SELECT public.test_expect_error(
    $q$INSERT INTO invitations (organization_id, phone, role, expires_at)
       VALUES ('bbbbbbbb-0000-0000-0000-000000000002', '+905551110005', 'member', now() + interval '1 day')$q$,
    '42501');
-- Davetin kapsamı değiştirilemez.
SELECT public.test_expect_error(
    $q$UPDATE invitations SET role = 'admin' WHERE id = 'd0000000-0000-0000-0000-000000000001'$q$,
    '42501');
-- Sahiplik davetle verilemez; 7 günden uzun davet olamaz.
SELECT public.test_expect_error(
    $q$INSERT INTO invitations (organization_id, phone, role, expires_at)
       VALUES ('aaaaaaaa-0000-0000-0000-000000000001', '+905551110005', 'owner', now() + interval '1 day')$q$,
    '23514');
SELECT public.test_expect_error(
    $q$INSERT INTO invitations (organization_id, phone, role, expires_at)
       VALUES ('aaaaaaaa-0000-0000-0000-000000000001', '+905551110005', 'member', now() + interval '8 days')$q$,
    '23514');
-- Aynı numaraya ikinci açık davet olamaz.
SELECT public.test_expect_error(
    $q$INSERT INTO invitations (organization_id, phone, role, expires_at)
       VALUES ('aaaaaaaa-0000-0000-0000-000000000001', '+905551110003', 'admin', now() + interval '1 day')$q$,
    '23505');

-- Davetli: organizasyon bağlamı yok; yalnızca kendi numarasına gelen davet ve o organizasyonun adı.
SELECT set_config('app.org_id', '', true),
       set_config('app.user_id', '33333333-0000-0000-0000-000000000003', true);
DO $$
DECLARE
    n integer;
BEGIN
    ASSERT (SELECT count(*) FROM invitations) = 1, 'davetli yalnızca kendi davetini görmeli';
    ASSERT (SELECT name FROM organizations) = 'Ev A', 'davetli yalnızca davet eden organizasyonu görmeli';
    ASSERT NOT EXISTS (SELECT 1 FROM panels), 'davetli panel görmemeli';

    -- Başkasının daveti yanıtlanamaz.
    UPDATE invitations SET accepted_at = now() WHERE id = 'd0000000-0000-0000-0000-000000000002';
    GET DIAGNOSTICS n = ROW_COUNT;
    ASSERT n = 0, 'başkasının daveti kabul edilememeli';

    UPDATE invitations SET declined_at = now() WHERE id = 'd0000000-0000-0000-0000-000000000001';
    GET DIAGNOSTICS n = ROW_COUNT;
    ASSERT n = 1, 'davetli kendi davetini yanıtlayabilmeli';

    -- Yanıtlanan davetin organizasyonu artık görünmez.
    ASSERT (SELECT count(*) FROM organizations) = 0, 'yanıtlanan davetin organizasyonu görünmemeli';
END
$$;
-- Davet bir kez sonuçlanır.
SELECT public.test_expect_error(
    $q$UPDATE invitations SET accepted_at = now() WHERE id = 'd0000000-0000-0000-0000-000000000001'$q$,
    '23514');

-- Bağlamı olmayan biri hiçbir daveti göremez.
SELECT set_config('app.user_id', '', true);
DO $$
BEGIN
    ASSERT (SELECT count(*) FROM invitations) = 0, 'bağlam yokken davet görünmemeli';
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 4. Zincirleme silme sahip korumasına takılmaz
-- ---------------------------------------------------------------------------------------------
RESET ROLE;
DELETE FROM organizations WHERE id = 'cccccccc-0000-0000-0000-000000000003';
DO $$
BEGIN
    ASSERT NOT EXISTS (SELECT 1 FROM memberships
                        WHERE organization_id = 'cccccccc-0000-0000-0000-000000000003'),
        'organizasyon silinince sahip üyeliği de silinmeli';
END
$$;

ROLLBACK;

\echo 'üyelik ve davet testleri: hepsi geçti'
