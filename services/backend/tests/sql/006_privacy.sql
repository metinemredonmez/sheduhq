-- Hesap silme ve kişisel veri dışa aktarma fonksiyonları.
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

-- A: B'nin de üyesi olduğu Ev A'nın sahibi. C: yalnızca kendisinin olduğu Ev C'nin sahibi.
INSERT INTO organizations (id, name, kind) VALUES
    ('aaaaaaaa-0000-0000-0000-000000000001', 'Ev A', 'home'),
    ('cccccccc-0000-0000-0000-000000000003', 'Ev C', 'home');
INSERT INTO users (id, phone, display_name, password_hash) VALUES
    ('11111111-0000-0000-0000-000000000001', '+905551110001', 'A', '$argon2id$x'),
    ('22222222-0000-0000-0000-000000000002', '+905551110002', 'B', '$argon2id$x'),
    ('33333333-0000-0000-0000-000000000003', '+905551110003', 'C', '$argon2id$x');
INSERT INTO memberships (user_id, organization_id, role) VALUES
    ('11111111-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001', 'owner'),
    ('22222222-0000-0000-0000-000000000002', 'aaaaaaaa-0000-0000-0000-000000000001', 'member'),
    ('33333333-0000-0000-0000-000000000003', 'cccccccc-0000-0000-0000-000000000003', 'owner');
INSERT INTO panels (id, organization_id, name, brand, device_serial) VALUES
    ('a0000000-0000-0000-0000-0000000000a1', 'aaaaaaaa-0000-0000-0000-000000000001', 'Panel A', 'test', 'SN-A'),
    ('c0000000-0000-0000-0000-0000000000c1', 'cccccccc-0000-0000-0000-000000000003', 'Panel C', 'test', 'SN-C');
INSERT INTO partitions (id, organization_id, panel_id, number, name) VALUES
    ('a1000000-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-0000000000a1', 1, 'Ev'),
    ('c1000000-0000-0000-0000-000000000001', 'cccccccc-0000-0000-0000-000000000003', 'c0000000-0000-0000-0000-0000000000c1', 1, 'Ev');
INSERT INTO access_grants (organization_id, user_id, panel_id, can_arm, always_open) VALUES
    ('aaaaaaaa-0000-0000-0000-000000000001', '22222222-0000-0000-0000-000000000002',
     'a0000000-0000-0000-0000-0000000000a1', true, true);
INSERT INTO commands (organization_id, panel_id, partition_id, user_id, kind, idempotency_key, status) VALUES
    ('aaaaaaaa-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-0000000000a1',
     'a1000000-0000-0000-0000-000000000001', '22222222-0000-0000-0000-000000000002', 'arm_away',
     'test-key-b-000000001', 'succeeded'),
    ('aaaaaaaa-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-0000000000a1',
     'a1000000-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001', 'disarm',
     'test-key-a-000000001', 'succeeded'),
    ('cccccccc-0000-0000-0000-000000000003', 'c0000000-0000-0000-0000-0000000000c1',
     'c1000000-0000-0000-0000-000000000001', '33333333-0000-0000-0000-000000000003', 'arm_away',
     'test-key-c-000000001', 'succeeded');
INSERT INTO panel_events (organization_id, panel_id, kind, alarm_kind, priority, occurred_at) VALUES
    ('cccccccc-0000-0000-0000-000000000003', 'c0000000-0000-0000-0000-0000000000c1', 'alarm', 'fire', 'critical', now());
INSERT INTO invitations (organization_id, phone, role, invited_by, expires_at) VALUES
    ('cccccccc-0000-0000-0000-000000000003', '+905551110002', 'member',
     '33333333-0000-0000-0000-000000000003', now() + interval '1 day');
INSERT INTO audit_log (organization_id, actor_user_id, action, outcome) VALUES
    ('aaaaaaaa-0000-0000-0000-000000000001', '22222222-0000-0000-0000-000000000002', 'command.created', 'success'),
    ('aaaaaaaa-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001', 'command.created', 'success');
INSERT INTO audit_log (organization_id, actor_user_id, action, target_type, target_id, outcome) VALUES
    ('aaaaaaaa-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001', 'member.role_changed',
     'user', '22222222-0000-0000-0000-000000000002', 'success');

SET LOCAL ROLE shedu_app;

-- ---------------------------------------------------------------------------------------------
-- 1. Dışa aktarma: yalnızca kendi verisi
-- ---------------------------------------------------------------------------------------------
SELECT set_config('app.user_id', '', true), set_config('app.org_id', '', true);
DO $$
BEGIN
    ASSERT (SELECT count(*) FROM privacy_my_commands(100)) = 0, 'bağlam yokken komut dönmemeli';
    ASSERT (SELECT count(*) FROM privacy_my_audit(100)) = 0, 'bağlam yokken olay dönmemeli';
END
$$;
SELECT set_config('app.user_id', '22222222-0000-0000-0000-000000000002', true);
DO $$
BEGIN
    ASSERT (SELECT count(*) FROM privacy_my_commands(100)) = 1, 'yalnızca kendi komutu';
    ASSERT (SELECT count(*) FROM privacy_my_audit(100)) = 2, 'kendi yaptığı ve ona yönelik olay';
    ASSERT (SELECT count(*) FROM privacy_my_audit(100) WHERE by_me) = 1, 'yapan ayrımı';
    ASSERT (SELECT count(*) FROM privacy_my_commands(0)) = 0, 'sınır uygulanmalı';
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 2. Silme koşulları
-- ---------------------------------------------------------------------------------------------
-- Bağlamsız çağrı ve başka üyesi olan organizasyonun sahibi reddedilir.
SELECT set_config('app.user_id', '', true);
SELECT test_expect_error($q$SELECT erase_account()$q$, '42501');
SELECT set_config('app.user_id', '11111111-0000-0000-0000-000000000001', true);
SELECT test_expect_error($q$SELECT erase_account()$q$, '23001');
-- Uygulama rolü silinmiş işaretini elle koyamaz (tanımlayıcı kalırken).
SELECT test_expect_error(
    $q$UPDATE users SET status = 'deleted', deleted_at = now()
        WHERE id = '11111111-0000-0000-0000-000000000001'$q$,
    '23514');

-- ---------------------------------------------------------------------------------------------
-- 3. Tek üyeli organizasyonun sahibi: organizasyon bütün verisiyle silinir
-- ---------------------------------------------------------------------------------------------
SELECT set_config('app.user_id', '33333333-0000-0000-0000-000000000003', true);
SELECT erase_account();
RESET ROLE;
DO $$
BEGIN
    ASSERT NOT EXISTS (SELECT 1 FROM organizations WHERE id = 'cccccccc-0000-0000-0000-000000000003'),
        'tek üyeli organizasyon silinmeli';
    ASSERT NOT EXISTS (SELECT 1 FROM panels WHERE organization_id = 'cccccccc-0000-0000-0000-000000000003'),
        'paneller silinmeli';
    ASSERT NOT EXISTS (SELECT 1 FROM commands WHERE organization_id = 'cccccccc-0000-0000-0000-000000000003'),
        'komutlar silinmeli';
    ASSERT NOT EXISTS (SELECT 1 FROM panel_events WHERE organization_id = 'cccccccc-0000-0000-0000-000000000003'),
        'olaylar silinmeli';
    ASSERT NOT EXISTS (SELECT 1 FROM invitations WHERE organization_id = 'cccccccc-0000-0000-0000-000000000003'),
        'davetler silinmeli';
    ASSERT (SELECT status = 'deleted' AND phone IS NULL AND password_hash IS NULL
                   AND display_name = 'Silinmiş kullanıcı'
              FROM users WHERE id = '33333333-0000-0000-0000-000000000003'),
        'kullanıcı kimliksizleşmeli';
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 4. Ortak organizasyonun üyesi: güvenlik kaydı kalır, kişi kimliksizleşir
-- ---------------------------------------------------------------------------------------------
SET LOCAL ROLE shedu_app;
SELECT set_config('app.user_id', '22222222-0000-0000-0000-000000000002', true);
SELECT erase_account();
-- İkinci çağrı: silinmiş hesap yok sayılır.
SELECT test_expect_error($q$SELECT erase_account()$q$, 'P0002');
RESET ROLE;
DO $$
BEGIN
    ASSERT EXISTS (SELECT 1 FROM commands WHERE user_id = '22222222-0000-0000-0000-000000000002'),
        'ortak organizasyondaki komut kaydı korunmalı';
    ASSERT NOT EXISTS (SELECT 1 FROM memberships WHERE user_id = '22222222-0000-0000-0000-000000000002'),
        'üyelik silinmeli';
    ASSERT NOT EXISTS (SELECT 1 FROM access_grants WHERE user_id = '22222222-0000-0000-0000-000000000002'),
        'yetki silinmeli';
    ASSERT NOT EXISTS (SELECT 1 FROM invitations WHERE phone = '+905551110002'),
        'numaraya gelen davet silinmeli';
    ASSERT (SELECT count(*) FROM audit_log WHERE actor_user_id = '22222222-0000-0000-0000-000000000002') = 1,
        'denetim kaydı korunmalı';
    ASSERT (SELECT phone IS NULL AND status = 'deleted' FROM users
             WHERE id = '22222222-0000-0000-0000-000000000002'),
        'kullanıcı kimliksizleşmeli';
    -- A ve organizasyonu etkilenmez.
    ASSERT (SELECT count(*) FROM memberships WHERE organization_id = 'aaaaaaaa-0000-0000-0000-000000000001') = 1,
        'sahibin üyeliği kalmalı';
    ASSERT (SELECT status FROM users WHERE id = '11111111-0000-0000-0000-000000000001') = 'active',
        'başka kullanıcı etkilenmemeli';
END
$$;

ROLLBACK;

\echo 'kişisel veri testleri: hepsi geçti'
