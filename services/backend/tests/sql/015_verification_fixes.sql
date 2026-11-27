-- Doğrulama denetimi düzeltmeleri: push alıcısı kuralı, push işlerinin bitişi, AI defterinin
-- kapanış yordamı ve sert üst sınırları, eski olay kısıtlarının doğrulanması.
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

-- Ev A: sahip (1) ve geçici yetkili üye (2). Ev B: başka bir sahip (3).
INSERT INTO organizations (id, name, kind) VALUES
    ('aaaaaaaa-0000-0000-0000-000000000001', 'Ev A', 'home'),
    ('bbbbbbbb-0000-0000-0000-000000000002', 'Ev B', 'home');
INSERT INTO users (id, phone, display_name, password_hash) VALUES
    ('11111111-0000-0000-0000-000000000001', '+905551110001', 'A', '$argon2id$x'),
    ('22222222-0000-0000-0000-000000000002', '+905551110002', 'B', '$argon2id$x'),
    ('33333333-0000-0000-0000-000000000003', '+905551110003', 'C', '$argon2id$x');
INSERT INTO memberships (user_id, organization_id, role) VALUES
    ('11111111-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001', 'owner'),
    ('22222222-0000-0000-0000-000000000002', 'aaaaaaaa-0000-0000-0000-000000000001', 'member'),
    ('33333333-0000-0000-0000-000000000003', 'bbbbbbbb-0000-0000-0000-000000000002', 'owner');
INSERT INTO panels (id, organization_id, name, brand, device_serial, simulated) VALUES
    ('a0000000-0000-0000-0000-0000000000a1', 'aaaaaaaa-0000-0000-0000-000000000001', 'Panel A', 'test', 'SN-A', true);
INSERT INTO partitions (id, organization_id, panel_id, number, name) VALUES
    ('a1000000-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001',
     'a0000000-0000-0000-0000-0000000000a1', 1, 'Ev'),
    ('a1000000-0000-0000-0000-000000000002', 'aaaaaaaa-0000-0000-0000-000000000001',
     'a0000000-0000-0000-0000-0000000000a1', 2, 'Garaj');
-- Üyenin yetkisi yalnızca 1. bölümde.
INSERT INTO access_grants (organization_id, user_id, panel_id, partition_id, can_view_events, always_open) VALUES
    ('aaaaaaaa-0000-0000-0000-000000000001', '22222222-0000-0000-0000-000000000002',
     'a0000000-0000-0000-0000-0000000000a1', 'a1000000-0000-0000-0000-000000000001', true, true);

INSERT INTO user_devices (id, user_id, platform, push_token) VALUES
    ('d0000000-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001', 'ios', 'token-1'),
    ('d0000000-0000-0000-0000-000000000002', '22222222-0000-0000-0000-000000000002', 'android', 'token-2'),
    ('d0000000-0000-0000-0000-000000000003', '33333333-0000-0000-0000-000000000003', 'android', 'token-3');
INSERT INTO session_families (id, user_id, device_id) VALUES
    ('f0000000-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-000000000001'),
    ('f0000000-0000-0000-0000-000000000002', '22222222-0000-0000-0000-000000000002', 'd0000000-0000-0000-0000-000000000002'),
    ('f0000000-0000-0000-0000-000000000003', '33333333-0000-0000-0000-000000000003', 'd0000000-0000-0000-0000-000000000003');
INSERT INTO refresh_tokens (user_id, device_id, family_id, token_hash, expires_at) VALUES
    ('11111111-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-000000000001',
     'f0000000-0000-0000-0000-000000000001', sha256('t1'::bytea), now() + interval '30 days'),
    ('22222222-0000-0000-0000-000000000002', 'd0000000-0000-0000-0000-000000000002',
     'f0000000-0000-0000-0000-000000000002', sha256('t2'::bytea), now() + interval '30 days'),
    ('33333333-0000-0000-0000-000000000003', 'd0000000-0000-0000-0000-000000000003',
     'f0000000-0000-0000-0000-000000000003', sha256('t3'::bytea), now() + interval '30 days');

-- ---------------------------------------------------------------------------------------------
-- Push alıcısı: dağıtımda ve gönderimde aynı kural
-- ---------------------------------------------------------------------------------------------

-- Uygulama rolü, dağıtıcının çalıştığı bağlamla (kullanıcısız, olayın organizasyonu).
SET LOCAL ROLE shedu_app;
SELECT set_config('app.org_id', 'aaaaaaaa-0000-0000-0000-000000000001', true),
       set_config('app.user_id', '', true);
DO $$
DECLARE
    org   uuid := 'aaaaaaaa-0000-0000-0000-000000000001';
    panel uuid := 'a0000000-0000-0000-0000-0000000000a1';
BEGIN
    ASSERT push_recipient_eligible('d0000000-0000-0000-0000-000000000001',
        '11111111-0000-0000-0000-000000000001', org, panel, 2::smallint, NULL), 'sahip her bölümü alır';
    ASSERT push_recipient_eligible('d0000000-0000-0000-0000-000000000002',
        '22222222-0000-0000-0000-000000000002', org, panel, 1::smallint, NULL), 'yetkili bölüm';
    ASSERT NOT push_recipient_eligible('d0000000-0000-0000-0000-000000000002',
        '22222222-0000-0000-0000-000000000002', org, panel, 2::smallint, NULL), 'yetkisiz bölüm';
    ASSERT NOT push_recipient_eligible('d0000000-0000-0000-0000-000000000001',
        '22222222-0000-0000-0000-000000000002', org, panel, 1::smallint, NULL), 'başkasının cihazı';
    -- Başka organizasyonun üyesi (ve RLS dışı satırı) bu organizasyonun olayını alamaz.
    ASSERT NOT push_recipient_eligible('d0000000-0000-0000-0000-000000000003',
        '33333333-0000-0000-0000-000000000003', org, panel, NULL, NULL), 'başka organizasyon';
END
$$;
RESET ROLE;

-- Kuyrukta beklerken değişen durumlar: yetki süresi dolar, kategori kapatılır, oturum iptal
-- edilir, hesap kapatılır. Her biri ayrı ayrı uygunluğu kaldırır.
CREATE FUNCTION pg_temp.member_eligible(muteable text) RETURNS boolean
    LANGUAGE sql
AS $$
    SELECT push_recipient_eligible('d0000000-0000-0000-0000-000000000002',
        '22222222-0000-0000-0000-000000000002', 'aaaaaaaa-0000-0000-0000-000000000001',
        'a0000000-0000-0000-0000-0000000000a1', 1::smallint, muteable)
$$;
DO $$
BEGIN
    ASSERT pg_temp.member_eligible(NULL), 'başlangıçta uygun';

    UPDATE access_grants SET expires_at = now() - interval '1 second', valid_from = now() - interval '1 day'
     WHERE user_id = '22222222-0000-0000-0000-000000000002';
    ASSERT NOT pg_temp.member_eligible(NULL), 'süresi dolmuş yetki';
    UPDATE access_grants SET expires_at = NULL, valid_from = NULL
     WHERE user_id = '22222222-0000-0000-0000-000000000002';

    UPDATE access_grants SET can_view_events = false WHERE user_id = '22222222-0000-0000-0000-000000000002';
    ASSERT NOT pg_temp.member_eligible(NULL), 'olay görme yetkisi kaldırılmış';
    UPDATE access_grants SET can_view_events = true WHERE user_id = '22222222-0000-0000-0000-000000000002';

    INSERT INTO notification_preferences (user_id, organization_id, category, enabled) VALUES
        ('22222222-0000-0000-0000-000000000002', 'aaaaaaaa-0000-0000-0000-000000000001', 'arming', false);
    ASSERT NOT pg_temp.member_eligible('arming'), 'kapatılmış kategori';
    ASSERT pg_temp.member_eligible(NULL), 'alarm kapatılamaz';
    DELETE FROM notification_preferences WHERE user_id = '22222222-0000-0000-0000-000000000002';

    UPDATE session_families SET revoked_at = now() WHERE id = 'f0000000-0000-0000-0000-000000000002';
    ASSERT NOT pg_temp.member_eligible(NULL), 'iptal edilmiş oturum';
    UPDATE session_families SET revoked_at = NULL WHERE id = 'f0000000-0000-0000-0000-000000000002';

    UPDATE users SET status = 'disabled' WHERE id = '22222222-0000-0000-0000-000000000002';
    ASSERT NOT pg_temp.member_eligible(NULL), 'kapatılmış hesap';
    UPDATE users SET status = 'active' WHERE id = '22222222-0000-0000-0000-000000000002';

    UPDATE user_devices SET push_token = NULL WHERE id = 'd0000000-0000-0000-0000-000000000002';
    ASSERT NOT pg_temp.member_eligible(NULL), 'token silinmiş (çıkış)';
    UPDATE user_devices SET push_token = 'token-2' WHERE id = 'd0000000-0000-0000-0000-000000000002';

    DELETE FROM access_grants WHERE user_id = '22222222-0000-0000-0000-000000000002';
    ASSERT NOT pg_temp.member_eligible(NULL), 'yetki kaldırılmış';

    ASSERT pg_temp.member_eligible(NULL) IS FALSE, 'sonuç hiçbir zaman NULL değil';
END
$$;

-- ---------------------------------------------------------------------------------------------
-- Push işlerinin bitişi
-- ---------------------------------------------------------------------------------------------

INSERT INTO panel_events (id, organization_id, panel_id, partition_number, kind, alarm_kind, priority,
                          occurred_at, received_at)
OVERRIDING SYSTEM VALUE VALUES
    (910001, 'aaaaaaaa-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-0000000000a1', 1,
     'alarm', 'intrusion', 'critical', now(), now()),
    -- Kesinti: iki gün önce alınmış ve hiç gönderilememiş.
    (910002, 'aaaaaaaa-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-0000000000a1', 1,
     'alarm', 'intrusion', 'critical', now() - interval '2 days', now() - interval '2 days');
INSERT INTO push_deliveries (organization_id, panel_event_id, user_id, device_id, priority, status,
                             attempts, next_attempt_at, lease_until, created_at) VALUES
    -- Yeni olay, bekleyen iş: dokunulmaz.
    ('aaaaaaaa-0000-0000-0000-000000000001', 910001, '11111111-0000-0000-0000-000000000001',
     'd0000000-0000-0000-0000-000000000001', 'critical', 'pending', 1, now(), NULL, now()),
    -- Yeni olay, süresi dolmuş alınmış iş, deneme hakkı bitti: kapanır.
    ('aaaaaaaa-0000-0000-0000-000000000001', 910001, '22222222-0000-0000-0000-000000000002',
     'd0000000-0000-0000-0000-000000000002', 'critical', 'sending', 6, now(), now() - interval '1 second', now()),
    -- Eski olay; iş yakın zamanda (gecikmeli dağıtımla) yazılmış olsa da yaş olaydan ölçülür.
    ('aaaaaaaa-0000-0000-0000-000000000001', 910002, '11111111-0000-0000-0000-000000000001',
     'd0000000-0000-0000-0000-000000000001', 'critical', 'pending', 0, now(), NULL, now()),
    -- Eski olay, süresi dolmamış alınmış iş: sonucu yazılmayı bekler, dokunulmaz.
    ('aaaaaaaa-0000-0000-0000-000000000001', 910002, '22222222-0000-0000-0000-000000000002',
     'd0000000-0000-0000-0000-000000000002', 'critical', 'sending', 1, now(), now() + interval '30 seconds', now());

-- Bağlamsız çağrılır (bütün kiracılar) ve yalnızca uygulama rolüne açıktır.
DO $$
BEGIN
    ASSERT NOT has_function_privilege('public', 'reap_push_deliveries(integer, integer)', 'EXECUTE'),
        'PUBLIC çalıştıramaz';
    ASSERT has_function_privilege('shedu_app', 'reap_push_deliveries(integer, integer)', 'EXECUTE'),
        'uygulama çalıştırır';
END
$$;
SET LOCAL ROLE shedu_app;
SELECT set_config('app.org_id', '', true), set_config('app.user_id', '', true);
DO $$
DECLARE
    reaped integer;
BEGIN
    reaped := reap_push_deliveries(6, 60);
    ASSERT reaped = 2, format('kapatılan iş: %s', reaped);
    ASSERT reap_push_deliveries(6, 60) = 0, 'ikinci çağrı boş';
END
$$;
RESET ROLE;
DO $$
BEGIN
    ASSERT (SELECT array_agg(status ORDER BY panel_event_id, device_id) FROM push_deliveries)
           = ARRAY['pending', 'failed', 'failed', 'sending'],
        format('durumlar: %s', (SELECT array_agg(status ORDER BY panel_event_id, device_id) FROM push_deliveries));
    ASSERT (SELECT count(*) FROM push_deliveries WHERE status = 'failed' AND lease_until IS NOT NULL) = 0,
        'kapanan işin süresi temizlenir';
END
$$;

-- Bir günden eski dağıtılmamış olay da taramaya girer (uygulama işi yazmadan kapatır).
SET LOCAL ROLE shedu_app;
DO $$
BEGIN
    ASSERT EXISTS (SELECT 1 FROM pending_panel_events(10) WHERE id = 910002), 'eski olay taranır';
    ASSERT EXISTS (SELECT 1 FROM pending_panel_events(10) WHERE id = 910001) IS FALSE,
        'beş saniyeden yeni olay canlı dağıtıma bırakılır';
END
$$;
RESET ROLE;

-- ---------------------------------------------------------------------------------------------
-- AI defteri: kapanış yordamı ve sert üst sınırlar
-- ---------------------------------------------------------------------------------------------

SET LOCAL ROLE shedu_app;
SELECT set_config('app.org_id', 'aaaaaaaa-0000-0000-0000-000000000001', true),
       set_config('app.user_id', '11111111-0000-0000-0000-000000000001', true);
-- Çağıranın verdiği sınır sert üst sınırı aşamaz: kişi başına 3 $ (3.000.000 µ$).
SELECT test_expect_error($q$SELECT ai_settle(NULL, NULL, 0, 0, 0, 'success')$q$, '42501');
DO $$
DECLARE
    mine bigint;
BEGIN
    ASSERT ai_reserve('event_summary', 3000001, 1000000000000, 1000000000000, 1000000000000) IS NULL,
        'kişi sert üst sınırı';
    mine := ai_reserve('event_summary', 1000, 1000000000000, 1000000000000, 1000000000000);
    ASSERT mine IS NOT NULL, 'sınır içinde';
    PERFORM set_config('test.mine', mine::text, true);
END
$$;
-- Geçersiz sonuç.
SELECT test_expect_error(
    format($q$SELECT ai_settle(%s, 'm', 0, 0, 0, 'reserved')$q$, current_setting('test.mine')), '22023');
-- Başka kişi aynı organizasyonda bile bu rezervasyonu kapatamaz.
SELECT set_config('app.user_id', '22222222-0000-0000-0000-000000000002', true);
SELECT test_expect_error(
    format($q$SELECT ai_settle(%s, 'm', 0, 0, 0, 'failed')$q$, current_setting('test.mine')), '42501');
-- Başka organizasyon bağlamında da kapatılamaz.
SELECT set_config('app.user_id', '11111111-0000-0000-0000-000000000001', true),
       set_config('app.org_id', 'bbbbbbbb-0000-0000-0000-000000000002', true);
SELECT test_expect_error(
    format($q$SELECT ai_settle(%s, 'm', 0, 0, 0, 'failed')$q$, current_setting('test.mine')), '42501');
SELECT set_config('app.org_id', 'aaaaaaaa-0000-0000-0000-000000000001', true);
-- Kapanış bir kez; ikincisi benzersizlik kısıtına takılır.
SELECT ai_settle(current_setting('test.mine')::bigint, 'claude-opus-5-5', 10, 5, 400, 'success');
SELECT test_expect_error(
    format($q$SELECT ai_settle(%s, 'm', 0, 0, 0, 'failed')$q$, current_setting('test.mine')), '23505');
DO $$
DECLARE
    r record;
BEGIN
    SELECT * INTO r FROM ai_spend_last_day();
    ASSERT r.user_microusd = 400, format('kapanınca gerçek harcama: %s', r.user_microusd);
END
$$;
RESET ROLE;
DO $$
BEGIN
    ASSERT (SELECT feature FROM ai_usage WHERE reservation_id = current_setting('test.mine')::bigint)
           = 'event_summary', 'kapanış rezervasyonun özelliğiyle yazılır';
END
$$;

-- ---------------------------------------------------------------------------------------------
-- Eski olay kısıtları doğrulanmış
-- ---------------------------------------------------------------------------------------------

DO $$
BEGIN
    ASSERT (SELECT bool_and(convalidated) FROM pg_constraint
             WHERE conrelid = 'panel_events'::regclass
               AND conname IN ('panel_events_zone_needs_partition',
                               'panel_events_connectivity_is_panel_level')), 'kısıtlar doğrulanmış';
END
$$;

ROLLBACK;

\echo 'doğrulama düzeltmeleri testleri: hepsi geçti'
