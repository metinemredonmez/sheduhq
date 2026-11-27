-- Denetim düzeltmeleri: oturum kuralı, AI rezervasyonu, push teslim kuyruğu, sahiplik devri,
-- olay kapsamı ve ayrıcalıklı yordamlar.
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
    ('bbbbbbbb-0000-0000-0000-000000000002', 'Ev B', 'home');
INSERT INTO users (id, phone, display_name, password_hash) VALUES
    ('11111111-0000-0000-0000-000000000001', '+905551110001', 'A', '$argon2id$x'),
    ('22222222-0000-0000-0000-000000000002', '+905551110002', 'B', '$argon2id$x'),
    ('33333333-0000-0000-0000-000000000003', '+905551110003', 'C', '$argon2id$x');
INSERT INTO memberships (user_id, organization_id, role) VALUES
    ('11111111-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001', 'owner'),
    ('22222222-0000-0000-0000-000000000002', 'aaaaaaaa-0000-0000-0000-000000000001', 'admin'),
    ('33333333-0000-0000-0000-000000000003', 'bbbbbbbb-0000-0000-0000-000000000002', 'owner');

-- ---------------------------------------------------------------------------------------------
-- Oturum kuralı: tek yerde, bütün koşullarıyla
-- ---------------------------------------------------------------------------------------------

INSERT INTO user_devices (id, user_id, platform) VALUES
    ('d0000000-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001', 'ios');
INSERT INTO session_families (id, user_id, device_id, created_at, revoked_at) VALUES
    ('f0000000-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001',
     'd0000000-0000-0000-0000-000000000001', now(), NULL),
    ('f0000000-0000-0000-0000-000000000002', '11111111-0000-0000-0000-000000000001', NULL, now(), now()),
    ('f0000000-0000-0000-0000-000000000003', '11111111-0000-0000-0000-000000000001', NULL,
     now() - interval '91 days', NULL),
    ('f0000000-0000-0000-0000-000000000004', '11111111-0000-0000-0000-000000000001', NULL, now(), NULL);
INSERT INTO refresh_tokens (user_id, device_id, family_id, token_hash, expires_at, used_at) VALUES
    ('11111111-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-000000000001',
     'f0000000-0000-0000-0000-000000000001', sha256('t1'::bytea), now() + interval '30 days', NULL),
    ('11111111-0000-0000-0000-000000000001', NULL,
     'f0000000-0000-0000-0000-000000000002', sha256('t2'::bytea), now() + interval '30 days', NULL),
    ('11111111-0000-0000-0000-000000000001', NULL,
     'f0000000-0000-0000-0000-000000000003', sha256('t3'::bytea), now() + interval '30 days', NULL),
    -- Ailenin tek token'ı kullanılmış: yenilenemez.
    ('11111111-0000-0000-0000-000000000001', NULL,
     'f0000000-0000-0000-0000-000000000004', sha256('t4'::bytea), now() + interval '30 days', now());

-- Yabancı anahtar: ailesi olmayan token yazılamaz.
SELECT test_expect_error(
    $q$INSERT INTO refresh_tokens (user_id, family_id, token_hash, expires_at)
       VALUES ('11111111-0000-0000-0000-000000000001', 'f0000000-0000-0000-0000-0000000000ff',
               sha256('yetim'::bytea), now() + interval '1 day')$q$,
    '23503');

DO $$
BEGIN
    ASSERT session_active('f0000000-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001'),
        'etkin aile';
    ASSERT NOT session_active('f0000000-0000-0000-0000-000000000001', '22222222-0000-0000-0000-000000000002'),
        'başkasının ailesi';
    ASSERT NOT session_active('f0000000-0000-0000-0000-000000000002', '11111111-0000-0000-0000-000000000001'),
        'iptal edilmiş aile';
    ASSERT NOT session_active('f0000000-0000-0000-0000-000000000003', '11111111-0000-0000-0000-000000000001'),
        '90 günü dolmuş aile';
    ASSERT NOT session_active('f0000000-0000-0000-0000-000000000004', '11111111-0000-0000-0000-000000000001'),
        'yenilenebilir token yok';
END
$$;

-- Uygulama aileyi yalnızca iptal edebilir (başka sütun değiştiremez).
SET LOCAL ROLE shedu_app;
SELECT test_expect_error(
    $q$UPDATE session_families SET created_at = now() WHERE id = 'f0000000-0000-0000-0000-000000000003'$q$,
    '42501');
UPDATE session_families SET revoked_at = now() WHERE id = 'f0000000-0000-0000-0000-000000000001';
DO $$
BEGIN
    ASSERT NOT session_active('f0000000-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001'),
        'iptalden sonra etkin olmamalı';
END
$$;
RESET ROLE;

UPDATE session_families SET revoked_at = NULL WHERE id = 'f0000000-0000-0000-0000-000000000001';
UPDATE users SET status = 'disabled' WHERE id = '11111111-0000-0000-0000-000000000001';
DO $$
BEGIN
    ASSERT NOT session_active('f0000000-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001'),
        'kapatılmış hesap';
END
$$;
UPDATE users SET status = 'active' WHERE id = '11111111-0000-0000-0000-000000000001';

-- ---------------------------------------------------------------------------------------------
-- AI rezervasyonu
-- ---------------------------------------------------------------------------------------------

SET LOCAL ROLE shedu_app;
SELECT set_config('app.org_id', 'aaaaaaaa-0000-0000-0000-000000000001', true),
       set_config('app.user_id', '11111111-0000-0000-0000-000000000001', true);

DO $$
DECLARE
    first bigint;
    second bigint;
    r record;
BEGIN
    -- Bütçe: kullanıcı 1000, organizasyon 5000, sistem 10000.
    first := ai_reserve('event_summary', 600, 1000, 5000, 10000);
    ASSERT first IS NOT NULL, 'ilk rezervasyon sığar';
    -- Açık rezervasyon bütçeden düşülmüş sayılır: ikinci 600 sığmaz.
    second := ai_reserve('event_summary', 600, 1000, 5000, 10000);
    ASSERT second IS NULL, 'ikinci rezervasyon kullanıcı sınırını aşar';
    SELECT * INTO r FROM ai_spend_last_day();
    ASSERT r.user_microusd = 600, format('açık rezervasyon sayılır: %s', r.user_microusd);

    -- Kapanış: gerçek harcama rezervasyonun yerine geçer.
    INSERT INTO ai_usage (organization_id, user_id, feature, model, input_tokens, output_tokens,
                          cost_microusd, outcome, reservation_id)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001',
            'event_summary', 'claude-opus-5-5', 100, 20, 80, 'success', first);
    SELECT * INTO r FROM ai_spend_last_day();
    ASSERT r.user_microusd = 80, format('kapanınca gerçek harcama: %s', r.user_microusd);
    ASSERT r.org_microusd = 80 AND r.global_microusd = 80, 'organizasyon ve sistem de';

    second := ai_reserve('event_summary', 600, 1000, 5000, 10000);
    ASSERT second IS NOT NULL, 'kapanıştan sonra bütçe açılır';
END
$$;

RESET ROLE;

-- Bir rezervasyon iki kez kapatılamaz; başkasının rezervasyonu kapatılamaz.
DO $$
DECLARE
    reservation bigint;
BEGIN
    SELECT min(id) INTO reservation FROM ai_usage WHERE outcome = 'reserved';
    BEGIN
        INSERT INTO ai_usage (organization_id, user_id, feature, input_tokens, output_tokens,
                              cost_microusd, outcome, reservation_id)
        VALUES ('aaaaaaaa-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001',
                'event_summary', 0, 0, 0, 'failed', reservation);
        RAISE EXCEPTION 'ikinci kapanış kabul edildi';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;
    -- Başka kişinin rezervasyonu kapatılamaz.
    SELECT max(id) INTO reservation FROM ai_usage WHERE outcome = 'reserved';
    BEGIN
        INSERT INTO ai_usage (organization_id, user_id, feature, input_tokens, output_tokens,
                              cost_microusd, outcome, reservation_id)
        VALUES ('aaaaaaaa-0000-0000-0000-000000000001', '22222222-0000-0000-0000-000000000002',
                'event_summary', 0, 0, 0, 'failed', reservation);
        RAISE EXCEPTION 'başkasının rezervasyonu kapatıldı';
    EXCEPTION WHEN foreign_key_violation THEN
        NULL;
    END;
    -- Rezervasyon satırı başka bir rezervasyona bağlanamaz.
    BEGIN
        INSERT INTO ai_usage (organization_id, user_id, feature, input_tokens, output_tokens,
                              cost_microusd, outcome, reservation_id)
        VALUES ('aaaaaaaa-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001',
                'event_summary', 0, 0, 0, 'reserved', reservation);
        RAISE EXCEPTION 'rezervasyon başka rezervasyona bağlandı';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END
$$;

-- Bağlam yoksa rezervasyon yapılamaz.
SET LOCAL ROLE shedu_app;
SELECT set_config('app.org_id', '', true), set_config('app.user_id', '', true);
SELECT test_expect_error($q$SELECT ai_reserve('event_summary', 1, 10, 10, 10)$q$, '42501');
RESET ROLE;

-- ---------------------------------------------------------------------------------------------
-- Push teslim kuyruğu
-- ---------------------------------------------------------------------------------------------

INSERT INTO panels (id, organization_id, name, brand, device_serial, simulated) VALUES
    ('a0000000-0000-0000-0000-0000000000a1', 'aaaaaaaa-0000-0000-0000-000000000001', 'Panel A', 'test', 'SN-A', true);
INSERT INTO partitions (id, organization_id, panel_id, number, name) VALUES
    ('a1000000-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001',
     'a0000000-0000-0000-0000-0000000000a1', 1, 'Ev');
INSERT INTO panel_events (id, organization_id, panel_id, partition_number, kind, alarm_kind, priority, occurred_at)
OVERRIDING SYSTEM VALUE VALUES
    (900001, 'aaaaaaaa-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-0000000000a1', 1,
     'alarm', 'intrusion', 'critical', now());
INSERT INTO push_deliveries (organization_id, panel_event_id, user_id, device_id, priority, status,
                             next_attempt_at, lease_until) VALUES
    ('aaaaaaaa-0000-0000-0000-000000000001', 900001, '11111111-0000-0000-0000-000000000001',
     'd0000000-0000-0000-0000-000000000001', 'critical', 'pending', now() - interval '1 second', NULL);
INSERT INTO user_devices (id, user_id, platform) VALUES
    ('d0000000-0000-0000-0000-000000000002', '22222222-0000-0000-0000-000000000002', 'android'),
    ('d0000000-0000-0000-0000-000000000003', '22222222-0000-0000-0000-000000000002', 'android');
INSERT INTO push_deliveries (organization_id, panel_event_id, user_id, device_id, priority, status,
                             next_attempt_at, lease_until) VALUES
    -- Süresi dolmuş alınmış iş (süreç gönderirken kesildi).
    ('aaaaaaaa-0000-0000-0000-000000000001', 900001, '22222222-0000-0000-0000-000000000002',
     'd0000000-0000-0000-0000-000000000002', 'critical', 'sending', now(), now() - interval '1 second'),
    -- Zamanı gelmemiş yeniden deneme.
    ('aaaaaaaa-0000-0000-0000-000000000001', 900001, '22222222-0000-0000-0000-000000000002',
     'd0000000-0000-0000-0000-000000000003', 'critical', 'pending', now() + interval '1 minute', NULL);

SET LOCAL ROLE shedu_app;
DO $$
DECLARE
    due integer;
BEGIN
    SELECT count(*) INTO due FROM due_push_deliveries(10);
    ASSERT due = 2, format('bekleyen ve süresi dolmuş iş: %s', due);
END
$$;
SELECT set_config('app.org_id', 'aaaaaaaa-0000-0000-0000-000000000001', true);
-- Uygulama yalnızca teslim durumunu güncelleyebilir; alıcıyı veya önceliği değiştiremez.
SELECT test_expect_error(
    $q$UPDATE push_deliveries SET priority = 'info'$q$, '42501');
SELECT test_expect_error(
    $q$UPDATE push_deliveries SET user_id = '33333333-0000-0000-0000-000000000003'$q$, '42501');
UPDATE push_deliveries SET status = 'sent', sent_at = now(), attempts = 1, updated_at = now()
 WHERE device_id = 'd0000000-0000-0000-0000-000000000001';
RESET ROLE;

-- ---------------------------------------------------------------------------------------------
-- Takılan sanal komut
-- ---------------------------------------------------------------------------------------------

INSERT INTO commands (organization_id, panel_id, partition_id, user_id, kind, idempotency_key, status,
                      requested_at) VALUES
    ('aaaaaaaa-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-0000000000a1',
     'a1000000-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001',
     'arm_away', 'takilan-komut-0001', 'accepted', now() - interval '5 minutes');
SET LOCAL ROLE shedu_app;
DO $$
BEGIN
    ASSERT (SELECT count(*) FROM stale_simulated_commands(30, 10)) = 1, 'eski kabul edilmiş komut';
    ASSERT (SELECT count(*) FROM stale_simulated_commands(3600, 10)) = 0, 'yeni sayılan komut';
END
$$;
RESET ROLE;

-- ---------------------------------------------------------------------------------------------
-- Olay kapsamı
-- ---------------------------------------------------------------------------------------------

SELECT test_expect_error(
    $q$INSERT INTO panel_events (organization_id, panel_id, zone_number, kind, alarm_kind, priority, occurred_at)
       VALUES ('aaaaaaaa-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-0000000000a1', 3,
               'alarm', 'intrusion', 'critical', now())$q$,
    '23514');
SELECT test_expect_error(
    $q$INSERT INTO panel_events (organization_id, panel_id, partition_number, kind, priority, occurred_at)
       VALUES ('aaaaaaaa-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-0000000000a1', 1,
               'disconnected', 'warning', now())$q$,
    '23514');

-- ---------------------------------------------------------------------------------------------
-- Sahiplik devri: devralan etkin olmalı
-- ---------------------------------------------------------------------------------------------

UPDATE users SET status = 'pending_deletion', deletion_due_at = now() + interval '30 days'
 WHERE id = '22222222-0000-0000-0000-000000000002';
SET LOCAL ROLE shedu_app;
SELECT set_config('app.org_id', 'aaaaaaaa-0000-0000-0000-000000000001', true),
       set_config('app.user_id', '11111111-0000-0000-0000-000000000001', true);
SELECT test_expect_error(
    $q$SELECT transfer_ownership('22222222-0000-0000-0000-000000000002')$q$, '22023');
RESET ROLE;
DO $$
BEGIN
    ASSERT (SELECT role FROM memberships
             WHERE user_id = '11111111-0000-0000-0000-000000000001'
               AND organization_id = 'aaaaaaaa-0000-0000-0000-000000000001') = 'owner',
        'sahiplik değişmemeli';
END
$$;

-- ---------------------------------------------------------------------------------------------
-- Ayrıcalıklı yordamlar: geçici şema en sonda, PUBLIC'e kapalı
-- ---------------------------------------------------------------------------------------------

DO $$
DECLARE
    f record;
BEGIN
    FOR f IN
        SELECT p.oid::regprocedure AS name, p.proconfig, p.proacl
          FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'public' AND p.prosecdef
    LOOP
        ASSERT 'search_path=pg_catalog, public, pg_temp' = ANY (f.proconfig),
            format('%s arama yolu: %s', f.name, f.proconfig);
        -- Boş ACL varsayılan haktır: PUBLIC çalıştırabilir.
        ASSERT f.proacl IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM aclexplode(f.proacl) a WHERE a.grantee = 0),
            format('%s PUBLIC''e açık', f.name);
    END LOOP;
END
$$;

ROLLBACK;

\echo 'denetim düzeltmeleri testleri: hepsi geçti'
