-- Şema güvenlik ve bütünlük testleri. Süper kullanıcıyla, migration'lardan sonra çalıştırılır.
-- Her şey tek bir işlemde yapılır ve sonunda geri alınır; veritabanında iz kalmaz.
\set ON_ERROR_STOP on

BEGIN;

-- Bir ifadenin belirli bir SQLSTATE ile hata vermesini bekler.
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

-- ---------------------------------------------------------------------------------------------
-- Test verisi (süper kullanıcı RLS'ye takılmaz)
-- ---------------------------------------------------------------------------------------------
INSERT INTO organizations (id, name, kind) VALUES
    ('aaaaaaaa-0000-0000-0000-000000000001', 'Ev A', 'home'),
    ('bbbbbbbb-0000-0000-0000-000000000002', 'Şirket B', 'business');

INSERT INTO users (id, email, display_name) VALUES
    ('11111111-0000-0000-0000-000000000001', 'a@example.com', 'Kullanıcı A');

INSERT INTO panels (id, organization_id, name, brand, device_serial) VALUES
    ('a0000000-0000-0000-0000-0000000000a1', 'aaaaaaaa-0000-0000-0000-000000000001', 'Ev paneli', 'test', 'SN-A'),
    ('b0000000-0000-0000-0000-0000000000b1', 'bbbbbbbb-0000-0000-0000-000000000002', 'Ofis paneli', 'test', 'SN-B');

INSERT INTO partitions (id, organization_id, panel_id, number, name) VALUES
    ('a1000000-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-0000000000a1', 1, 'Ev'),
    ('b1000000-0000-0000-0000-000000000001', 'bbbbbbbb-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-0000000000b1', 1, 'Ofis');

INSERT INTO zones (id, organization_id, panel_id, number, name) VALUES
    ('a2000000-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-0000000000a1', 1, 'Ön kapı');

-- ---------------------------------------------------------------------------------------------
-- 1. Varsayılanlar güvenli tarafta
-- ---------------------------------------------------------------------------------------------
DO $$
BEGIN
    ASSERT (SELECT connectivity FROM panels WHERE device_serial = 'SN-A') = 'offline',
        'yeni panel varsayılan olarak çevrimdışı olmalı';
    ASSERT NOT (SELECT ready_to_arm FROM panels WHERE device_serial = 'SN-A'),
        'yeni panel varsayılan olarak kurulmaya hazır olmamalı';
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 2. Kiracı bağlamı olmadan hiçbir şey görünmez (fail-closed)
-- ---------------------------------------------------------------------------------------------
SET LOCAL ROLE shedu_app;
SELECT set_config('app.org_id', '', true);
DO $$
BEGIN
    ASSERT (SELECT count(*) FROM panels) = 0, 'bağlam yokken panel görünmemeli';
    ASSERT (SELECT count(*) FROM organizations) = 0, 'bağlam yokken organizasyon görünmemeli';
    ASSERT (SELECT count(*) FROM partitions) = 0, 'bağlam yokken bölüm görünmemeli';
END
$$;

-- Geçersiz kiracı değeri sızıntı değil, hata üretir.
SELECT set_config('app.org_id', 'gecersiz', true);
SELECT test_expect_error('SELECT count(*) FROM panels', '22P02');

-- ---------------------------------------------------------------------------------------------
-- 3. Kiracı A yalnızca kendi verisini görür ve değiştirebilir
-- ---------------------------------------------------------------------------------------------
SELECT set_config('app.org_id', 'aaaaaaaa-0000-0000-0000-000000000001', true);
DO $$
DECLARE
    n integer;
BEGIN
    ASSERT (SELECT count(*) FROM panels) = 1, 'A yalnızca kendi panelini görmeli';
    ASSERT (SELECT device_serial FROM panels) = 'SN-A', 'A, B''nin panelini görmemeli';
    ASSERT (SELECT count(*) FROM organizations) = 1, 'A yalnızca kendi organizasyonunu görmeli';

    UPDATE panels SET name = 'ele geçirildi' WHERE device_serial = 'SN-B';
    GET DIAGNOSTICS n = ROW_COUNT;
    ASSERT n = 0, 'A, B''nin panelini güncelleyememeli';
END
$$;

-- Başka bir kiracı adına kayıt eklenemez.
SELECT test_expect_error(
    $q$INSERT INTO panels (organization_id, name, brand, device_serial)
       VALUES ('bbbbbbbb-0000-0000-0000-000000000002', 'sahte', 'test', 'SN-X')$q$,
    '42501');

-- ---------------------------------------------------------------------------------------------
-- 4. Komutlar: tekrar anahtarı ve bölüm başına tek yoldaki komut (BUS-02)
-- ---------------------------------------------------------------------------------------------
INSERT INTO commands (id, organization_id, panel_id, partition_id, user_id, kind, idempotency_key) VALUES
    ('c0000000-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001',
     'a0000000-0000-0000-0000-0000000000a1', 'a1000000-0000-0000-0000-000000000001',
     '11111111-0000-0000-0000-000000000001', 'arm_away', 'anahtar-0000000001');

-- Aynı bölüme ikinci bir komut, ilki yoldayken reddedilir.
SELECT test_expect_error(
    $q$INSERT INTO commands (organization_id, panel_id, partition_id, user_id, kind, idempotency_key)
       VALUES ('aaaaaaaa-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-0000000000a1',
               'a1000000-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001',
               'disarm', 'anahtar-0000000002')$q$,
    '23505');

-- Aynı tekrar anahtarı ikinci kez kullanılamaz.
UPDATE commands SET status = 'succeeded', completed_at = now()
    WHERE id = 'c0000000-0000-0000-0000-000000000001';
SELECT test_expect_error(
    $q$INSERT INTO commands (organization_id, panel_id, partition_id, user_id, kind, idempotency_key)
       VALUES ('aaaaaaaa-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-0000000000a1',
               'a1000000-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001',
               'disarm', 'anahtar-0000000001')$q$,
    '23505');

-- İlki tamamlandıktan sonra yeni anahtarla yeni komut kabul edilir.
INSERT INTO commands (organization_id, panel_id, partition_id, user_id, kind, idempotency_key) VALUES
    ('aaaaaaaa-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-0000000000a1',
     'a1000000-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001',
     'disarm', 'anahtar-0000000003');

-- Bypass komutu zon listesi olmadan, reddedilen komut gerekçe olmadan kaydedilemez.
SELECT test_expect_error(
    $q$INSERT INTO commands (organization_id, panel_id, partition_id, user_id, kind, idempotency_key)
       VALUES ('aaaaaaaa-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-0000000000a1',
               'a1000000-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001',
               'bypass_zones', 'anahtar-0000000004')$q$,
    '23514');
SELECT test_expect_error(
    $q$UPDATE commands SET status = 'rejected' WHERE idempotency_key = 'anahtar-0000000003'$q$,
    '23514');

-- Uygulama rolü komut silemez, olay güncelleyemez.
SELECT test_expect_error($q$DELETE FROM commands$q$, '42501');
SELECT test_expect_error($q$UPDATE panel_events SET priority = 'info'$q$, '42501');

-- ---------------------------------------------------------------------------------------------
-- 5. Denetim kaydı
-- ---------------------------------------------------------------------------------------------
INSERT INTO audit_log (organization_id, actor_user_id, action, outcome)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001', 'command.arm_away', 'success');
-- Kiracısız kimlik olayı eklenebilir ama uygulama tarafından okunamaz.
INSERT INTO audit_log (action, outcome) VALUES ('auth.login_failed', 'failure');
DO $$
BEGIN
    ASSERT (SELECT count(*) FROM audit_log) = 1, 'A yalnızca kendi denetim kaydını görmeli';
END
$$;
-- Başka kiracı adına denetim kaydı yazılamaz.
SELECT test_expect_error(
    $q$INSERT INTO audit_log (organization_id, action, outcome)
       VALUES ('bbbbbbbb-0000-0000-0000-000000000002', 'command.disarm', 'success')$q$,
    '42501');

RESET ROLE;

-- Süper kullanıcı bile denetim kaydını değiştiremez veya silemez.
SELECT test_expect_error($q$UPDATE audit_log SET outcome = 'failure'$q$, 'P0001');
SELECT test_expect_error($q$DELETE FROM audit_log$q$, 'P0001');

-- ---------------------------------------------------------------------------------------------
-- 6. Kiracılar arası bağlantı veritabanı düzeyinde imkânsız (AZ-04)
-- ---------------------------------------------------------------------------------------------
-- A'nın paneline B adına bölüm eklenemez.
SELECT test_expect_error(
    $q$INSERT INTO partitions (organization_id, panel_id, number, name)
       VALUES ('bbbbbbbb-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-0000000000a1', 2, 'sahte')$q$,
    '23503');
-- A'nın zonu B'nin bölümüne bağlanamaz.
SELECT test_expect_error(
    $q$INSERT INTO zone_partitions (organization_id, panel_id, zone_id, partition_id)
       VALUES ('aaaaaaaa-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-0000000000a1',
               'a2000000-0000-0000-0000-000000000001', 'b1000000-0000-0000-0000-000000000001')$q$,
    '23503');
-- A'nın panelindeki yetki, B'nin bölümünü hedefleyemez.
SELECT test_expect_error(
    $q$INSERT INTO access_grants (organization_id, user_id, panel_id, partition_id)
       VALUES ('aaaaaaaa-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001',
               'a0000000-0000-0000-0000-0000000000a1', 'b1000000-0000-0000-0000-000000000001')$q$,
    '23503');

-- ---------------------------------------------------------------------------------------------
-- 7. Diğer bütünlük kuralları
-- ---------------------------------------------------------------------------------------------
-- Doğrulama kodu 15 dakikadan uzun geçerli olamaz.
SELECT test_expect_error(
    $q$INSERT INTO verification_codes (purpose, phone, code_hash, expires_at)
       VALUES ('register', '+905551112233', decode(repeat('ab', 32), 'hex'), now() + interval '20 minutes')$q$,
    '23514');
-- Alarm olayı kritik olmak zorunda.
SELECT test_expect_error(
    $q$INSERT INTO panel_events (organization_id, panel_id, kind, alarm_kind, priority, occurred_at)
       VALUES ('aaaaaaaa-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-0000000000a1',
               'alarm', 'fire', 'info', now())$q$,
    '23514');
-- Parola hash'i yalnızca argon2id olabilir.
SELECT test_expect_error(
    $q$INSERT INTO users (email, display_name, password_hash) VALUES ('b@example.com', 'B', 'duz-metin')$q$,
    '23514');
-- Aynı kullanıcıya aynı panel için ikinci "bütün bölümler" yetkisi verilemez.
INSERT INTO access_grants (organization_id, user_id, panel_id)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-0000000000a1');
SELECT test_expect_error(
    $q$INSERT INTO access_grants (organization_id, user_id, panel_id)
       VALUES ('aaaaaaaa-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001',
               'a0000000-0000-0000-0000-0000000000a1')$q$,
    '23505');

ROLLBACK;

\echo 'veritabanı testleri: hepsi geçti'
