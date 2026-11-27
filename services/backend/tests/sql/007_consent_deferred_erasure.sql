-- Rıza defteri ve bekleyen silme talebi kısıtları.
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

INSERT INTO users (id, phone, display_name) VALUES
    ('11111111-0000-0000-0000-000000000001', '+905551110001', 'Kullanıcı');

SET LOCAL ROLE shedu_app;

-- ---------------------------------------------------------------------------------------------
-- 1. Rıza defteri yalnızca eklenir
-- ---------------------------------------------------------------------------------------------
INSERT INTO consent_records (user_id, purpose, version, granted)
    VALUES ('11111111-0000-0000-0000-000000000001', 'marketing', 'taslak-1', true);
SELECT test_expect_error(
    $q$UPDATE consent_records SET granted = false$q$, '42501');
SELECT test_expect_error(
    $q$DELETE FROM consent_records$q$, '42501');
-- Tablo sahibi bile (yetki engeli olmadan) kaydı değiştiremez: tetikleyici ikinci bariyerdir.
RESET ROLE;
SELECT test_expect_error(
    $q$UPDATE consent_records SET granted = false$q$, '42501');
SELECT test_expect_error(
    $q$DELETE FROM consent_records$q$, '42501');
SET LOCAL ROLE shedu_app;
-- Bilinmeyen amaç ve uygulamanın amaç listesini değiştirmesi reddedilir.
SELECT test_expect_error(
    $q$INSERT INTO consent_records (user_id, purpose, version, granted)
       VALUES ('11111111-0000-0000-0000-000000000001', 'uydurma', 'taslak-1', true)$q$,
    '23503');
SELECT test_expect_error(
    $q$UPDATE consent_purposes SET current_version = 'x' WHERE code = 'marketing'$q$, '42501');
SELECT test_expect_error(
    $q$INSERT INTO consent_purposes (code, current_version, kind, description)
       VALUES ('yeni', '1', 'explicit_consent', 'x')$q$,
    '42501');

-- ---------------------------------------------------------------------------------------------
-- 2. Bekleyen silme talebinde tarih zorunlu, etkin hesapta yasak
-- ---------------------------------------------------------------------------------------------
SELECT test_expect_error(
    $q$UPDATE users SET status = 'pending_deletion'
        WHERE id = '11111111-0000-0000-0000-000000000001'$q$,
    '23514');
SELECT test_expect_error(
    $q$UPDATE users SET deletion_due_at = now()
        WHERE id = '11111111-0000-0000-0000-000000000001'$q$,
    '23514');
UPDATE users SET status = 'pending_deletion', deletion_due_at = now() + interval '30 days'
 WHERE id = '11111111-0000-0000-0000-000000000001';

-- Silme fonksiyonu bekleyen hesabı siler; rıza kayıtları kanıt olarak kalır.
SELECT set_config('app.user_id', '11111111-0000-0000-0000-000000000001', true);
SELECT erase_account();
RESET ROLE;
DO $$
BEGIN
    ASSERT (SELECT status FROM users WHERE id = '11111111-0000-0000-0000-000000000001') = 'deleted',
        'bekleyen hesap silinebilmeli';
    ASSERT (SELECT count(*) FROM consent_records
             WHERE user_id = '11111111-0000-0000-0000-000000000001') = 1,
        'rıza kaydı kalmalı';
END
$$;

ROLLBACK;

\echo 'rıza defteri ve bekleyen silme testleri: hepsi geçti'
