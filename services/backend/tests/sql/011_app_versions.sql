-- Uygulama sürüm politikası: yalnızca yönetici yazar, mağaza adresi resmi mağazalarla sınırlı.
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

SET LOCAL ROLE shedu_app;
SELECT test_expect_error(
    $q$INSERT INTO app_versions (platform, minimum_version, latest_version) VALUES ('ios', '1', '1')$q$,
    '42501');

SET LOCAL ROLE shedu_admin;
INSERT INTO app_versions (platform, minimum_version, latest_version, store_url)
    VALUES ('ios', '1.2.0', '1.4.0', 'https://apps.apple.com/app/id000');
SELECT test_expect_error(
    $q$UPDATE app_versions SET store_url = 'https://evil.example/apps.apple.com/'$q$, '23514');
SELECT test_expect_error(
    $q$UPDATE app_versions SET store_url = 'http://apps.apple.com/app'$q$, '23514');
SELECT test_expect_error(
    $q$UPDATE app_versions SET minimum_version = '1.2-beta'$q$, '23514');
SELECT test_expect_error(
    $q$INSERT INTO app_versions (platform, minimum_version, latest_version) VALUES ('symbian', '1', '1')$q$,
    '23514');

SET LOCAL ROLE shedu_app;
SELECT test_expect_error($q$UPDATE app_versions SET minimum_version = '0'$q$, '42501');
DO $$
BEGIN
    ASSERT (SELECT minimum_version FROM app_versions WHERE platform = 'ios') = '1.2.0', 'okunabilmeli';
END
$$;

ROLLBACK;

\echo 'sürüm politikası testleri: hepsi geçti'
