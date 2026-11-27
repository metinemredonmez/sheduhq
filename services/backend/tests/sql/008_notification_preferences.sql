-- Bildirim tercihleri: alarm kapatılamaz, kişi yalnızca kendi tercihini yazar.
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
INSERT INTO users (id, phone, display_name) VALUES
    ('11111111-0000-0000-0000-000000000001', '+905551110001', 'Sahip'),
    ('22222222-0000-0000-0000-000000000002', '+905551110002', 'Üye');
INSERT INTO memberships (user_id, organization_id, role) VALUES
    ('11111111-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001', 'owner'),
    ('22222222-0000-0000-0000-000000000002', 'aaaaaaaa-0000-0000-0000-000000000001', 'member'),
    ('22222222-0000-0000-0000-000000000002', 'bbbbbbbb-0000-0000-0000-000000000002', 'owner');
INSERT INTO notification_preferences (user_id, organization_id, category, enabled) VALUES
    ('22222222-0000-0000-0000-000000000002', 'bbbbbbbb-0000-0000-0000-000000000002', 'arming', false);

SET LOCAL ROLE shedu_app;
SELECT set_config('app.org_id', 'aaaaaaaa-0000-0000-0000-000000000001', true),
       set_config('app.user_id', '22222222-0000-0000-0000-000000000002', true);

-- Alarm kategorisi yazılamaz.
SELECT test_expect_error(
    $q$INSERT INTO notification_preferences (user_id, organization_id, category, enabled)
       VALUES ('22222222-0000-0000-0000-000000000002', 'aaaaaaaa-0000-0000-0000-000000000001', 'alarm', false)$q$,
    '23514');
-- Başkası adına ve başka organizasyona yazılamaz.
SELECT test_expect_error(
    $q$INSERT INTO notification_preferences (user_id, organization_id, category, enabled)
       VALUES ('11111111-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001', 'arming', false)$q$,
    '42501');
SELECT test_expect_error(
    $q$INSERT INTO notification_preferences (user_id, organization_id, category, enabled)
       VALUES ('22222222-0000-0000-0000-000000000002', 'bbbbbbbb-0000-0000-0000-000000000002', 'power', false)$q$,
    '42501');
-- Üye olunmayan organizasyona tercih yazılamaz.
SELECT set_config('app.user_id', '11111111-0000-0000-0000-000000000001', true),
       set_config('app.org_id', 'bbbbbbbb-0000-0000-0000-000000000002', true);
SELECT test_expect_error(
    $q$INSERT INTO notification_preferences (user_id, organization_id, category, enabled)
       VALUES ('11111111-0000-0000-0000-000000000001', 'bbbbbbbb-0000-0000-0000-000000000002', 'arming', false)$q$,
    '23503');

-- Kendi tercihi yazılır; dağıtıcı (kullanıcı bağlamı yok) organizasyondakileri okur, başka
-- organizasyonunkini görmez.
SELECT set_config('app.user_id', '22222222-0000-0000-0000-000000000002', true),
       set_config('app.org_id', 'aaaaaaaa-0000-0000-0000-000000000001', true);
INSERT INTO notification_preferences (user_id, organization_id, category, enabled)
    VALUES ('22222222-0000-0000-0000-000000000002', 'aaaaaaaa-0000-0000-0000-000000000001', 'power', false);
SELECT set_config('app.user_id', '', true);
DO $$
DECLARE
    n integer;
BEGIN
    ASSERT (SELECT count(*) FROM notification_preferences) = 1, 'yalnızca bu organizasyonun tercihi';
    -- Kullanıcı bağlamı olmadan güncelleme yapılamaz.
    UPDATE notification_preferences SET enabled = true;
    GET DIAGNOSTICS n = ROW_COUNT;
    ASSERT n = 0, 'bağlamsız güncelleme olmamalı';
END
$$;

-- Üyelik silinince tercih de silinir.
RESET ROLE;
DELETE FROM memberships
 WHERE user_id = '22222222-0000-0000-0000-000000000002'
   AND organization_id = 'aaaaaaaa-0000-0000-0000-000000000001';
DO $$
BEGIN
    ASSERT NOT EXISTS (SELECT 1 FROM notification_preferences
                        WHERE organization_id = 'aaaaaaaa-0000-0000-0000-000000000001'),
        'üyelikle birlikte tercih silinmeli';
END
$$;

ROLLBACK;

\echo 'bildirim tercihi testleri: hepsi geçti'
