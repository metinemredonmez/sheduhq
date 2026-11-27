-- Özellik bayrakları: yalnızca yönetici yazar, organizasyon ayarı kiracıya özeldir.
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
    ('aaaaaaaa-0000-0000-0000-000000000001', 'A', 'home'),
    ('bbbbbbbb-0000-0000-0000-000000000002', 'B', 'home');

-- Yönetici yazar.
SET LOCAL ROLE shedu_admin;
INSERT INTO feature_flags (key, description, enabled, rollout_percent) VALUES ('camera_live', 'Kamera', true, 0);
SELECT test_expect_error(
    $q$INSERT INTO feature_flags (key, description) VALUES ('Kamera-Canlı', 'x')$q$, '23514');
SELECT test_expect_error(
    $q$INSERT INTO feature_flags (key, description, rollout_percent) VALUES ('x_y', 'x', 101)$q$, '23514');
SELECT set_config('app.org_id', 'aaaaaaaa-0000-0000-0000-000000000001', true);
INSERT INTO feature_flag_overrides (flag_key, organization_id, enabled)
    VALUES ('camera_live', 'aaaaaaaa-0000-0000-0000-000000000001', true);
-- Yönetici de RLS'ye tabidir: başka organizasyonun ayarını bu bağlamla yazamaz.
SELECT test_expect_error(
    $q$INSERT INTO feature_flag_overrides (flag_key, organization_id, enabled)
       VALUES ('camera_live', 'bbbbbbbb-0000-0000-0000-000000000002', true)$q$,
    '42501');

-- Uygulama yalnızca okur; yalnızca kendi organizasyonunun ayarını görür.
SET LOCAL ROLE shedu_app;
SELECT test_expect_error($q$UPDATE feature_flags SET enabled = false$q$, '42501');
SELECT test_expect_error($q$DELETE FROM feature_flags$q$, '42501');
SELECT test_expect_error(
    $q$INSERT INTO feature_flag_overrides (flag_key, organization_id, enabled)
       VALUES ('camera_live', 'aaaaaaaa-0000-0000-0000-000000000001', false)$q$,
    '42501');
SELECT set_config('app.org_id', 'bbbbbbbb-0000-0000-0000-000000000002', true);
DO $$
BEGIN
    ASSERT (SELECT count(*) FROM feature_flags) = 1, 'bayrak tanımı herkese açık';
    ASSERT (SELECT count(*) FROM feature_flag_overrides) = 0, 'başka organizasyonun ayarı görünmemeli';
END
$$;

-- Organizasyon silinince ayarı da silinir.
RESET ROLE;
DELETE FROM organizations WHERE id = 'aaaaaaaa-0000-0000-0000-000000000001';
DO $$
BEGIN
    ASSERT NOT EXISTS (SELECT 1 FROM feature_flag_overrides), 'ayar organizasyonla silinmeli';
END
$$;

ROLLBACK;

\echo 'özellik bayrağı testleri: hepsi geçti'
