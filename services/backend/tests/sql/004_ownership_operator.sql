-- Sahiplik devri fonksiyonu ve operatör rolü kısıtı.
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
    ('bbbbbbbb-0000-0000-0000-000000000002', 'Şirket B', 'business');
INSERT INTO users (id, phone, display_name) VALUES
    ('11111111-0000-0000-0000-000000000001', '+905551110001', 'Sahip'),
    ('22222222-0000-0000-0000-000000000002', '+905551110002', 'Yönetici'),
    ('33333333-0000-0000-0000-000000000003', '+905551110003', 'Üye');
INSERT INTO memberships (user_id, organization_id, role) VALUES
    ('11111111-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001', 'owner'),
    ('22222222-0000-0000-0000-000000000002', 'aaaaaaaa-0000-0000-0000-000000000001', 'admin'),
    ('33333333-0000-0000-0000-000000000003', 'aaaaaaaa-0000-0000-0000-000000000001', 'member'),
    ('11111111-0000-0000-0000-000000000001', 'bbbbbbbb-0000-0000-0000-000000000002', 'owner');

SET LOCAL ROLE shedu_app;
SELECT set_config('app.org_id', 'aaaaaaaa-0000-0000-0000-000000000001', true);

-- ---------------------------------------------------------------------------------------------
-- 1. Sahiplik devri (AZ-05)
-- ---------------------------------------------------------------------------------------------
-- Sahip olmayan devredemez.
SELECT set_config('app.user_id', '22222222-0000-0000-0000-000000000002', true);
SELECT test_expect_error(
    $q$SELECT transfer_ownership('33333333-0000-0000-0000-000000000003')$q$, '42501');
-- Devralan yönetici olmalı; hata sahibin rolünü de geri alır.
SELECT set_config('app.user_id', '11111111-0000-0000-0000-000000000001', true);
SELECT test_expect_error(
    $q$SELECT transfer_ownership('33333333-0000-0000-0000-000000000003')$q$, '22023');
SELECT test_expect_error(
    $q$SELECT transfer_ownership('11111111-0000-0000-0000-000000000001')$q$, '22023');
DO $$
BEGIN
    ASSERT (SELECT role FROM memberships
             WHERE user_id = '11111111-0000-0000-0000-000000000001'
               AND organization_id = 'aaaaaaaa-0000-0000-0000-000000000001') = 'owner',
        'başarısız devir sahipliği değiştirmemeli';
END
$$;
-- Başarılı devir: tek sahip, önceki sahip yönetici.
SELECT transfer_ownership('22222222-0000-0000-0000-000000000002');
DO $$
BEGIN
    ASSERT (SELECT count(*) FROM memberships
             WHERE organization_id = 'aaaaaaaa-0000-0000-0000-000000000001' AND role = 'owner') = 1,
        'tek sahip olmalı';
    ASSERT (SELECT role FROM memberships
             WHERE user_id = '22222222-0000-0000-0000-000000000002'
               AND organization_id = 'aaaaaaaa-0000-0000-0000-000000000001') = 'owner',
        'devralan sahip olmalı';
    ASSERT (SELECT role FROM memberships
             WHERE user_id = '11111111-0000-0000-0000-000000000001'
               AND organization_id = 'aaaaaaaa-0000-0000-0000-000000000001') = 'admin',
        'önceki sahip yönetici olmalı';
    -- Diğer organizasyondaki sahiplik etkilenmez.
    ASSERT (SELECT role FROM memberships
             WHERE user_id = '11111111-0000-0000-0000-000000000001'
               AND organization_id = 'bbbbbbbb-0000-0000-0000-000000000002') = 'owner',
        'başka organizasyonun sahipliği değişmemeli';
END
$$;
-- Uygulama rolü devir fonksiyonu dışında sahip üyeliğine hâlâ dokunamaz.
SELECT test_expect_error(
    $q$UPDATE memberships SET role = 'member'
        WHERE user_id = '22222222-0000-0000-0000-000000000002'
          AND organization_id = 'aaaaaaaa-0000-0000-0000-000000000001'$q$,
    '23001');

-- ---------------------------------------------------------------------------------------------
-- 2. Operatör yalnızca işletme ve izleme merkezinde
-- ---------------------------------------------------------------------------------------------
SELECT test_expect_error(
    $q$UPDATE memberships SET role = 'operator'
        WHERE user_id = '33333333-0000-0000-0000-000000000003'
          AND organization_id = 'aaaaaaaa-0000-0000-0000-000000000001'$q$,
    '23514');
SELECT test_expect_error(
    $q$INSERT INTO invitations (organization_id, phone, role, expires_at)
       VALUES ('aaaaaaaa-0000-0000-0000-000000000001', '+905551110009', 'operator', now() + interval '1 day')$q$,
    '23514');
-- İşletmede olur (kiracı bağlamı yokken de: kabul akışı).
SELECT set_config('app.org_id', '', true);
INSERT INTO memberships (user_id, organization_id, role)
    VALUES ('33333333-0000-0000-0000-000000000003', 'bbbbbbbb-0000-0000-0000-000000000002', 'operator');

ROLLBACK;

\echo 'sahiplik ve operatör testleri: hepsi geçti'
