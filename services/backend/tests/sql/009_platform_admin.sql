-- Platform yöneticisi rolü: uygulama rolünden ayrı, RLS'ye tabi.
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
    ('aaaaaaaa-0000-0000-0000-000000000001', 'Kurum A', 'business');
INSERT INTO panels (id, organization_id, name, brand, device_serial) VALUES
    ('a0000000-0000-0000-0000-0000000000a1', 'aaaaaaaa-0000-0000-0000-000000000001', 'Panel', 'acme', 'SN-A');

-- Uygulama rolü organizasyon listesini alamaz.
SET LOCAL ROLE shedu_app;
SELECT test_expect_error($q$SELECT * FROM admin_organizations()$q$, '42501');

-- Yönetici rolü listeyi alır ama kiracı verisine bağlamsız erişemez (RLS aynen geçerli).
SET LOCAL ROLE shedu_admin;
SELECT set_config('app.org_id', '', true);
DO $$
BEGIN
    ASSERT (SELECT panels FROM admin_organizations()
             WHERE id = 'aaaaaaaa-0000-0000-0000-000000000001') = 1, 'özet sayıları';
    ASSERT NOT EXISTS (SELECT 1 FROM panels), 'bağlamsız panel görünmemeli';
END
$$;
-- Denetim kaydını silemez, uygulama rolünün yapamadığını yapamaz.
SELECT test_expect_error($q$DELETE FROM audit_log$q$, '42501');
SELECT test_expect_error($q$DELETE FROM organizations$q$, '42501');

ROLLBACK;

\echo 'platform yöneticisi testleri: hepsi geçti'
