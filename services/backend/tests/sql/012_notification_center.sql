-- Bildirim merkezi okundu bilgisi: kişiye ve organizasyona özel.
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
INSERT INTO users (id, phone, display_name) VALUES
    ('11111111-0000-0000-0000-000000000001', '+905551110001', 'Sahip'),
    ('22222222-0000-0000-0000-000000000002', '+905551110002', 'Üye');
INSERT INTO memberships (user_id, organization_id, role) VALUES
    ('11111111-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001', 'owner'),
    ('22222222-0000-0000-0000-000000000002', 'aaaaaaaa-0000-0000-0000-000000000001', 'member'),
    ('22222222-0000-0000-0000-000000000002', 'bbbbbbbb-0000-0000-0000-000000000002', 'owner');
INSERT INTO panels (id, organization_id, name, brand, device_serial) VALUES
    ('a0000000-0000-0000-0000-0000000000a1', 'aaaaaaaa-0000-0000-0000-000000000001', 'P', 'test', 'SN-A'),
    ('b0000000-0000-0000-0000-0000000000b1', 'bbbbbbbb-0000-0000-0000-000000000002', 'P', 'test', 'SN-B');
INSERT INTO panel_events (id, organization_id, panel_id, kind, priority, occurred_at) OVERRIDING SYSTEM VALUE VALUES
    (900001, 'aaaaaaaa-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-0000000000a1', 'connected', 'info', now()),
    (900002, 'bbbbbbbb-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-0000000000b1', 'connected', 'info', now());

SET LOCAL ROLE shedu_app;
SELECT set_config('app.org_id', 'aaaaaaaa-0000-0000-0000-000000000001', true),
       set_config('app.user_id', '22222222-0000-0000-0000-000000000002', true);

-- Kendi okundu bilgisi yazılır; başkası adına yazılamaz.
INSERT INTO notification_reads (user_id, organization_id, last_read_event_id)
    VALUES ('22222222-0000-0000-0000-000000000002', 'aaaaaaaa-0000-0000-0000-000000000001', 900001);
INSERT INTO notification_item_reads (user_id, organization_id, event_id)
    VALUES ('22222222-0000-0000-0000-000000000002', 'aaaaaaaa-0000-0000-0000-000000000001', 900001);
SELECT test_expect_error(
    $q$INSERT INTO notification_reads (user_id, organization_id, last_read_event_id)
       VALUES ('11111111-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001', 1)$q$,
    '42501');
-- Başka organizasyonun olayı bu organizasyonun okundu kaydına bağlanamaz.
SELECT test_expect_error(
    $q$INSERT INTO notification_item_reads (user_id, organization_id, event_id)
       VALUES ('22222222-0000-0000-0000-000000000002', 'aaaaaaaa-0000-0000-0000-000000000001', 900002)$q$,
    '23503');

-- Kişi bağlamı yoksa hiçbir kayıt görünmez.
SELECT set_config('app.user_id', '11111111-0000-0000-0000-000000000001', true);
DO $$
BEGIN
    ASSERT (SELECT count(*) FROM notification_reads) = 0, 'başkasının okundu bilgisi görünmemeli';
    ASSERT (SELECT count(*) FROM notification_item_reads) = 0, 'başkasının okundu bilgisi görünmemeli';
END
$$;

-- Üyelik silinince okundu bilgisi de silinir.
RESET ROLE;
DELETE FROM memberships
 WHERE user_id = '22222222-0000-0000-0000-000000000002'
   AND organization_id = 'aaaaaaaa-0000-0000-0000-000000000001';
DO $$
BEGIN
    ASSERT NOT EXISTS (SELECT 1 FROM notification_reads), 'okundu sınırı silinmeli';
    ASSERT NOT EXISTS (SELECT 1 FROM notification_item_reads), 'tekil okundu silinmeli';
END
$$;

ROLLBACK;

\echo 'bildirim merkezi testleri: hepsi geçti'
