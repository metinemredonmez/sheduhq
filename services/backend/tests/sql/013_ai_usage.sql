-- AI maliyet defteri: yalnızca eklenir, yalnızca kendi bağlamına yazılır, satırlar okunamaz,
-- toplamlar silmeden etkilenmez.
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

-- Harcama kimliklere yabancı anahtarla bağlı değildir: hesap silinse de kalır. Tek yabancı
-- anahtar, kapanış satırını kendi rezervasyonuna bağlar (aynı tablo).
DO $$
BEGIN
    ASSERT NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'ai_usage'::regclass AND contype = 'f'
           AND confrelid <> 'ai_usage'::regclass
    ), 'defterde başka tabloya yabancı anahtar olmamalı';
END
$$;

-- Önceden yazılmış harcamalar: B organizasyonu, başka kullanıcı ve 24 saatten eski bir kayıt.
INSERT INTO ai_usage (occurred_at, organization_id, user_id, feature, model, input_tokens,
                      output_tokens, cost_microusd, outcome) VALUES
    (now() - interval '1 hour', 'bbbbbbbb-0000-0000-0000-000000000002',
     '22222222-0000-0000-0000-000000000002', 'event_summary', 'claude-opus-5-5', 10, 10, 700, 'success'),
    (now() - interval '1 hour', 'bbbbbbbb-0000-0000-0000-000000000002',
     '11111111-0000-0000-0000-000000000001', 'event_summary', 'claude-opus-5-5', 10, 10, 50, 'refused'),
    (now() - interval '25 hours', 'aaaaaaaa-0000-0000-0000-000000000001',
     '11111111-0000-0000-0000-000000000001', 'event_summary', 'claude-opus-5-5', 10, 10, 99999, 'success');

SET LOCAL ROLE shedu_app;

-- Bağlam yoksa toplam okunamaz.
SELECT test_expect_error('SELECT * FROM ai_spend_last_day()', '42501');

SELECT set_config('app.org_id', 'aaaaaaaa-0000-0000-0000-000000000001', true),
       set_config('app.user_id', '11111111-0000-0000-0000-000000000001', true);

INSERT INTO ai_usage (organization_id, user_id, feature, model, input_tokens, output_tokens,
                      cost_microusd, outcome)
VALUES ('aaaaaaaa-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001',
        'event_summary', 'claude-opus-5-5', 100, 20, 800, 'success');

-- Başka organizasyon veya başka kullanıcı adına yazılamaz.
SELECT test_expect_error(
    $q$INSERT INTO ai_usage (organization_id, user_id, feature, input_tokens, output_tokens, cost_microusd, outcome)
       VALUES ('bbbbbbbb-0000-0000-0000-000000000002', '11111111-0000-0000-0000-000000000001',
               'event_summary', 0, 0, 0, 'failed')$q$,
    '42501');
SELECT test_expect_error(
    $q$INSERT INTO ai_usage (organization_id, user_id, feature, input_tokens, output_tokens, cost_microusd, outcome)
       VALUES ('aaaaaaaa-0000-0000-0000-000000000001', '22222222-0000-0000-0000-000000000002',
               'event_summary', 0, 0, 0, 'failed')$q$,
    '42501');
-- Negatif maliyetle harcama silinemez.
SELECT test_expect_error(
    $q$INSERT INTO ai_usage (organization_id, user_id, feature, input_tokens, output_tokens, cost_microusd, outcome)
       VALUES ('aaaaaaaa-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001',
               'event_summary', 0, 0, -1000, 'failed')$q$,
    '23514');

-- Uygulama satırları okuyamaz, değiştiremez, silemez.
SELECT test_expect_error('SELECT count(*) FROM ai_usage', '42501');
SELECT test_expect_error('UPDATE ai_usage SET cost_microusd = 0', '42501');
SELECT test_expect_error('DELETE FROM ai_usage', '42501');

-- Toplamlar: kullanıcı 800 + 50 (B'deki ret de sayılır), organizasyon A 800, sistem 1550.
-- 24 saatten eski kayıt sayılmaz.
DO $$
DECLARE
    r record;
BEGIN
    SELECT * INTO r FROM ai_spend_last_day();
    ASSERT r.user_microusd = 850, format('kullanıcı toplamı %s', r.user_microusd);
    ASSERT r.org_microusd = 800, format('organizasyon toplamı %s', r.org_microusd);
    ASSERT r.global_microusd = 1550, format('sistem toplamı %s', r.global_microusd);
END
$$;

-- Tablo sahibi de olsa defter değiştirilemez ve boşaltılamaz.
RESET ROLE;
SELECT test_expect_error('UPDATE ai_usage SET cost_microusd = 0', '42501');
SELECT test_expect_error('DELETE FROM ai_usage', '42501');
SELECT test_expect_error('TRUNCATE ai_usage', '42501');

ROLLBACK;

\echo 'AI maliyet defteri testleri: hepsi geçti'
