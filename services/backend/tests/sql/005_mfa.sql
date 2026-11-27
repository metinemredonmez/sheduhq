-- İki adımlı doğrulama tablolarının sınırları.
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

-- Sır yalnızca şifreli biçimde (20 bayt + 16 bayt etiket) ve 24 baytlık nonce ile saklanır.
SELECT test_expect_error(
    $q$INSERT INTO user_totp (user_id, key_version, nonce, secret_ct)
       VALUES ('11111111-0000-0000-0000-000000000001', 1, decode(repeat('00', 24), 'hex'),
               decode(repeat('ab', 20), 'hex'))$q$,
    '23514');
SELECT test_expect_error(
    $q$INSERT INTO user_totp (user_id, key_version, nonce, secret_ct)
       VALUES ('11111111-0000-0000-0000-000000000001', 0, decode(repeat('00', 24), 'hex'),
               decode(repeat('ab', 36), 'hex'))$q$,
    '23514');
-- İkinci adım bileti en fazla 5 dakika ve 5 deneme.
SELECT test_expect_error(
    $q$INSERT INTO mfa_challenges (user_id, token_hash, platform, expires_at)
       VALUES ('11111111-0000-0000-0000-000000000001', decode(repeat('cd', 32), 'hex'), 'ios',
               now() + interval '6 minutes')$q$,
    '23514');
INSERT INTO mfa_challenges (id, user_id, token_hash, platform, expires_at)
    VALUES ('c0000000-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000001',
            decode(repeat('cd', 32), 'hex'), 'ios', now() + interval '5 minutes');
SELECT test_expect_error(
    $q$UPDATE mfa_challenges SET attempts = 6 WHERE id = 'c0000000-0000-0000-0000-000000000001'$q$,
    '23514');
-- Kurtarma kodunun yalnızca 32 baytlık özeti saklanır; aynı özet iki kez olamaz.
SELECT test_expect_error(
    $q$INSERT INTO recovery_codes (user_id, code_hash)
       VALUES ('11111111-0000-0000-0000-000000000001', convert_to('abcdefghjk', 'UTF8'))$q$,
    '23514');
INSERT INTO recovery_codes (user_id, code_hash)
    VALUES ('11111111-0000-0000-0000-000000000001', decode(repeat('ef', 32), 'hex'));
SELECT test_expect_error(
    $q$INSERT INTO recovery_codes (user_id, code_hash)
       VALUES ('11111111-0000-0000-0000-000000000001', decode(repeat('ef', 32), 'hex'))$q$,
    '23505');
-- Oturum doğrulama yöntemi sınırlı.
SELECT test_expect_error(
    $q$INSERT INTO session_factors (family_id, user_id, method)
       VALUES (gen_random_uuid(), '11111111-0000-0000-0000-000000000001', 'sms')$q$,
    '23514');

ROLLBACK;

\echo 'iki adımlı doğrulama testleri: hepsi geçti'
