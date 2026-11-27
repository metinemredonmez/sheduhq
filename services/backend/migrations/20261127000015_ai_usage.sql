-- AI maliyet defteri (AI-03).
--
-- Kurallar:
--  * Her ücretli model çağrısı, isteğin sonucu ne olursa olsun (başarı, ret, hata), çağrı döner
--    dönmez yazılır. Sonucu bilinmeyen çağrı (ör. zaman aşımı) en kötü durum tahminiyle yazılır.
--  * Defter yalnızca eklenir. Yabancı anahtar yoktur: hesap veya organizasyon silinse de harcama
--    kalır, silme bütçeyi sıfırlamaz.
--  * Kişisel veri yok: kimlikler, model adı ve sayılar. Özet metni yazılmaz.
--  * Uygulama yalnızca kendi bağlamındaki (kullanıcı ve organizasyon) satırı yazabilir, satırları
--    okuyamaz. Bütçe denetimi yalnızca toplam döndüren `ai_spend_last_day()` ile yapılır.

CREATE TABLE ai_usage (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at      timestamptz NOT NULL DEFAULT now(),
    organization_id  uuid NOT NULL,
    user_id          uuid NOT NULL,
    feature          text NOT NULL CHECK (feature ~ '^[a-z][a-z0-9_]{1,49}$'),
    model            text CHECK (length(model) BETWEEN 1 AND 100),
    input_tokens     bigint NOT NULL CHECK (input_tokens >= 0),
    output_tokens    bigint NOT NULL CHECK (output_tokens >= 0),
    cost_microusd    bigint NOT NULL CHECK (cost_microusd >= 0),
    outcome          text NOT NULL CHECK (outcome IN ('success', 'refused', 'failed', 'unknown'))
);
CREATE INDEX ai_usage_time_idx ON ai_usage (occurred_at);
CREATE INDEX ai_usage_org_time_idx ON ai_usage (organization_id, occurred_at);
CREATE INDEX ai_usage_user_time_idx ON ai_usage (user_id, occurred_at);

CREATE TRIGGER ai_usage_append_only
    BEFORE UPDATE OR DELETE ON ai_usage
    FOR EACH ROW EXECUTE FUNCTION append_only();
CREATE TRIGGER ai_usage_no_truncate
    BEFORE TRUNCATE ON ai_usage
    FOR EACH STATEMENT EXECUTE FUNCTION append_only();

ALTER TABLE ai_usage ENABLE ROW LEVEL SECURITY;
CREATE POLICY own_insert ON ai_usage FOR INSERT
    WITH CHECK (organization_id = app_current_org() AND user_id = app_current_user());

GRANT INSERT ON ai_usage TO shedu_app;

-- Son 24 saatteki harcama (mikro-dolar): bu kullanıcı (bütün organizasyonlarda), bu organizasyon
-- ve bütün sistem. Yalnızca toplam döner; kullanıcı ve organizasyon bağlamı zorunludur.
CREATE FUNCTION ai_spend_last_day()
    RETURNS TABLE (user_microusd bigint, org_microusd bigint, global_microusd bigint)
    LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
DECLARE
    me  uuid := app_current_user();
    org uuid := app_current_org();
BEGIN
    IF me IS NULL OR org IS NULL THEN
        RAISE EXCEPTION 'kullanıcı ve organizasyon bağlamı gerekli'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN QUERY
    SELECT coalesce(sum(u.cost_microusd) FILTER (WHERE u.user_id = me), 0)::bigint,
           coalesce(sum(u.cost_microusd) FILTER (WHERE u.organization_id = org), 0)::bigint,
           coalesce(sum(u.cost_microusd), 0)::bigint
      FROM ai_usage u
     WHERE u.occurred_at > now() - interval '24 hours';
END
$$;

REVOKE ALL ON FUNCTION ai_spend_last_day() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ai_spend_last_day() TO shedu_app;
