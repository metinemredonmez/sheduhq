-- Özellik bayrakları: bir özelliği yeniden dağıtım yapmadan açıp kapatma.
--
-- Kurallar:
--  * Bayrak yetki vermez; yalnızca özelliği gösterir veya gizler. Yetki her istekte ayrıca
--    denetlenir.
--  * Değerlendirme: `enabled = false` her organizasyonda kapalıdır (acil kapatma, organizasyon
--    ayarını da ezer). Açıksa organizasyona özel ayar varsa o geçerlidir; yoksa organizasyon,
--    bayrak anahtarı ve kimliğinden hesaplanan sabit bir kova ile `rollout_percent` uygulanır.
--    Tanımsız bayrak kapalıdır.
--  * Bayrakları yalnızca platform yöneticisi (`shedu_admin`) yazar; API yalnızca okur. Kim, ne
--    zaman, neden değiştirdi denetim kaydındadır.

CREATE TABLE feature_flags (
    key              text PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]{1,63}$'),
    description      text NOT NULL CHECK (length(description) BETWEEN 1 AND 300),
    enabled          boolean NOT NULL DEFAULT false,
    rollout_percent  smallint NOT NULL DEFAULT 0 CHECK (rollout_percent BETWEEN 0 AND 100),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE feature_flag_overrides (
    flag_key         text NOT NULL REFERENCES feature_flags (key) ON DELETE CASCADE,
    organization_id  uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    enabled          boolean NOT NULL,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (flag_key, organization_id)
);
CREATE INDEX feature_flag_overrides_org_idx ON feature_flag_overrides (organization_id);

-- Organizasyon ayarı kiracı verisidir: her organizasyon yalnızca kendi ayarını görür (AZ-02).
ALTER TABLE feature_flag_overrides ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON feature_flag_overrides
    USING (organization_id = app_current_org())
    WITH CHECK (organization_id = app_current_org());

GRANT SELECT ON feature_flags, feature_flag_overrides TO shedu_app;
GRANT INSERT, UPDATE, DELETE ON feature_flags, feature_flag_overrides TO shedu_admin;

-- Yönetici aracı için bütün organizasyon ayarları (kişisel veri yok). Uygulama rolü çalıştıramaz.
CREATE FUNCTION admin_flag_overrides()
    RETURNS TABLE (flag_key text, organization_id uuid, enabled boolean, updated_at timestamptz)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
    SELECT flag_key, organization_id, enabled, updated_at
      FROM feature_flag_overrides
     ORDER BY flag_key, organization_id
$$;

REVOKE ALL ON FUNCTION admin_flag_overrides() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION admin_flag_overrides() TO shedu_admin;
