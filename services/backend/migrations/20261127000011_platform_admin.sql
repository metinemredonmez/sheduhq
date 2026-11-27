-- Platform yöneticisi (Shedu / izleme firması işletmecisi) rolü.
--
-- Kurallar (AZ-05, OPS-02):
--  * Platform yöneticisi organizasyon yöneticisinden ayrıdır. İşlemlerini yalnızca sunucuda
--    çalışan `shedu-admin` aracı yapar; API'de karşılığı yoktur.
--  * Araç kendi veritabanı rolüyle (`shedu_admin`) bağlanır. Bu rol uygulama rolünün
--    yetkilerini miras alır ve RLS'ye aynen tabidir; ek olarak yalnızca bütün organizasyonların
--    özetini veren fonksiyonu çalıştırabilir. Uygulama rolü bu fonksiyonu çalıştıramaz; API ele
--    geçirilse bile organizasyon listesi alınamaz.
--  * Aracı çalıştıracak gerçek giriş rolü (parolası sır yönetiminden) bu role üye yapılır;
--    parolası API'ninkinden ayrıdır.

DO $$
BEGIN
    CREATE ROLE shedu_admin NOLOGIN;
EXCEPTION
    WHEN duplicate_object OR unique_violation THEN
        NULL;
END
$$;

-- Rol üyeliği küme geneldir; paralel kurulumda ikinci GRANT'in çakışması yok sayılır.
DO $$
BEGIN
    GRANT shedu_app TO shedu_admin;
EXCEPTION
    WHEN duplicate_object OR unique_violation THEN
        NULL;
END
$$;

-- Bütün organizasyonların özeti: kişisel veri içermez (ad, tür, sayılar).
CREATE FUNCTION admin_organizations()
    RETURNS TABLE (id uuid, name text, kind text, created_at timestamptz,
                   members bigint, panels bigint)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
    SELECT o.id, o.name, o.kind, o.created_at,
           (SELECT count(*) FROM memberships m WHERE m.organization_id = o.id),
           (SELECT count(*) FROM panels p WHERE p.organization_id = o.id)
      FROM organizations o
     ORDER BY o.created_at
$$;

REVOKE ALL ON FUNCTION admin_organizations() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION admin_organizations() TO shedu_admin;
