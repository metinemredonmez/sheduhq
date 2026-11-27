-- Kullanıcı, kiracı bağlamı seçmeden yalnızca üyesi olduğu organizasyonların adını görebilir.
\set ON_ERROR_STOP on

BEGIN;

INSERT INTO organizations (id, name, kind) VALUES
    ('aaaaaaaa-0000-0000-0000-000000000001', 'Ev A', 'home'),
    ('bbbbbbbb-0000-0000-0000-000000000002', 'Şirket B', 'business'),
    ('cccccccc-0000-0000-0000-000000000003', 'Şirket C', 'business');
INSERT INTO users (id, phone, display_name) VALUES
    ('11111111-0000-0000-0000-000000000001', '+905551112233', 'Kullanıcı');
INSERT INTO memberships (user_id, organization_id, role) VALUES
    ('11111111-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001', 'owner'),
    ('11111111-0000-0000-0000-000000000001', 'bbbbbbbb-0000-0000-0000-000000000002', 'member');

SET LOCAL ROLE shedu_app;

-- Kullanıcı bağlamı yok: hiçbir organizasyon görünmez.
SELECT set_config('app.user_id', '', true), set_config('app.org_id', '', true);
DO $$
BEGIN
    ASSERT (SELECT count(*) FROM organizations) = 0, 'bağlam yokken organizasyon görünmemeli';
END
$$;

-- Kullanıcı bağlamı var: yalnızca üyesi olduğu iki organizasyon görünür.
SELECT set_config('app.user_id', '11111111-0000-0000-0000-000000000001', true);
DO $$
DECLARE
    n integer;
BEGIN
    ASSERT (SELECT count(*) FROM organizations) = 2, 'yalnızca üye olunan organizasyonlar görünmeli';
    ASSERT NOT EXISTS (SELECT 1 FROM organizations WHERE name = 'Şirket C'), 'üye olunmayan görünmemeli';

    -- Üyelik okuma yetkisi yazma yetkisi vermez: kiracı bağlamı olmadan güncellenemez.
    UPDATE organizations SET name = 'değişti' WHERE id = 'bbbbbbbb-0000-0000-0000-000000000002';
    GET DIAGNOSTICS n = ROW_COUNT;
    ASSERT n = 0, 'üyelik okuma politikası güncellemeye izin vermemeli';
END
$$;

ROLLBACK;

\echo 'üyelik okuma testleri: hepsi geçti'
