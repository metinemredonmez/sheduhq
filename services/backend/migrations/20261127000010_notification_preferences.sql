-- Bildirim tercihleri: kişi, üyesi olduğu her organizasyon için hangi bildirim kategorilerini
-- almak istediğini seçer.
--
-- Kurallar:
--  * Alarm bildirimleri kapatılamaz: `alarm` kategorisi bu tabloya yazılamaz (domain kuralı
--    `NotificationCategory::can_be_disabled` ile aynı).
--  * Kayıt yoksa kategori açıktır (varsayılan: hepsi açık).
--  * Tercih üyeliğe bağlıdır; üyelik silinince (çıkarma, ayrılma, hesap silme) tercihler de silinir.
--  * Kişi yalnızca kendi tercihini yazar; bildirim dağıtıcısı organizasyondaki herkesinkini okur
--    (AZ-02).

CREATE TABLE notification_preferences (
    user_id          uuid NOT NULL,
    organization_id  uuid NOT NULL,
    category         text NOT NULL CHECK (category IN ('connectivity', 'power', 'arming')),
    enabled          boolean NOT NULL,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, organization_id, category),
    FOREIGN KEY (user_id, organization_id) REFERENCES memberships (user_id, organization_id)
        ON DELETE CASCADE
);
CREATE INDEX notification_preferences_org_idx ON notification_preferences (organization_id, category)
    WHERE NOT enabled;

ALTER TABLE notification_preferences ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON notification_preferences FOR SELECT
    USING (organization_id = app_current_org());
CREATE POLICY own_insert ON notification_preferences FOR INSERT
    WITH CHECK (organization_id = app_current_org() AND user_id = app_current_user());
CREATE POLICY own_update ON notification_preferences FOR UPDATE
    USING (organization_id = app_current_org() AND user_id = app_current_user())
    WITH CHECK (organization_id = app_current_org() AND user_id = app_current_user());

GRANT SELECT, INSERT, UPDATE ON notification_preferences TO shedu_app;
