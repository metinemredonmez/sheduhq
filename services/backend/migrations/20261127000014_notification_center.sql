-- Bildirim merkezi: kişinin gördüğü olayların okundu bilgisi.
--
-- Kurallar:
--  * Bildirimler ayrıca saklanmaz; olaylardan, kişinin o anki yetkisiyle türetilir (olay geçmişi
--    ve push ile aynı görünürlük kuralı). Yetkisini veya üyeliğini kaybeden kişi eski
--    bildirimleri de göremez.
--  * Okundu bilgisi iki parçadır: organizasyon başına "buraya kadar hepsi okundu" sınırı ve bu
--    sınırın üstünde tek tek okunanlar. Sınır ilerleyince altındaki tekil kayıtlar silinir;
--    tablo büyümez.
--  * Kişi yalnızca kendi okundu bilgisini okur ve yazar (AZ-02); üyelik silinince silinir.

CREATE TABLE notification_reads (
    user_id             uuid NOT NULL,
    organization_id     uuid NOT NULL,
    last_read_event_id  bigint NOT NULL CHECK (last_read_event_id >= 0),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, organization_id),
    FOREIGN KEY (user_id, organization_id) REFERENCES memberships (user_id, organization_id)
        ON DELETE CASCADE
);

CREATE TABLE notification_item_reads (
    user_id          uuid NOT NULL,
    organization_id  uuid NOT NULL,
    event_id         bigint NOT NULL,
    read_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, event_id),
    FOREIGN KEY (user_id, organization_id) REFERENCES memberships (user_id, organization_id)
        ON DELETE CASCADE,
    FOREIGN KEY (event_id, organization_id) REFERENCES panel_events (id, organization_id)
        ON DELETE CASCADE
);
CREATE INDEX notification_item_reads_org_idx ON notification_item_reads (organization_id);

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['notification_reads', 'notification_item_reads']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY own_rows ON %I
                 USING (organization_id = app_current_org() AND user_id = app_current_user())
                 WITH CHECK (organization_id = app_current_org() AND user_id = app_current_user())', t);
    END LOOP;
END
$$;

GRANT SELECT, INSERT, UPDATE, DELETE ON notification_reads, notification_item_reads TO shedu_app;
