-- Olay geçmişi ve push bildirimleri.

-- Olayın kaynağı: panelden mi, uygulamadaki panik butonundan mı, sanal panelden mi.
ALTER TABLE panel_events
    ADD COLUMN source text NOT NULL DEFAULT 'panel' CHECK (source IN ('panel', 'app', 'simulator'));

-- Gaz ve su baskını alarmları.
ALTER TABLE panel_events DROP CONSTRAINT panel_events_alarm_kind_check;
ALTER TABLE panel_events ADD CONSTRAINT panel_events_alarm_kind_check
    CHECK (alarm_kind IN ('intrusion', 'keypad_or_keyfob', 'panic', 'fire', 'medical', 'tamper', 'gas', 'flood'));

-- Bildirim takibi: olay için push dağıtımı tamamlanınca doldurulur. Boş kalan olaylar düzenli
-- taramayla yeniden denenir; böylece bir API kopyası çökse bile alarm bildirimi kaybolmaz.
ALTER TABLE panel_events ADD COLUMN notified_at timestamptz;
CREATE INDEX panel_events_unnotified_idx ON panel_events (received_at) WHERE notified_at IS NULL;
-- Olaylar yine yalnızca eklenir; uygulama yalnızca bu sütunu güncelleyebilir.
GRANT UPDATE (notified_at) ON panel_events TO shedu_app;

ALTER TABLE panel_events ADD CONSTRAINT panel_events_id_org_key UNIQUE (id, organization_id);

-- Kime, hangi cihaza, hangi öncelikle bildirim gitti: alarm sonrası "haber verildi mi?"
-- sorusunun kanıtı. Token saklanmaz, yalnızca cihaz kimliği.
CREATE TABLE push_deliveries (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id  uuid NOT NULL,
    panel_event_id   bigint NOT NULL,
    user_id          uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id        uuid REFERENCES user_devices (id) ON DELETE SET NULL,
    priority         text NOT NULL CHECK (priority IN ('info', 'warning', 'critical')),
    status           text NOT NULL CHECK (status IN ('sent', 'failed')),
    created_at       timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (panel_event_id, organization_id) REFERENCES panel_events (id, organization_id) ON DELETE CASCADE,
    UNIQUE (panel_event_id, device_id)
);
CREATE INDEX push_deliveries_event_idx ON push_deliveries (panel_event_id);

ALTER TABLE push_deliveries ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON push_deliveries
    USING (organization_id = app_current_org())
    WITH CHECK (organization_id = app_current_org());
GRANT SELECT, INSERT ON push_deliveries TO shedu_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO shedu_app;

-- Bildirimi bekleyen olaylar (bütün kiracılar). Yalnızca kimlik döner; ayrıntı her olay için
-- kendi kiracı bağlamında okunur. Tablo sahibinin yetkisiyle çalışır, bu yüzden RLS'yi aşar;
-- herkese değil yalnızca uygulama rolüne açıktır.
CREATE FUNCTION pending_panel_events(max_rows integer)
    RETURNS TABLE (id bigint, organization_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_temp
AS $$
    SELECT e.id, e.organization_id
      FROM panel_events e
     WHERE e.notified_at IS NULL
       AND e.received_at < now() - interval '5 seconds'
       AND e.received_at > now() - interval '1 day'
     ORDER BY e.received_at
     LIMIT least(max_rows, 500)
$$;
REVOKE ALL ON FUNCTION pending_panel_events(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pending_panel_events(integer) TO shedu_app;
