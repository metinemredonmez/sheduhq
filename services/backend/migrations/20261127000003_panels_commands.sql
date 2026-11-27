-- Panel ve komut API'si desteği.

-- Sanal (demo) panel: gerçek bir cihaza bağlı değildir; komutları sunucu içinde simüle edilir.
-- Mağaza incelemesi ve deneme için. Bir organizasyonda en fazla bir tane olabilir.
ALTER TABLE panels ADD COLUMN simulated boolean NOT NULL DEFAULT false;
CREATE UNIQUE INDEX panels_one_simulated_per_org ON panels (organization_id) WHERE simulated;

-- Değişiklik bildirimi: API kopyaları `shedu_events` kanalını dinler ve WebSocket istemcilerine
-- iletir. Yükte yalnızca kimlikler vardır; ayrıntı her istemci için kendi yetkisiyle (RLS altında)
-- yeniden okunur. Böylece bir istemciye başkasının verisi taşınmaz (API-04).
CREATE FUNCTION notify_org_event() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_notify(
        'shedu_events',
        json_build_object(
            'org', NEW.organization_id,
            'kind', TG_ARGV[0],
            'id', NEW.id::text,
            'panel', NEW.panel_id
        )::text
    );
    RETURN NEW;
END
$$;

CREATE TRIGGER commands_notify
    AFTER INSERT OR UPDATE OF status ON commands
    FOR EACH ROW EXECUTE FUNCTION notify_org_event('command');

CREATE TRIGGER partitions_notify
    AFTER UPDATE OF state ON partitions
    FOR EACH ROW EXECUTE FUNCTION notify_org_event('partition');

CREATE TRIGGER panel_events_notify
    AFTER INSERT ON panel_events
    FOR EACH ROW EXECUTE FUNCTION notify_org_event('panel_event');
