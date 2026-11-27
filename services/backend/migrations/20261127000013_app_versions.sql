-- Uygulama sürüm politikası: platform başına desteklenen en düşük ve en güncel sürüm.
--
-- Kurallar:
--  * En düşük sürümün altındaki istemci güncellemeye zorlanır; API de bu istemcilerin
--    isteklerini reddeder (426). En güncel sürümün altı yalnızca önerilir.
--  * Kayıt yoksa o platformda hiçbir şey zorlanmaz.
--  * Mağaza adresi yalnızca resmi mağazalara (App Store, Google Play) gidebilir; adres API'de ayrıca
--    doğrulanır.
--  * Yalnızca platform yöneticisi yazar; API yalnızca okur.

CREATE TABLE app_versions (
    platform         text PRIMARY KEY CHECK (platform IN ('ios', 'android', 'web')),
    minimum_version  text NOT NULL CHECK (minimum_version ~ '^[0-9]{1,6}(\.[0-9]{1,6}){0,2}$'),
    latest_version   text NOT NULL CHECK (latest_version ~ '^[0-9]{1,6}(\.[0-9]{1,6}){0,2}$'),
    store_url        text CHECK (store_url ~ '^https://(apps\.apple\.com|play\.google\.com)/'
                                 AND length(store_url) <= 500),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT ON app_versions TO shedu_app;
GRANT INSERT, UPDATE, DELETE ON app_versions TO shedu_admin;
