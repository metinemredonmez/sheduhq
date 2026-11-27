#!/usr/bin/env bash
# Migration'ları boş bir veritabanına uygular ve SQL testlerini çalıştırır.
#
# Bağlantı standart PostgreSQL ortam değişkenleriyle verilir: PGHOST, PGPORT, PGUSER, PGDATABASE
# (gerekirse PGPASSWORD). Testler rol ve RLS kontrolü yaptığı için süper kullanıcı gerekir.
# Yalnızca yerel veya CI'daki geçici veritabanında çalıştırın; üretimde ASLA.
set -euo pipefail
cd "$(dirname "$0")/.."

psql_run() { psql -X -q -v ON_ERROR_STOP=1 "$@"; }

for migration in migrations/*.sql; do
    echo "migration: $migration"
    psql_run -f "$migration"
done

for test in tests/sql/*.sql; do
    echo "test: $test"
    psql_run -f "$test"
done
