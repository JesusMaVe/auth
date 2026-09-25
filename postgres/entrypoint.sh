#!/bin/sh
# Arranca postgres con el entrypoint oficial y, en cada arranque, aplica la contraseña de
# POSTGRES_PASSWORD_FILE (rotación sin borrar datos). El healthcheck espera el archivo $APPLIED.
# Nunca imprime la contraseña.
set -eu

APPLIED=/tmp/.password-applied
rm -f "$APPLIED"

docker-entrypoint.sh "$@" &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null' TERM INT

# ALTER USER es idempotente: se reintenta hasta que el servidor definitivo lo acepta
# (durante la primera inicialización, el entrypoint oficial usa un servidor temporal).
apply_password() {
  PG_NEW_PASSWORD=$(cat "$POSTGRES_PASSWORD_FILE") psql -v ON_ERROR_STOP=1 -q \
    -h /var/run/postgresql -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1 <<'SQL'
\getenv pw PG_NEW_PASSWORD
ALTER ROLE CURRENT_USER PASSWORD :'pw';
SQL
}

until apply_password; do
  kill -0 "$pid" 2>/dev/null || break
  sleep 1
done
kill -0 "$pid" 2>/dev/null && touch "$APPLIED" && echo "entrypoint: contraseña aplicada"

set +e
wait "$pid"
status=$?
while kill -0 "$pid" 2>/dev/null; do
  wait "$pid"
  status=$?
done
exit "$status"
