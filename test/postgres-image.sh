#!/usr/bin/env bash
# Tests de la imagen postgres en aislamiento (docker run, sin compose): rotación de la contraseña.
# Usa valores de prueba propios; no depende de .env.
set -u
cd "$(dirname "$0")/.." || exit 1
# shellcheck source=test/lib.sh
. test/lib.sh

IMG=${POSTGRES_TEST_IMAGE:?POSTGRES_TEST_IMAGE no definida (usa make test-postgres-image)}
vol="auth-pg-test-$$"
pwdir=$(mktemp -d)
chmod 755 "$pwdir"
cid=""
cleanup() {
  [[ -n $cid ]] && docker rm -fv "$cid" >/dev/null 2>&1
  docker volume rm "$vol" >/dev/null 2>&1
  rm -rf "$pwdir"
}
trap cleanup EXIT

boot() {
  printf '%s' "$1" > "$pwdir/pw"
  chmod 644 "$pwdir/pw"
  docker run -d -v "$vol:/var/lib/postgresql" -v "$pwdir/pw:/run/secrets/pg:ro" \
    -e POSTGRES_USER=u -e POSTGRES_DB=d -e POSTGRES_PASSWORD_FILE=/run/secrets/pg "$IMG"
}
# Por TCP a la IP del contenedor (no a 127.0.0.1, que el pg_hba de la imagen oficial acepta sin contraseña).
select_as() {
  docker exec -e PGPASSWORD="$2" "$1" sh -c 'psql -h "$(hostname -i)" -U u -d d -tAc "select 1"'
}

echo "postgres-image: rotación de contraseña"
cid=$(boot pg-viejo-1234)
check "arranca y llega a healthy" wait_healthy "$cid"
check_output "la contraseña inicial funciona por TCP" '^1$' select_as "$cid" pg-viejo-1234
check_fails "control: una contraseña errónea es rechazada" select_as "$cid" incorrecta
docker rm -f "$cid" >/dev/null

cid=$(boot pg-nuevo-5678)
check "arranca con la contraseña nueva sobre el mismo volumen" wait_healthy "$cid"
check_output "la contraseña nueva funciona" '^1$' select_as "$cid" pg-nuevo-5678
check_fails "la vieja ya no" select_as "$cid" pg-viejo-1234
check_no_output "los logs no muestran contraseñas" 'pg-viejo-1234|pg-nuevo-5678' docker logs "$cid"

stop_cleanly() {
  local start=$SECONDS
  docker stop -t 20 "$1" >/dev/null || return 1
  [[ $(docker inspect -f '{{.State.ExitCode}}' "$1") == 0 ]] && (( SECONDS - start < 15 ))
}
check "docker stop lo detiene limpio (exit 0, sin esperar el timeout)" stop_cleanly "$cid"

summary
