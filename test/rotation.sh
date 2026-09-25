#!/usr/bin/env bash
# Rotación de contraseñas de extremo a extremo con compose, sin `make clean`:
# `make up` con un .env de contraseñas nuevas debe aplicarlas a ldap y postgres.
# Al final restaura el .env original (y lo verifica).
set -u
cd "$(dirname "$0")/.." || exit 1
# shellcheck source=test/lib.sh
. test/lib.sh
load_env

read -ra DC <<< "${COMPOSE:?COMPOSE no definida (usa make test-rotation)}"
URI="ldap://127.0.0.1:${LDAP_PORT}"
SVC_DN="cn=${LDAP_SERVICE_CN},ou=services,${LDAP_BASE_DN}"
ALICE="uid=alice,ou=users,${LDAP_BASE_DN}"

rotated=$(mktemp)
trap 'rm -f "$rotated"; make -s up >/dev/null 2>&1' EXIT
sed -E 's/^([A-Z0-9_]+_PASSWORD)=(.*)$/\1=\2-rotada/' "${ENV_FILE:-.env}" > "$rotated"

ldap_bind() { "${DC[@]}" exec -T ldap ldapwhoami -x -H "$URI" -D "$1" -w "$2"; }
# shellcheck disable=SC2016  # se expande dentro del contenedor
pg_tcp() { "${DC[@]}" exec -T -e PGPASSWORD="$1" postgres \
  sh -c 'psql -h "$(hostname -i)" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "select 1"'; }

echo "rotation: contraseñas nuevas sin borrar datos"
check "make up aplica el .env rotado" make -s up ENV_FILE="$rotated"
check "servicio: la contraseña nueva funciona" ldap_bind "$SVC_DN" "${LDAP_SERVICE_PASSWORD}-rotada"
check_fails "servicio: la vieja ya no" ldap_bind "$SVC_DN" "$LDAP_SERVICE_PASSWORD"
check "alice: la contraseña nueva funciona" ldap_bind "$ALICE" "${LDAP_SEED_USER_PASSWORD}-rotada"
check_output "postgres: la contraseña nueva funciona" '^1$' pg_tcp "${POSTGRES_PASSWORD}-rotada"
check_fails "postgres: la vieja ya no" pg_tcp "$POSTGRES_PASSWORD"

echo "rotation: vuelta al .env original"
check "make up vuelve a aplicar el .env original" make -s up
check "servicio: la contraseña original funciona de nuevo" ldap_bind "$SVC_DN" "$LDAP_SERVICE_PASSWORD"
check_output "postgres: la contraseña original funciona de nuevo" '^1$' pg_tcp "$POSTGRES_PASSWORD"

summary
