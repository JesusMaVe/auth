#!/usr/bin/env bash
# Tests de la imagen ldap en aislamiento (docker run, sin compose).
# Usa valores de prueba propios; no depende de .env.
set -u
cd "$(dirname "$0")/.." || exit 1
# shellcheck source=test/lib.sh
. test/lib.sh

IMG=${LDAP_TEST_IMAGE:?LDAP_TEST_IMAGE no definida (usa make test-ldap-image)}
PORT=1389
BASE=dc=test,dc=local
URI="ldap://127.0.0.1:$PORT"
BASE_ENV=(-e "LDAP_BASE_DN=$BASE" -e LDAP_ORG_NAME=Test -e "LDAP_PORT=$PORT"
          -e LDAP_SERVICE_CN=svc -e LDAP_DB_MAX_SIZE=104857600 -e LDAP_LOG_LEVEL=stats)
PW_ENV=(-e LDAP_ADMIN_PASSWORD=admin-test -e LDAP_SERVICE_PASSWORD=svc-test)

# run_once <docker-run-args...>: arranca el contenedor, espera hasta 30 s a que termine
# e imprime sus logs. Devuelve su código de salida, o 0 si sigue corriendo (no falló).
run_once() {
  local cid code
  cid=$(docker run -d "$@" "$IMG") || return 1
  for _ in $(seq 30); do
    [[ $(docker inspect -f '{{.State.Running}}' "$cid") == false ]] && break
    sleep 1
  done
  docker logs "$cid" 2>&1
  code=$(docker inspect -f '{{if .State.Running}}0{{else}}{{.State.ExitCode}}{{end}}' "$cid")
  docker rm -fv "$cid" >/dev/null
  return "$code"
}

echo "ldap-image: configuración inválida"
check_fails  "sin variables → sale con error" run_once
check_output "sin variables → nombra LDAP_BASE_DN" 'LDAP_BASE_DN' run_once
check_output "falta un secreto → lo nombra" 'LDAP_ADMIN_PASSWORD' \
  run_once "${BASE_ENV[@]}" -e LDAP_SERVICE_PASSWORD=valor-que-no-debe-salir
check_no_output "el error no muestra valores de secretos" 'valor-que-no-debe-salir' \
  run_once "${BASE_ENV[@]}" -e LDAP_SERVICE_PASSWORD=valor-que-no-debe-salir
check_output "base DN inválido → error" 'LDAP_BASE_DN debe' \
  run_once "${BASE_ENV[@]}" "${PW_ENV[@]}" -e LDAP_BASE_DN=o=foo

seed=$(mktemp -d)
# shellcheck disable=SC2016  # el ${...} es literal: es la plantilla
printf 'dn: cn=x,${LDAP_BASE_DN}\nobjectClass: organizationalRole\ncn: ${NO_DEFINIDA}\n' > "$seed/x.ldif"
chmod -R a+rX "$seed"
check_output "plantilla con variable no definida → la nombra" 'NO_DEFINIDA' \
  run_once "${BASE_ENV[@]}" "${PW_ENV[@]}" -v "$seed:/seed:ro"
check_fails "plantilla con variable no definida → sale con error" \
  run_once "${BASE_ENV[@]}" "${PW_ENV[@]}" -v "$seed:/seed:ro"
rm -rf "$seed"

echo "ldap-image: primer arranque fallido"
# Un seed con un DN duplicado hace fallar slapadd -n 1 después de que -n 0 ya se cargó.
bad_seed=$(mktemp -d)
# shellcheck disable=SC2016  # el ${...} es literal: es la plantilla
# cn=probe se carga antes del duplicado: si el reintento no empezara de cero, seguiría ahí.
printf 'dn: cn=probe,ou=services,${LDAP_BASE_DN}\nobjectClass: organizationalRole\ncn: probe\n\ndn: ou=users,${LDAP_BASE_DN}\nobjectClass: organizationalUnit\nou: users\n' > "$bad_seed/dup.ldif"
chmod -R a+rX "$bad_seed"
vol="auth-ldap-test-$$"
check_fails "un seed inválido hace fallar el primer arranque" \
  run_once "${BASE_ENV[@]}" "${PW_ENV[@]}" -v "$vol:/var/lib/openldap" -v "$bad_seed:/seed:ro"
retry=$(docker run -d "${BASE_ENV[@]}" "${PW_ENV[@]}" -v "$vol:/var/lib/openldap" "$IMG")
check "el siguiente arranque reintenta desde cero y llega a healthy" wait_healthy "$retry"
check "tras el reintento la cuenta de servicio se autentica" \
  docker exec "$retry" ldapwhoami -x -H "$URI" -D "cn=svc,ou=services,$BASE" -w svc-test
check_no_output "tras el reintento no queda nada del intento fallido" 'dn: cn=probe' \
  docker exec "$retry" ldapsearch -x -LLL -H "$URI" -D "cn=admin,$BASE" -w admin-test -b "ou=services,$BASE" '(cn=probe)'
check_output "control: el admin sí puede buscar en ou=services" "dn: cn=svc,ou=services,$BASE" \
  docker exec "$retry" ldapsearch -x -LLL -H "$URI" -D "cn=admin,$BASE" -w admin-test -b "ou=services,$BASE" '(cn=svc)'
docker rm -fv "$retry" >/dev/null 2>&1
docker volume rm "$vol" >/dev/null 2>&1
rm -rf "$bad_seed"

echo "ldap-image: rotación de contraseñas"
# Mismo volumen, segundo arranque con otras contraseñas: deben aplicarse sin reinicializar.
seed=$(mktemp -d)
# shellcheck disable=SC2016  # el ${...} es literal: es la plantilla
printf 'dn: uid=u1,ou=users,${LDAP_BASE_DN}\nobjectClass: inetOrgPerson\nuid: u1\ncn: U1\nsn: U1\nuserPassword: ${LDAP_SEED_USER_PASSWORD_HASH}\n' > "$seed/u.ldif"
chmod -R a+rX "$seed"
vol="auth-ldap-rot-$$"
boot() { docker run -d "${BASE_ENV[@]}" -v "$vol:/var/lib/openldap" -v "$seed:/seed:ro" \
  -e LDAP_ADMIN_PASSWORD="admin-$1" -e LDAP_SERVICE_PASSWORD="svc-$1" -e LDAP_SEED_USER_PASSWORD="seed-$1" "$IMG"; }
whoami_as() { docker exec "$1" ldapwhoami -x -H "$URI" -D "$2" -w "$3"; }
uuid_of_u1() { docker exec "$1" ldapsearch -x -LLL -H "$URI" -D "cn=admin,$BASE" -w "admin-$2" \
  -b "uid=u1,ou=users,$BASE" -s base entryUUID | sed -n 's/^entryUUID: //p'; }

rot=$(boot viejo)
wait_healthy "$rot"
uuid_before=$(uuid_of_u1 "$rot" viejo)
docker rm -f "$rot" >/dev/null
rot=$(boot nuevo)
check "arranca con contraseñas nuevas sobre el mismo volumen" wait_healthy "$rot"
check "admin: la contraseña nueva funciona" whoami_as "$rot" "cn=admin,$BASE" admin-nuevo
check_fails "admin: la vieja ya no" whoami_as "$rot" "cn=admin,$BASE" admin-viejo
check "servicio: la contraseña nueva funciona" whoami_as "$rot" "cn=svc,ou=services,$BASE" svc-nuevo
check_fails "servicio: la vieja ya no" whoami_as "$rot" "cn=svc,ou=services,$BASE" svc-viejo
check "usuario semilla: la contraseña nueva funciona" whoami_as "$rot" "uid=u1,ou=users,$BASE" seed-nuevo
check_fails "usuario semilla: la vieja ya no" whoami_as "$rot" "uid=u1,ou=users,$BASE" seed-viejo
check "no se reinicializó (entryUUID no vacío y sin cambios)" \
  test -n "$uuid_before" -a "$(uuid_of_u1 "$rot" nuevo)" = "$uuid_before"
check_no_output "los logs no muestran contraseñas" 'admin-nuevo|svc-nuevo|seed-nuevo' docker logs "$rot"
docker rm -fv "$rot" >/dev/null 2>&1
docker volume rm "$vol" >/dev/null 2>&1
rm -rf "$seed"

echo "ldap-image: arranque válido"
WEIRD='p@$$ w/o\rd&"x'
cid=$(docker run -d -v /var/lib/openldap "${BASE_ENV[@]}" \
  -e LDAP_ADMIN_PASSWORD="$WEIRD" -e LDAP_SERVICE_PASSWORD="$WEIRD" "$IMG")
trap 'docker rm -fv "$cid" >/dev/null 2>&1' EXIT

check "llega a healthy" wait_healthy "$cid"
check "bind de la cuenta de servicio con contraseña con caracteres especiales" \
  docker exec "$cid" ldapwhoami -x -H "$URI" -D "cn=svc,ou=services,$BASE" -w "$WEIRD"
check "bind del admin con contraseña con caracteres especiales" \
  docker exec "$cid" ldapwhoami -x -H "$URI" -D "cn=admin,$BASE" -w "$WEIRD"
check_fails "contraseña errónea es rechazada" \
  docker exec "$cid" ldapwhoami -x -H "$URI" -D "cn=svc,ou=services,$BASE" -w incorrecta
# userPassword es binario → ldapsearch lo devuelve en base64; e0FSR09OMn0 = "{ARGON2}"
check_output "el hash guardado es ARGON2" '^userPassword:: e0FSR09OMn0' \
  docker exec "$cid" ldapsearch -x -LLL -H "$URI" -D "cn=admin,$BASE" -w "$WEIRD" \
    -b "cn=svc,ou=services,$BASE" userPassword -o ldif-wrap=no
# shellcheck disable=SC2016  # $(id -u) debe expandirse dentro del contenedor
check_fails "no corre como root" docker exec "$cid" sh -c 'test "$(id -u)" = 0'
check_no_output "slapd no conserva contraseñas en su entorno" 'PASSWORD' \
  docker exec "$cid" sh -c 'tr "\0" "\n" < /proc/1/environ'

summary
