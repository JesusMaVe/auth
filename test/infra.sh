#!/usr/bin/env bash
# Tests de integración del compose de desarrollo (ldap con seed + auth-svc).
# Requiere los servicios levantados: make test-infra lo hace.
set -u
cd "$(dirname "$0")/.." || exit 1
# shellcheck source=test/lib.sh
. test/lib.sh
load_env

read -ra DC <<< "${COMPOSE:?COMPOSE no definida (usa make test-infra)}"
in_ldap() { "${DC[@]}" exec -T ldap "$@"; }

URI="ldap://127.0.0.1:${LDAP_PORT}"
USERS="ou=users,${LDAP_BASE_DN}"
SVC_DN="cn=${LDAP_SERVICE_CN},ou=services,${LDAP_BASE_DN}"
ALICE="uid=alice,${USERS}"
SVC_PW=/run/secrets/ldap_service_password
SEED_PW=/run/secrets/ldap_seed_user_password

as_svc()   { in_ldap ldapsearch -x -LLL -H "$URI" -D "$SVC_DN" -y "$SVC_PW" "$@"; }
as_alice() { in_ldap ldapsearch -x -LLL -H "$URI" -D "$ALICE" -y "$SEED_PW" "$@"; }
as_anon()  { in_ldap ldapsearch -x -LLL -H "$URI" "$@"; }
alice_whoami() { in_ldap ldapwhoami -x -H "$URI" -D "$ALICE" -y "$SEED_PW"; }
svc_modify_alice() {
  printf 'dn: %s\nchangetype: modify\nreplace: mail\nmail: x@example.org\n' "$ALICE" \
    | in_ldap ldapmodify -x -H "$URI" -D "$SVC_DN" -y "$SVC_PW"
}
# entryUUID de alice: una reinicialización lo regeneraría (no depende de los logs ni de si compose recrea el contenedor).
alice_uuid() { as_svc -b "$ALICE" -s base entryUUID | sed -n 's/^entryUUID: //p'; }

echo "infra: servicios"
check_no_output "postgres ya no vive en este repo (está en JesusMaVe/api)" '^postgres$' \
  "${DC[@]}" config --services

echo "infra: ldap"
check_output    "el Root DSE es legible de forma anónima" "namingContexts: ${LDAP_BASE_DN}" \
  as_anon -b "" -s base namingContexts
check_no_output "el anónimo no ve usuarios" 'dn: uid=' as_anon -b "$USERS" '(uid=*)'
check_output    "la cuenta de servicio encuentra a alice con mail" '^mail: ' \
  as_svc -b "$USERS" '(uid=alice)' uid cn mail
check_no_output "la cuenta de servicio no lee userPassword" 'userPassword' \
  as_svc -b "$USERS" '(uid=alice)' userPassword
check_output    "la cuenta de servicio lee los miembros del grupo" "member: ${ALICE}" \
  as_svc -b "ou=groups,${LDAP_BASE_DN}" '(cn=staff)' member
check_output    "la cuenta de servicio no puede escribir" 'Insufficient access' svc_modify_alice
check_output    "alice se autentica" "dn:${ALICE}" alice_whoami
check_output    "contraseña errónea → Invalid credentials (49)" 'Invalid credentials \(49\)' \
  in_ldap ldapwhoami -x -H "$URI" -D "$ALICE" -w contraseña-incorrecta
check_output    "alice se lee a sí misma" "dn: ${ALICE}" as_alice -b "$ALICE" -s base
check_no_output "alice no puede leer a bob" 'dn: uid=bob' as_alice -b "$USERS" '(uid=bob)'
check_no_output "cn=config no es legible" 'olcRootPW' as_anon -b cn=config

echo "infra: reinicio"
before=$(alice_uuid)
"${DC[@]}" restart ldap >/dev/null 2>&1
"${DC[@]}" up -d --wait ldap >/dev/null 2>&1
check "hay un entryUUID de referencia" test -n "$before"
# -n evita el pase en falso: si el bind falla, ambos valores serían vacíos e iguales.
check "no se vuelve a inicializar al reiniciar" test -n "$before" -a "$(alice_uuid)" = "$before"
check_output "alice sigue autenticándose tras el reinicio" "dn:${ALICE}" alice_whoami

echo "infra: auth-svc"
AUTH="http://127.0.0.1:${AUTH_SVC_HOST_PORT}"
token_req() { curl -s -X POST "$AUTH/token" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}"; }
token_status() { curl -s -o /dev/null -w '%{http_code}' -X POST "$AUTH/token" \
  -H 'Content-Type: application/json' -d "{\"username\":\"$1\",\"password\":\"$2\"}"; }
# jwt_payload <json>: decodifica (sin verificar) el payload del token de la respuesta.
jwt_payload() {
  local p
  p=$(sed -E 's/.*"token":"[^.]+\.([^.]+)\..*/\1/' <<< "$1" | tr '_-' '/+')
  while (( ${#p} % 4 )); do p+='='; done
  base64 -d <<< "$p" 2>/dev/null
}

check_output "healthz responde" '"status":"ok"' curl -s "$AUTH/healthz"
resp=$(token_req alice "$LDAP_SEED_USER_PASSWORD")
check_output "alice obtiene un JWT" '"token":"[^".]+\.[^".]+\.[^".]+"' echo "$resp"
check_output "el JWT es de alice" '"sub":"alice"' jwt_payload "$resp"
check_output "el JWT trae el emisor configurado" "\"iss\":\"${JWT_ISSUER}\"" jwt_payload "$resp"
check_output "contraseña errónea → 401" '^401$' token_status alice contraseña-incorrecta
check_output "usuario inexistente → 401" '^401$' token_status nadie "$LDAP_SEED_USER_PASSWORD"
check_no_output "los logs no contienen la contraseña" "$LDAP_SEED_USER_PASSWORD" "${DC[@]}" logs auth-svc
check_output "sin puerto publicado fuera de 127.0.0.1" '127\.0\.0\.1' "${DC[@]}" port auth-svc "$AUTH_SVC_PORT"

summary
