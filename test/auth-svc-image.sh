#!/usr/bin/env bash
# Tests de la imagen auth-svc en aislamiento (docker run, sin compose).
set -u
cd "$(dirname "$0")/.." || exit 1
# shellcheck source=test/lib.sh
. test/lib.sh

IMG=${AUTH_SVC_TEST_IMAGE:?AUTH_SVC_TEST_IMAGE no definida (usa make test-auth-svc-image)}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf 'valor-que-no-debe-salir' > "$tmp/pw"
chmod -R a+rX "$tmp"

echo "auth-svc-image:"
check_fails  "sin variables → sale con error" docker run --rm "$IMG"
check_output "sin variables → nombra AUTH_SVC_PORT" 'AUTH_SVC_PORT' docker run --rm "$IMG"
check_no_output "el error no muestra el valor de un secreto" 'valor-que-no-debe-salir' \
  docker run --rm -v "$tmp:/s:ro" -e LDAP_BIND_PASSWORD_FILE=/s/pw "$IMG"
check_output "corre como non-root (uid 65532)" '^65532:65532$' docker image inspect -f '{{.Config.User}}' "$IMG"
check_output "tiene healthcheck" 'healthcheck' docker image inspect -f '{{.Config.Healthcheck.Test}}' "$IMG"

summary
