#!/usr/bin/env bash
# Tests del esqueleto del repo: .gitignore y generación de .env.
set -u
cd "$(dirname "$0")/.." || exit 1
# shellcheck source=test/lib.sh
. test/lib.sh

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf 'PLAIN=valor\nSECRET_A=__GENERATE__\nSECRET_B=__GENERATE__\n' > "$tmp/example"

echo "repo:"
check "git ignora .env" git check-ignore -q .env
check "make help lista el target env" sh -c 'make -s help | grep -q "env"'
check "make env genera el archivo" make -s env ENV_EXAMPLE="$tmp/example" ENV_FILE="$tmp/a.env"
check_no_output "no quedan marcadores __GENERATE__" '__GENERATE__' cat "$tmp/a.env"
check_output "conserva los valores no secretos" '^PLAIN=valor$' cat "$tmp/a.env"
check_output "genera secretos de 48 hex" '^SECRET_A=[0-9a-f]{48}$' cat "$tmp/a.env"
a=$(sed -n 's/^SECRET_A=//p' "$tmp/a.env")
b=$(sed -n 's/^SECRET_B=//p' "$tmp/a.env")
check "cada secreto es distinto" test "$a" != "$b"
check_output "el archivo solo lo lee su dueño (600)" '^-rw-------' ls -l "$tmp/a.env"
check_fails "no sobrescribe un .env existente" make -s env ENV_EXAMPLE="$tmp/example" ENV_FILE="$tmp/a.env"

summary
