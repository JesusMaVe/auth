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

printf '# Los valores __GENERATE__ se reemplazan\nSECRET_A=__GENERATE__\n' > "$tmp/comment-example"
check "un comentario que menciona __GENERATE__ no bloquea make env" \
  make -s env ENV_EXAMPLE="$tmp/comment-example" ENV_FILE="$tmp/comment.env"
check "la plantilla real .env.example genera un .env" make -s env ENV_FILE="$tmp/real.env"

printf 'PLAIN=valor\r\nSECRET_A=__GENERATE__\r\n' > "$tmp/crlf-example"
check "make env acepta una plantilla con CRLF" make -s env ENV_EXAMPLE="$tmp/crlf-example" ENV_FILE="$tmp/crlf.env"
check_output "con CRLF también genera el secreto" '^SECRET_A=[0-9a-f]{48}$' cat "$tmp/crlf.env"
check_no_output "con CRLF no quedan \\r en el archivo" $'\r' cat "$tmp/crlf.env"

mkdir -p "$tmp/bin"
printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/openssl"
chmod +x "$tmp/bin/openssl"
check_fails "si openssl falla, make env falla" \
  env PATH="$tmp/bin:$PATH" scripts/gen-env.sh "$tmp/example" "$tmp/noopenssl.env"
check_fails "si openssl falla, no deja un .env a medias" test -e "$tmp/noopenssl.env"

echo "repo: secretos como archivos"
# shellcheck disable=SC2016  # el $ es parte literal del valor de prueba
printf '# comentario\nPLAIN=valor\nX_PASSWORD=abc=d$e f\n' > "$tmp/s.env"
check "sync-secrets escribe los archivos" scripts/sync-secrets.sh "$tmp/s.env" "$tmp/secrets"
check_output "el directorio solo lo abre su dueño (700)" '^drwx------' ls -ld "$tmp/secrets"
# shellcheck disable=SC2016  # el $ es parte literal del valor de prueba
check "cada *_PASSWORD es un archivo con su valor exacto, sin salto de línea" \
  test "$(od -c "$tmp/secrets/x_password" | head -1)" = "$(printf 'abc=d$e f' | od -c | head -1)"
check_fails "las variables que no son *_PASSWORD no se escriben" test -e "$tmp/secrets/plain"
# inode <archivo>: ls -i es portable entre macOS y Linux (stat no lo es).
# shellcheck disable=SC2012
inode() { ls -i "$1" | awk '{print $1}'; }
inode_before=$(inode "$tmp/secrets/x_password")
printf 'X_PASSWORD=nuevo\n' > "$tmp/s.env"
scripts/sync-secrets.sh "$tmp/s.env" "$tmp/secrets" >/dev/null 2>&1
# Docker monta cada secreto por inodo: si cambiara, el contenedor en marcha dejaría de verlo.
check "al actualizar se conserva el inodo del archivo" \
  test "$(inode "$tmp/secrets/x_password")" = "$inode_before"
check_output "se actualiza al cambiar .env" '^nuevo$' cat "$tmp/secrets/x_password"

printf 'X_PASSWORD=YWJj=\n' > "$tmp/s.env"
scripts/sync-secrets.sh "$tmp/s.env" "$tmp/secrets" >/dev/null 2>&1
check_output "conserva un = final en el valor" '^YWJj=$' cat "$tmp/secrets/x_password"

printf 'X_PASSWORD=YWJj=\nY_PASSWORD=otro\n' > "$tmp/s.env"
check_output "informa los secretos nuevos o cambiados" '^y_password$' \
  scripts/sync-secrets.sh "$tmp/s.env" "$tmp/secrets"
check_no_output "no informa los que no cambiaron" 'x_password' \
  scripts/sync-secrets.sh "$tmp/s.env" "$tmp/secrets"
check_no_output "no informa nada si nada cambió" '.' \
  scripts/sync-secrets.sh "$tmp/s.env" "$tmp/secrets"
for bad in 'X_PASSWORD = valorsecreto' 'X_PASSWORD="valorsecreto"' $'X_PASSWORD=valorsecreto\r'; do
  printf '%s\n' "$bad" > "$tmp/bad.env"
  check_fails "rechaza una línea inválida: $(printf %q "$bad")" scripts/sync-secrets.sh "$tmp/bad.env" "$tmp/secrets"
  check_no_output "el error no muestra el valor: $(printf %q "$bad")" 'valorsecreto' \
    scripts/sync-secrets.sh "$tmp/bad.env" "$tmp/secrets"
done

summary
