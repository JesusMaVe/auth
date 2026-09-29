#!/usr/bin/env bash
# Genera el par Ed25519 del JWT en <dir> si no existe: jwt_private_key (Docker secret de auth-svc)
# y jwt_public_key (se copia al repo api como JWT_PUBLIC_KEY_FILE). Nunca sobrescribe la privada.
# Imprime "jwt_private_key" si la creó, para que `make up` recree los contenedores.
set -euo pipefail

dir=${1:?uso: gen-jwt-keys.sh <directorio>}
priv="$dir/jwt_private_key"
pub="$dir/jwt_public_key"

openssl version | grep -q '^OpenSSL 3' \
  || { echo "gen-jwt-keys: se requiere OpenSSL 3 (en macOS: brew install openssl)" >&2; exit 1; }

install -d -m 700 "$dir"
if [[ -f $priv ]]; then
  [[ -f $pub ]] || { openssl pkey -in "$priv" -pubout -out "$pub"; chmod 644 "$pub"; }
  exit 0
fi

tmp=$(mktemp "$dir/.jwt.XXXXXX")
trap 'rm -f "$tmp"' EXIT
openssl genpkey -algorithm ed25519 -out "$tmp"
openssl pkey -in "$tmp" -pubout -out "$pub"
# 644 como los demás secretos: el contenedor corre con otro uid (non-root); el directorio es 700.
chmod 644 "$tmp" "$pub"
mv "$tmp" "$priv"
trap - EXIT
echo "jwt_private_key"
