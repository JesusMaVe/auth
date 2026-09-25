#!/usr/bin/env bash
# Genera un .env a partir de la plantilla, reemplazando __GENERATE__ por secretos aleatorios.
# Nunca sobrescribe un archivo existente.
set -euo pipefail

src=${1:?uso: gen-env.sh <plantilla> <destino>}
dst=${2:?uso: gen-env.sh <plantilla> <destino>}

if [[ -e $dst ]]; then
  echo "gen-env: $dst ya existe; bórralo si quieres regenerarlo" >&2
  exit 1
fi

umask 077
while IFS= read -r line || [[ -n $line ]]; do
  if [[ $line == *=__GENERATE__ ]]; then
    printf '%s=%s\n' "${line%%=*}" "$(openssl rand -hex 24)"
  else
    printf '%s\n' "$line"
  fi
done < "$src" > "$dst"

echo "gen-env: $dst creado"
