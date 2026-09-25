#!/usr/bin/env bash
# Genera un .env a partir de la plantilla, reemplazando __GENERATE__ por secretos aleatorios.
# Nunca sobrescribe un archivo existente y no deja archivos a medias si algo falla.
set -euo pipefail

src=${1:?uso: gen-env.sh <plantilla> <destino>}
dst=${2:?uso: gen-env.sh <plantilla> <destino>}

if [[ -e $dst ]]; then
  echo "gen-env: $dst ya existe; bórralo si quieres regenerarlo" >&2
  exit 1
fi

umask 077
tmp=$(mktemp "$dst.XXXXXX")
trap 'rm -f "$tmp"' EXIT

while IFS= read -r line || [[ -n $line ]]; do
  line=${line%$'\r'}
  if [[ $line == *=__GENERATE__ ]]; then
    # En su propia línea para que un fallo de openssl dispare set -e.
    secret=$(openssl rand -hex 24)
    [[ ${#secret} -eq 48 ]] || { echo "gen-env: openssl no generó un secreto válido" >&2; exit 1; }
    printf '%s=%s\n' "${line%%=*}" "$secret"
  else
    printf '%s\n' "$line"
  fi
done < "$src" > "$tmp"

if grep -q '__GENERATE__' "$tmp"; then
  echo "gen-env: quedaron marcadores __GENERATE__ sin reemplazar" >&2
  exit 1
fi

mv "$tmp" "$dst"
trap - EXIT
echo "gen-env: $dst creado"
