#!/usr/bin/env bash
# Escribe cada *_PASSWORD de un .env como archivo <dir>/<nombre en minúsculas>,
# para montarlo como Docker secret (`file:`), lo que funciona también con contenedores read_only.
set -euo pipefail

src=${1:?uso: sync-secrets.sh <archivo .env> <directorio>}
dst=${2:?uso: sync-secrets.sh <archivo .env> <directorio>}

# El directorio (700) protege los secretos en el host; los archivos son 644 porque
# los contenedores corren con otro uid (non-root) y necesitan leerlos.
install -d -m 700 "$dst"
chmod 700 "$dst"

while IFS='=' read -r key value || [[ -n $key ]]; do
  [[ $key =~ ^[A-Z0-9_]+_PASSWORD$ ]] || continue
  file="$dst/$(tr '[:upper:]' '[:lower:]' <<< "$key")"
  # Se escribe en el mismo archivo (sin mv): Docker monta cada secreto por inodo.
  (umask 022 && printf '%s' "$value" > "$file")
done < "$src"
