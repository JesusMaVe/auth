#!/usr/bin/env bash
# Escribe cada *_PASSWORD de un .env como archivo <dir>/<nombre en minúsculas>,
# para montarlo como Docker secret (`file:`), lo que funciona también con contenedores read_only.
# Imprime el nombre de cada secreto nuevo o cambiado (uno por línea).
# Falla (nombrando la variable, nunca su valor) ante líneas que compose y bash leerían distinto.
set -euo pipefail

src=${1:?uso: sync-secrets.sh <archivo .env> <directorio>}
dst=${2:?uso: sync-secrets.sh <archivo .env> <directorio>}

# El directorio (700) protege los secretos en el host; los archivos son 644 porque
# los contenedores corren con otro uid (non-root) y necesitan leerlos.
install -d -m 700 "$dst"
chmod 700 "$dst"

while IFS= read -r line || [[ -n $line ]]; do
  [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
  key=${line%%=*}
  value=${line#*=}
  [[ $key =~ _PASSWORD[[:space:]]*$ ]] || continue
  if [[ ! $key =~ ^[A-Z0-9_]+$ ]]; then
    echo "sync-secrets: $key: sin espacios alrededor de '='" >&2
    exit 1
  fi
  if [[ $value == *$'\r'* || $value == \"* || $value == \'* ]]; then
    echo "sync-secrets: $key: el valor no puede llevar comillas ni fin de línea CRLF" >&2
    exit 1
  fi
  name=$(tr '[:upper:]' '[:lower:]' <<< "$key")
  file="$dst/$name"
  # Solo se escriben (e informan) los que cambian: `make up` recrea los contenedores si hay alguno.
  [[ -f $file && $(< "$file") == "$value" ]] && continue
  # Se escribe en el mismo archivo (sin mv): Docker monta cada secreto por inodo.
  (umask 022 && printf '%s' "$value" > "$file")
  echo "$name"
done < "$src"
