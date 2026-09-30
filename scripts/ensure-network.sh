#!/usr/bin/env bash
# Crea la red Docker compartida por auth, api y frontend si no existe. Si existe con otra subnet
# falla: TRUSTED_PROXIES de auth-svc depende de esa subnet.
set -euo pipefail

name=${1:?uso: ensure-network.sh <nombre> <subnet>}
subnet=${2:?uso: ensure-network.sh <nombre> <subnet>}

if current=$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "$name" 2>/dev/null); then
  [[ $current == "$subnet" ]] && exit 0
  echo "ensure-network: la red $name existe con la subnet $current (se esperaba $subnet)" >&2
  exit 1
fi
docker network create --driver bridge --subnet "$subnet" "$name" >/dev/null
