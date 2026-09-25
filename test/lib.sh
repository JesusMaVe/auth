#!/usr/bin/env bash
# Helpers mínimos de aserción para los smoke tests en shell.
# Uso: source test/lib.sh; check ...; summary

FAILED=0

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }

# check <desc> <cmd...>: el comando debe terminar con código 0.
check() {
  local desc=$1; shift
  if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}

# check_fails <desc> <cmd...>: el comando debe fallar.
check_fails() {
  local desc=$1; shift
  if "$@" >/dev/null 2>&1; then fail "$desc"; else pass "$desc"; fi
}

# check_output <desc> <regex> <cmd...>: stdout+stderr debe contener <regex> (ERE).
check_output() {
  local desc=$1 re=$2; shift 2
  if "$@" 2>&1 | grep -Eq -- "$re"; then pass "$desc"; else fail "$desc"; fi
}

# check_no_output <desc> <regex> <cmd...>: stdout+stderr NO debe contener <regex>.
check_no_output() {
  local desc=$1 re=$2; shift 2
  if "$@" 2>&1 | grep -Eq -- "$re"; then fail "$desc"; else pass "$desc"; fi
}

# wait_healthy <container-id>: espera hasta 60 s a que el healthcheck esté "healthy".
wait_healthy() {
  local status
  for _ in $(seq 60); do
    status=$(docker inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null)
    case $status in
      healthy) return 0 ;;
      unhealthy) return 1 ;;
    esac
    sleep 1
  done
  return 1
}

# load_env: exporta las variables de ${ENV_FILE:-.env}.
load_env() {
  local file=${ENV_FILE:-.env}
  [[ -f $file ]] || { echo "falta $file: ejecuta 'make env'" >&2; exit 1; }
  set -a
  # shellcheck disable=SC1090
  . "$file"
  set +a
}

summary() {
  if [[ $FAILED -eq 0 ]]; then
    echo "OK"
  else
    echo "$FAILED test(s) fallaron" >&2
    exit 1
  fi
}
