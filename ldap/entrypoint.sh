#!/bin/sh
# Inicializa slapd desde variables de entorno en el primer arranque y lo ejecuta en primer plano.
# Nunca imprime valores de variables (pueden ser secretos).
set -eu

ROOT_DIR=/var/lib/openldap
CONFIG_DIR=$ROOT_DIR/slapd.d
DATA_DIR=$ROOT_DIR/data
MARKER=$ROOT_DIR/.initialized
TEMPLATES_DIR=/etc/openldap/templates
SEED_DIR=/seed

die() { echo "entrypoint: $*" >&2; exit 1; }

# require VAR...: falla si alguna variable no está definida o está vacía.
require() {
  for var in "$@"; do
    eval "val=\${$var:-}"
    [ -n "$val" ] || die "falta la variable obligatoria $var"
  done
}

# Convierte cada LDAP_*_PASSWORD_FILE en LDAP_*_PASSWORD (Docker secrets).
load_secret_files() {
  for fvar in $(env | sed -n 's/^\(LDAP_[A-Z0-9_]*_PASSWORD_FILE\)=.*/\1/p'); do
    file=$(printenv "$fvar")
    [ -r "$file" ] || die "$fvar apunta a un archivo que no se puede leer"
    val=$(cat "$file")
    export "${fvar%_FILE}=$val"
    unset "$fvar"
  done
}

# Genera LDAP_*_PASSWORD_HASH (ARGON2) para cada LDAP_*_PASSWORD.
hash_passwords() {
  for var in $(env | sed -n 's/^\(LDAP_[A-Z0-9_]*_PASSWORD\)=.*/\1/p'); do
    eval "val=\${$var}"
    hash=$(printf '%s' "$val" | slappasswd -o module-path=/usr/lib/openldap -o module-load=argon2.so -h '{ARGON2}' -T /dev/stdin)
    export "${var}_HASH=$hash"
  done
}

# Borra de este proceso las contraseñas y sus hashes antes de ejecutar slapd.
forget_passwords() {
  for var in $(env | sed -n 's/^\(LDAP_[A-Z0-9_]*_PASSWORD\(_HASH\)\{0,1\}\)=.*/\1/p'); do
    unset "$var"
  done
}

# render <plantilla>: sustituye solo los ${VAR} que usa la plantilla; falla si alguno no está definido.
render() {
  # shellcheck disable=SC2016  # buscamos el texto literal ${VAR}
  vars=$(grep -o '\${[A-Za-z_][A-Za-z0-9_]*}' "$1" | sort -u || true)
  for placeholder in $vars; do
    var=${placeholder#??}
    var=${var%?}
    eval "val=\${$var:-}"
    [ -n "$val" ] || die "$(basename "$1") usa \${$var}, que no está definida"
  done
  envsubst "$vars" < "$1"
}

initialize() {
  echo "entrypoint: primer arranque, inicializando el directorio"
  rm -rf "$CONFIG_DIR" "$DATA_DIR"
  mkdir -p "$CONFIG_DIR" "$DATA_DIR"
  work=$(mktemp -d)

  hash_passwords
  render "$TEMPLATES_DIR/config.ldif" > "$work/config.ldif"
  {
    render "$TEMPLATES_DIR/base.ldif"
    for seed in "$SEED_DIR"/*.ldif; do
      [ -e "$seed" ] || continue
      echo
      render "$seed"
    done
  } > "$work/data.ldif"

  slapadd -n 0 -F "$CONFIG_DIR" -l "$work/config.ldif"
  slapadd -n 1 -F "$CONFIG_DIR" -l "$work/data.ldif"
  rm -rf "$work"
  touch "$MARKER"
}

require LDAP_BASE_DN LDAP_ORG_NAME LDAP_PORT LDAP_SERVICE_CN LDAP_DB_MAX_SIZE LDAP_LOG_LEVEL
echo "$LDAP_BASE_DN" | grep -Eq '^dc=[A-Za-z0-9-]+(,dc=[A-Za-z0-9-]+)*$' \
  || die "LDAP_BASE_DN debe tener la forma dc=ejemplo,dc=org"
LDAP_DC=${LDAP_BASE_DN%%,*}
export LDAP_DC="${LDAP_DC#dc=}"

load_secret_files
require LDAP_ADMIN_PASSWORD LDAP_SERVICE_PASSWORD

[ -f "$MARKER" ] || initialize
forget_passwords

exec slapd -d "$LDAP_LOG_LEVEL" -F "$CONFIG_DIR" -h "ldap://0.0.0.0:${LDAP_PORT}/"
