# auth

Dashboard con login contra LDAP, sesión por cookie HttpOnly (Go + `scs`) y JWT para clientes que no son navegador. Todo corre en Docker.

Diseño: [`docs/superpowers/specs/2026-09-24-auth-dashboard-design.md`](docs/superpowers/specs/2026-09-24-auth-dashboard-design.md)

## Requisitos

- Docker Desktop / Docker Engine con Compose v2
- GNU Make, bash, openssl

## Primeros pasos

```bash
make env     # crea .env con secretos aleatorios (una sola vez)
make help    # lista los comandos disponibles
make test    # corre todos los tests
```

## Servicios de desarrollo

```bash
make up      # postgres + ldap (espera a que estén healthy)
make logs
make down    # detiene
make clean   # detiene y BORRA los datos
```

- Postgres: `127.0.0.1:$POSTGRES_HOST_PORT`, base/usuario en `.env`.
- LDAP: `ldap://127.0.0.1:$LDAP_HOST_PORT`, base `LDAP_BASE_DN`.
  Usuarios semilla `alice` y `bob` (contraseña `LDAP_SEED_USER_PASSWORD` de tu `.env`):

```bash
ldapwhoami -x -H ldap://127.0.0.1:1389 -D uid=alice,ou=users,dc=auth,dc=local -W
```

El seed se carga solo en el **primer** arranque; para recargarlo: `make clean && make up`.

`make up` ejecuta antes `make secrets`, que escribe cada `*_PASSWORD` de `.env` en `secrets/` (ignorado por git). Compose los monta como Docker secrets: los contenedores nunca reciben contraseñas como variables de entorno.

## Estructura

| Carpeta | Contenido |
|---|---|
| `ldap/` | Imagen OpenLDAP propia |
| `test/` | Smoke tests de infraestructura |
| `scripts/` | Utilidades del repo (`gen-env.sh`, `sync-secrets.sh`) |
| `docs/` | Spec y planes por etapa |
