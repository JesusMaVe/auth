# auth

Directorio LDAP y **auth-svc**, la API de LDAP que emite el JWT del dashboard. Los otros dos repos de la práctica: [`api`](https://github.com/JesusMaVe/api) (valida el JWT como Bearer) y [`frontend`](https://github.com/JesusMaVe/frontend). Todo corre en Docker.

Diseño: [`docs/superpowers/specs/2026-09-24-auth-dashboard-design.md`](docs/superpowers/specs/2026-09-24-auth-dashboard-design.md)

## Requisitos

- Docker Desktop / Docker Engine con Compose v2
- GNU Make, bash, OpenSSL 3 (en macOS: `brew install openssl`)
- Go 1.27 (tests de auth-svc)

## Primeros pasos

```bash
make env     # crea .env con secretos aleatorios (una sola vez)
make help    # lista los comandos disponibles
make test    # corre todos los tests
```

## Servicios de desarrollo

```bash
make up      # postgres + ldap + auth-svc (espera a que estén healthy)
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

`make up` escribe cada `*_PASSWORD` de `.env` en `secrets/` (ignorado por git), y Compose los monta como Docker secrets: los contenedores nunca reciben contraseñas como variables de entorno.

### Rotar contraseñas

ldap y postgres aplican las contraseñas de los secretos **en cada arranque**, y `make up` recrea los contenedores cuando algún secreto cambió. Para rotar, sin perder datos:

```bash
rm .env && make env   # o edita los *_PASSWORD de .env
make up               # detecta el cambio, recrea y aplica
```

## auth-svc (API de LDAP que emite el JWT)

`POST /token {"username","password"}` → `{"token":"<JWT EdDSA>"}`. Errores: 400 cuerpo inválido, 401 credenciales inválidas (genérico), 413 cuerpo demasiado grande, 429 rate limit (por IP y por usuario; detrás del proxy de Vite todas las peticiones comparten IP), 502 LDAP no disponible.

```bash
make up
curl -s -X POST 127.0.0.1:${AUTH_SVC_HOST_PORT}/token -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"<LDAP_SEED_USER_PASSWORD de tu .env>"}'
```

`make up` genera el par Ed25519 en `secrets/` si no existe. La **clave pública** (`make jwt-public-key`) se copia al repo `api` como `JWT_PUBLIC_KEY_FILE`; `JWT_ISSUER` y `JWT_AUDIENCE` deben coincidir en ambos repos.

## Estructura

| Carpeta | Contenido |
|---|---|
| `ldap/` | Imagen OpenLDAP propia |
| `auth-svc/` | Servicio Go: `POST /token` (search-then-bind + JWT EdDSA) |
| `postgres/` | Imagen oficial + entrypoint que aplica la contraseña en cada arranque |
| `test/` | Smoke tests de infraestructura |
| `scripts/` | Utilidades del repo (`gen-env.sh`, `sync-secrets.sh`, `gen-jwt-keys.sh`) |
| `docs/` | Spec y planes por etapa |
