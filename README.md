# auth

Directorio LDAP y **auth-svc**, la API de LDAP que emite el JWT del dashboard. Los otros dos repos de la práctica: [`api`](https://github.com/JesusMaVe/api) (valida el JWT como Bearer) y [`frontend`](https://github.com/JesusMaVe/frontend). Todo corre en Docker.

Diseño: [`docs/superpowers/specs/2026-09-24-auth-dashboard-design.md`](docs/superpowers/specs/2026-09-24-auth-dashboard-design.md)

## Entrega de la práctica

| Repo | Qué hace |
|---|---|
| [`JesusMaVe/auth`](https://github.com/JesusMaVe/auth) (este) | OpenLDAP + **auth-svc**: `POST /token` valida usuario y contraseña contra LDAP y regresa un **JWT** (EdDSA) |
| [`JesusMaVe/api`](https://github.com/JesusMaVe/api) | Backend de items: recibe el JWT como **`Authorization: Bearer`**, lo valida y atiende `GET` y `POST /api/items` (Postgres) |
| [`JesusMaVe/frontend`](https://github.com/JesusMaVe/frontend) | Login, dashboard con el listado y página para agregar elementos; inyecta el JWT en **cada** request y lo imprime con `console.log` |

```
Navegador ──▶ frontend (Vite, 127.0.0.1:5173)
                ├─ /auth/token ──▶ auth-svc (127.0.0.1:8081) ──▶ OpenLDAP      → JWT
                └─ /api/items + Authorization: Bearer <JWT> ──▶ api (127.0.0.1:8082) ──▶ Postgres
```

### Levantar todo desde cero

Requisitos: Docker con Compose v2, GNU Make, OpenSSL 3, Node 26. Los tres repos van como carpetas hermanas:

```bash
mkdir practica && cd practica
git clone https://github.com/JesusMaVe/auth.git
git clone https://github.com/JesusMaVe/api.git
git clone https://github.com/JesusMaVe/frontend.git

(cd auth && make env && make up)       # ldap + auth-svc; genera el par de claves del JWT en auth/secrets/
(cd api && make env && make up)        # postgres + api; importa la clave pública desde ../auth automáticamente
(cd frontend && make env && make install && make dev)   # http://127.0.0.1:5173
```

- Usuario de prueba: **`alice`** (o `bob`). Contraseña: `sed -n 's/^LDAP_SEED_USER_PASSWORD=//p' auth/.env`.
- El orden importa: `api` necesita la clave pública que genera `auth`. Si `auth` rota su clave, basta con volver a correr `make up` en `api`.
- Para comprobar sin navegador:

```bash
PW=$(sed -n 's/^LDAP_SEED_USER_PASSWORD=//p' auth/.env)
TOKEN=$(curl -s -X POST 127.0.0.1:5173/auth/token -H 'Content-Type: application/json' \
  -d "{\"username\":\"alice\",\"password\":\"$PW\"}" | sed -E 's/.*"token":"([^"]+)".*/\1/')
curl -s -o /dev/null -w '%{http_code}\n' 127.0.0.1:5173/api/items          # 401: sin token
curl -s 127.0.0.1:5173/api/items -H "Authorization: Bearer $TOKEN"          # 200: con token
```

### Guion del video

Antes de grabar: los tres servicios arriba, el navegador en http://127.0.0.1:5173 con **DevTools** abierto (pestañas **Console** y **Network**, filtro `Fetch/XHR`, "Preserve log" activado).

1. **Los tres repos.** Mostrar en GitHub `auth`, `api` y `frontend` (tabla de arriba).
2. **Login contra la API de LDAP.** Iniciar sesión con `alice`. En **Network**: `POST /auth/token` responde `200` con `{"token":"eyJ…"}` (el JWT que regresa auth-svc).
3. **El JWT en cada request.**
   - **Console:** aparece `[api] GET /api/items Bearer eyJ…` (el `console.log` que hace `src/api/client.ts` en cada request; `VITE_LOG_JWT=true` en `frontend/.env`).
   - **Network:** abrir `GET /api/items` → *Request Headers* → `Authorization: Bearer eyJ…`, el mismo token de la consola.
4. **Dashboard.** El listado de elementos que vino de la API.
5. **Agregar un elemento.** "Agregar" → título y descripción → "Guardar". En **Console** aparece `[api] POST /api/items Bearer eyJ…` y, al volver, `[api] GET /api/items Bearer eyJ…`; en **Network**, ambas requests con el header `Authorization`. El elemento nuevo aparece en el dashboard.
6. **El backend exige el token.** En la **Console** del navegador:
   ```js
   fetch('/api/items').then((r) => r.status)   // 401: sin Bearer la API rechaza la request
   ```
7. **Cerrar sesión.** "Cerrar sesión" borra el token; volver a `/dashboard` pide login otra vez.
8. **(Opcional) El código.** `frontend/src/api/client.ts` (inyección del Bearer + `console.log`) y `api/internal/auth/middleware.go` (`RequireBearer`).

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
make up      # ldap + auth-svc (espera a que estén healthy)
make logs
make down    # detiene
make clean   # detiene y BORRA los datos
```

- LDAP: `ldap://127.0.0.1:$LDAP_HOST_PORT`, base `LDAP_BASE_DN`.
  Usuarios semilla `alice` y `bob` (contraseña `LDAP_SEED_USER_PASSWORD` de tu `.env`):

```bash
ldapwhoami -x -H ldap://127.0.0.1:1389 -D uid=alice,ou=users,dc=auth,dc=local -W
```

El seed se carga solo en el **primer** arranque; para recargarlo: `make clean && make up`.

`make up` escribe cada `*_PASSWORD` de `.env` en `secrets/` (ignorado por git), y Compose los monta como Docker secrets: los contenedores nunca reciben contraseñas como variables de entorno.

### Rotar contraseñas

ldap aplica las contraseñas de los secretos **en cada arranque**, y `make up` recrea los contenedores cuando algún secreto cambió. Para rotar, sin perder datos:

```bash
rm .env && make env   # o edita los *_PASSWORD de .env
make up               # detecta el cambio, recrea y aplica
```

## auth-svc (API de LDAP que emite el JWT)

`POST /token {"username","password"}` → `{"token":"<JWT EdDSA>"}`. Errores: 400 cuerpo inválido, 401 credenciales inválidas (genérico), 413 cuerpo demasiado grande, 429 rate limit (por IP y por usuario; detrás de cualquier proxy —Vite o nginx— todas las peticiones comparten IP, así que el límite por IP es global), 502 LDAP no disponible.

```bash
make up
curl -s -X POST 127.0.0.1:${AUTH_SVC_HOST_PORT}/token -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"<LDAP_SEED_USER_PASSWORD de tu .env>"}'
```

`make up` genera el par Ed25519 en `secrets/` si no existe. La **clave pública** (`make jwt-public-key`) se copia al repo `api` como `JWT_PUBLIC_KEY_FILE`; `JWT_ISSUER` y `JWT_AUDIENCE` deben coincidir en ambos repos.

Postgres vive en el repo [`api`](https://github.com/JesusMaVe/api).

## Estructura

| Carpeta | Contenido |
|---|---|
| `ldap/` | Imagen OpenLDAP propia |
| `auth-svc/` | Servicio Go: `POST /token` (search-then-bind + JWT EdDSA) |
| `test/` | Smoke tests de infraestructura |
| `scripts/` | Utilidades del repo (`gen-env.sh`, `sync-secrets.sh`, `gen-jwt-keys.sh`) |
| `docs/` | Spec y planes por etapa |
