# Plan: Dashboard con login LDAP + JWT Bearer (Go + React + Docker)

## Contexto
Práctica de la clase: un dashboard con **pantalla de login**, un **dashboard inicial** con el listado de elementos que le gustan al usuario (videojuegos, ropa, zapatos…) y **una pantalla aparte para agregar elementos**; al volver, el listado muestra los nuevos. Todo corre en Docker.

Requerimientos de la práctica (fuente de verdad):
- El login consume **la API de LDAP, que regresa un JWT**.
- El frontend **inyecta el JWT** en cada request con la librería elegida (**`fetch` + TanStack Query**, con un único wrapper `api.ts`).
- El backend recibe el JWT como **`Authorization: Bearer`** y lo valida antes de `GET` y `POST` de items.
- **Tres repositorios en GitHub**: `auth` (LDAP + API de LDAP/JWT), `api` (backend de items) y `frontend`.
- Entregable: video que muestra que **el JWT va en cada request** (`console.log`) y los 3 repos.

Reglas del proyecto: desarrollo por etapas, **tests en cada feature (TDD)**, **nada hardcodeado** (todo por variables de entorno o secrets), seguridad como requisito, KISS/DRY/YAGNI.

### Decisiones ya tomadas
| Tema | Decisión |
|---|---|
| API de LDAP que regresa el JWT | **Nuestro `auth-svc`** (repo `auth`). La API de la clase (`JesusMaVe/security-api`) no emite JWT (usa sesión opaca por cookie + `x-api-key`), así que no se usa. De la clase (`security-ldap`/`security-api`) se toma el modelo: `ou=users` con `inetOrgPerson`, usuarios semilla alice/bob, cuenta de servicio de solo lectura y **search-then-bind** |
| LDAP | Imagen OpenLDAP propia (sin imágenes de terceros), `LDAP_BASE_DN` por env |
| JWT en el navegador | El frontend **guarda el JWT** (memoria + `sessionStorage`, se pierde al cerrar la pestaña) y lo manda como `Authorization: Bearer` en cada request. Con `VITE_LOG_JWT=true` el wrapper hace `console.log` del JWT en **cada** request (para el video); en prod va en `false` |
| Autenticación en la API | **Solo Bearer**. Sin cookies ni sesiones de servidor (sin scs/pgxstore, sin `/login`, `/logout` ni `/me` en la API). Sin cookies no hay CSRF, así que no se usa `CrossOriginProtection` |
| Clave del JWT | EdDSA. La privada solo la tiene auth-svc; la **pública** se copia a la API como Docker secret (`JWT_PUBLIC_KEY_FILE`) |
| Elemento del listado | Genérico: `id, title, description, created_by, created_at`; `created_by` = `sub` del JWT |
| Agregar elemento | Ruta propia `/items/new`; al guardar se invalida la query del listado y se vuelve a `/dashboard` |
| Repos | **Tres repos públicos**: `JesusMaVe/auth`, `JesusMaVe/api`, `JesusMaVe/frontend`. Cada uno con su Makefile, CI, `CLAUDE.md` y docker-compose |
| Postgres | Pertenece a la API: la imagen `postgres/` (con rotación de contraseña) se mueve de `auth` a `api` |

## Arquitectura

```
                   ┌──── POST /auth/token ────▶ auth-svc (Go) ──search-then-bind──▶ ldap (OpenLDAP)      [repo auth]
Browser ─▶ frontend│                               │ firma JWT (EdDSA, privada)
  (Vite dev /      └──── /api/* + Bearer JWT ──▶ api (Go) ──▶ postgres (items)                           [repo api]
   nginx prod)                                     │ verifica JWT con la pública
[repo frontend]
```

El navegador habla con un **solo origen** (el del frontend): el proxy de Vite (dev) o nginx (prod) reenvía `/auth/*` a auth-svc y `/api/*` a la API. Los destinos salen de env (`AUTH_SVC_URL`, `API_URL`). Así no hace falta CORS. Cada repo levanta su compose y publica su puerto solo en `127.0.0.1`.

- **ldap** (repo `auth`, imagen propia en `/ldap`): Alpine + OpenLDAP 2.6 (`slapd`, `mdb`). El `entrypoint.sh` genera `cn=config` desde env en el primer arranque, hashea contraseñas (ARGON2) y carga `ou=users`, `ou=groups`, `ou=services` + cuenta de servicio de auth-svc. Contraseñas por `*_FILE`; se aplican en cada arranque (rotación). Seed de desarrollo (alice, bob) solo en `docker-compose.dev.yml`. Non-root, solo lectura, healthcheck.
- **auth-svc** (repo `auth`): `POST /token {username,password}` → search-then-bind LDAP (`go-ldap/ldap/v3`, filtros escapados) → `{token}` firmado con **EdDSA**. `make up`/`make secrets` generan el par de claves en `secrets/` si falta (`make jwt-public-key` imprime la pública para `api`). Puerto publicado en `127.0.0.1`.
- **api** (repo `api`, `net/http` estándar):
  - `GET /api/items`, `POST /api/items`, `/healthz`.
  - Middleware **`RequireBearer`**: lee `Authorization: Bearer <jwt>`, lo verifica (firma, `alg` fijo, `exp`, `iss`, `aud`) y pone el usuario en el `context`. Sin token o inválido → 401.
- **postgres** (repo `api`): imagen oficial con el entrypoint mínimo propio que aplica la contraseña en cada arranque. Tabla `items`; migraciones con `goose` embebidas.
- **frontend** (repo `frontend`, Vite + React + TS): TanStack Router (rutas por archivo) + TanStack Query.
  - `src/api/client.ts`: el **único** wrapper de `fetch`; agrega `Authorization: Bearer` si hay token, hace `console.log` con el flag y centraliza errores (un 401 borra el token y manda a `/login`).
  - `features/auth/token.ts`: guarda, lee y borra el token; decodifica el payload (sin verificar) para mostrar el usuario y saber si ya expiró.
  - Layout `_authed` con `beforeLoad`: sin token o con token expirado → `redirect('/login?redirect=…')`; el usuario (claims) pasa por el contexto del router.
  - Rutas: `/login`, `/_authed/dashboard`, `/_authed/items/new`. Logout = borrar el token y la caché.

### Seguridad (checklist transversal; cada issue indica cuáles le tocan)
- JWT: algoritmo fijo en el parser (evitar `alg` confusion), `exp`/`iat`/`iss`/`aud` obligatorios, TTL corto por env. La API solo tiene la clave pública.
- Token en el navegador: `sessionStorage` (no `localStorage`), CSP estricta para limitar XSS, se borra en logout y ante un 401. El `console.log` del JWT es solo para la demo y se apaga con `VITE_LOG_JWT=false`.
- Rate limit en `/token` (por IP y usuario); errores genéricos ("credenciales inválidas") y **mismo costo de respuesta** (un usuario inexistente paga un bind ARGON2 equivalente) para no revelar si el usuario existe.
- La IP del rate limit es la de la conexión, salvo que venga de un proxy de confianza (`TRUSTED_PROXIES`, en compose = la subnet de la red compartida): entonces se usa la dirección de más a la derecha de `X-Forwarded-For` que no sea un proxy. La clave por usuario se normaliza como lo compara LDAP (minúsculas, espacios colapsados).
- Red Docker compartida (`SHARED_NETWORK`, subnet `SHARED_NETWORK_SUBNET`): auth-svc, api y la imagen `web` (nginx) se unen a ella; nginx llega a los servicios por nombre. La crea el primer `make up` de cualquier repo.
- TLS fuera de alcance: todo corre en localhost.
- Escape de filtros LDAP; contraseña vacía rechazada; LDAPS/StartTLS configurable.
- Imagen LDAP: ACLs de mínimo privilegio (anónimo solo autentica y lee el Root DSE; la cuenta de servicio solo lee `ou=users`/`ou=groups`; cada usuario solo se ve a sí mismo; `userPassword` nunca es legible), `cn=config` inaccesible en runtime, non-root, `read_only`, `cap_drop: ALL`.
- Consultas parametrizadas con pgx; validación de entrada (longitudes) y `http.MaxBytesReader`.
- Headers: CSP, `X-Content-Type-Options`, `Referrer-Policy`, `frame-ancestors 'none'`.
- Contenedores distroless/non-root, secretos por Docker secrets/`.env` (en `.gitignore`), `.env.example` documentado.
- **Rotación de contraseñas:** ldap y postgres aplican las contraseñas de los secretos **en cada arranque**. Rotar = cambiar `.env` + `make up`, sin borrar datos.
- Logs estructurados (`log/slog`) en los servicios Go que **nunca** incluyen contraseñas, tokens ni el header `Authorization`. El único volcado del JWT es el `console.log` del navegador con el flag.
- CI: `govulncheck`, `gosec`, `npm audit`, `gitleaks`.

### "Nada hardcodeado"
Un paquete `config` por servicio Go que lee env vars, valida y **falla al arrancar** si falta algo (sin defaults silenciosos para secretos). En React, solo `import.meta.env` para lo que realmente sea público (`VITE_LOG_JWT`); los destinos del proxy se leen en `vite.config.ts`/nginx desde env.

## Estructura de los repos
```
auth/       ldap/ (imagen OpenLDAP), auth-svc/ (Go: cmd/, internal/{config,ldap,token,httpapi}),
            test/ (smoke tests shell), docker-compose*.yml, Makefile, .github/workflows
api/        cmd/, internal/{config,db,migrations,auth(verifier+RequireBearer),items,httpx},
            postgres/ (imagen), docker-compose*.yml, Makefile, .github/workflows
frontend/   src/{routes,api,features/{auth,items},components}, deploy/nginx.conf,
            Dockerfile, docker-compose.yml, Makefile, .github/workflows
```

## Etapas → issues (un issue por feature)
Cada issue incluye: descripción, criterios de aceptación, **tests requeridos** y checklist de seguridad aplicable. Las issues de `api` y `frontend` nacieron en `auth` y ya viven en su repo (`JesusMaVe/api#1–6`, `JesusMaVe/frontend#1–8`).

**Etapa 0 – Fundaciones** *(auth: hecha)*
- auth: repo, Makefile, imagen OpenLDAP, CI, protección de `main`, plantillas, rotación.
- api: inicializar el repo (Makefile, CI, `CLAUDE.md`, plantillas, protección) y **mover la imagen `postgres/`** con sus tests desde `auth`.
- auth: quitar `postgres/` una vez que vive en `api`.
- frontend: la inicialización del repo va dentro del scaffold (Etapa 4).

**Etapa 1 – API de LDAP (auth-svc)** *(repo auth)*
- `config` fail-fast · cliente LDAP search-then-bind · emisor JWT EdDSA · `POST /token` + rate limit + Dockerfile + par de claves en `make env`.

**Etapa 2 – API base** *(repo api)*
- `config`, pool pgx, migraciones goose, `/healthz` · middleware común (headers, MaxBytes, logging sin `Authorization`, recover).

**Etapa 3 – Autenticación Bearer** *(repo api)*
- Verificador de JWT con la clave pública · middleware `RequireBearer`.

**Etapa 4 – Frontend base y login** *(repo frontend)*
- Scaffold (Vite + TS + Router + Query + Vitest/RTL/MSW + proxy `/auth` y `/api` + Makefile/CI) · `api.ts` con inyección del Bearer y `console.log` + token store + layout `_authed` · página de login contra `/auth/token` · logout.

**Etapa 5 – Items (dashboard)**
- api: migración `items`, repositorio, `GET/POST /api/items` con `RequireBearer`.
- frontend: dashboard con listado · página `/items/new` → mutación → invalidar `items` → `/dashboard`.

**Etapa 6 – Despliegue, E2E y entrega**
- frontend: imagen `web` (nginx: estáticos + proxy `/auth` y `/api`).
- frontend: E2E con Playwright contra los 3 composes: login → dashboard → agregar → ver en la lista → logout; verifica el header `Authorization` en cada request a `/api`.
- auth: revisión de seguridad final de los 3 repos.
- auth: guion de la demo (video) y README con los enlaces a los 3 repos y cómo levantarlos juntos.

## Flujo de trabajo con git/GitHub
- Rama por issue en su repo: `feat/<n>-<slug>`; commits convencionales; PR con `Closes #n`; CI verde obligatorio; merge squash a `main`.
- Por cada issue: test en rojo → implementación → verde → refactor → review → PR.
- Plan de implementación detallado **por etapa** (writing-plans) justo antes de empezar cada una.

## Verificación
- Por feature: `make test` en cada repo (Go `go test ./... -race` con testcontainers; front `vitest run`) en local y en CI.
- Por etapa: levantar los composes y probar el flujo (p. ej. `curl` a `/token` en la Etapa 1, `curl -H "Authorization: Bearer …"` a `/api/items` en la 5).
- Final: Playwright E2E verde + `/security-review` sin hallazgos críticos; en DevTools, cada request a `/api` lleva `Authorization: Bearer` y la consola muestra el JWT con el flag activo.
