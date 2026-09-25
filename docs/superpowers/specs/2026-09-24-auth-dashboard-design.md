# Plan: Dashboard con login LDAP + sesiones (Go + React + Docker)

## Contexto
Proyecto nuevo (directorio `auth` vacío). Objetivo: una app web con login contra LDAP, sesión por cookie HttpOnly y un dashboard con un listado de elementos. Se agregan elementos desde **una página aparte**; al volver, el listado se actualiza. Clientes que no son navegador (Android) usan JWT. Todo corre en Docker.

Reglas del proyecto: desarrollo por etapas, **tests en cada feature (TDD)**, **nada hardcodeado** (todo por variables de entorno o secrets), seguridad como requisito, KISS/DRY/YAGNI.

### Decisiones ya tomadas
| Tema | Decisión |
|---|---|
| Servicio LDAP+JWT | Se crea: contenedor `ldap` con **imagen OpenLDAP propia** (construida por nosotros, sin imágenes de terceros) + contenedor `auth-svc` (Go) que hace el bind LDAP y firma el JWT |
| JWT en el navegador | Solo con `EXPOSE_JWT_TO_CLIENT=true` (en `false` en prod): `/login` también lo devuelve en el body; React decodifica el payload **sin verificarlo**, hace `console.log` y lo descarta. La cookie sigue siendo la única forma de autenticarse en la web |
| Elemento del listado | Genérico: `id, title, description, created_by, created_at` |
| Agregar elemento | Ruta propia `/items/new`; al guardar se invalida la query del listado y se vuelve a `/dashboard` |
| Repo | Monorepo **público** `auth` en GitHub |

## Arquitectura

```
Browser ──cookie──▶ web (nginx: estáticos + /api proxy) ──▶ api (Go) ──▶ postgres (sesiones scs + items)
Android ──Bearer JWT──────────────────────────────────────▶ api (Go)
                                                             │ POST /token
                                                             ▼
                                                  auth-svc (Go) ──bind──▶ ldap (OpenLDAP)
```

- **ldap** (imagen propia en `/ldap`): Alpine + paquetes oficiales de OpenLDAP 2.6 (`slapd`, backend `mdb`). Un `entrypoint.sh` genera la configuración `cn=config` desde variables de entorno **en el primer arranque** (idempotente en reinicios), hashea las contraseñas con `slappasswd` (ARGON2) y carga el árbol base (`ou=users`, `ou=groups`, `ou=services` + cuenta de servicio de auth-svc). Las contraseñas llegan por `*_FILE` (Docker secrets). Los usuarios semilla de desarrollo se montan solo en `docker-compose.dev.yml`. Corre como non-root, con filesystem de solo lectura y healthcheck.
- **auth-svc**: `POST /token {username,password}` → bind LDAP (`go-ldap/ldap/v3`, con escape de filtros) → JWT firmado con **EdDSA/RS256**. La clave privada solo la tiene auth-svc; la API recibe la **clave pública** (Docker secret). Red interna, sin publicar puerto.
- **api** (net/http estándar + `CrossOriginProtection`):
  - `POST /api/auth/login` → llama a auth-svc, verifica el JWT con la clave pública, `scs.RenewToken`, guarda el usuario en la sesión, pone la cookie. Devuelve el JWT en el body solo si el flag está activo.
  - `POST /api/auth/logout`, `GET /api/me`
  - `POST /api/auth/token` → para Android, devuelve el JWT (sin cookie).
  - `GET /api/items`, `POST /api/items`
  - **Un solo middleware `RequireUser`** (DRY): acepta sesión por cookie **o** `Authorization: Bearer`, y pone el usuario en el `context`.
- **postgres**: imagen oficial con un entrypoint mínimo propio (`/postgres`) que aplica la contraseña en cada arranque. Sesiones con `scs/pgxstore` + tabla `items`. Migraciones versionadas con `goose` (embebidas).
- **frontend** (Vite + React + TS): TanStack Router (rutas por archivo) + TanStack Query.
  - `meQueryOptions` es la única pieza de sesión en el cliente.
  - Layout `_authed` con `beforeLoad` que hace `queryClient.ensureQueryData(meQuery)` → si da 401, redirige a `/login?redirect=…`; el usuario se pasa por el contexto del router a las rutas hijas.
  - Rutas: `/login`, `/_authed/dashboard`, `/_authed/items/new`.
  - Un solo cliente `api.ts` (`fetch` con `credentials: 'same-origin'`, manejo de errores centralizado).
  - Dev: proxy de Vite `/api` → api. Prod: nginx sirve la app y la API en el mismo dominio.

### Seguridad (checklist transversal; cada issue indica cuáles le tocan)
- Cookie `HttpOnly`, `Secure` (configurable por entorno), `SameSite=Lax`, idle y lifetime por env; `RenewToken` al hacer login y logout.
- `http.CrossOriginProtection` en rutas que cambian estado; orígenes de confianza por env.
- Rate limit en `/login` y `/token` (por IP y usuario); errores genéricos ("credenciales inválidas") para no revelar si el usuario existe.
- Escape de filtros LDAP; LDAPS/StartTLS configurable.
- Imagen LDAP: ACLs de mínimo privilegio (anónimo solo puede autenticar y leer el Root DSE; la cuenta de servicio solo lee `ou=users`/`ou=groups`; cada usuario solo se ve a sí mismo; `userPassword` nunca es legible), `cn=config` inaccesible en runtime, non-root, `read_only`, `cap_drop: ALL`.
- JWT: algoritmo fijo en el parser (evitar `alg` confusion), `exp`/`iat`/`iss`/`aud` obligatorios, TTL corto por env.
- Consultas parametrizadas con pgx; validación de entrada (longitudes) y `http.MaxBytesReader`.
- Headers: CSP, `X-Content-Type-Options`, `Referrer-Policy`, `frame-ancestors 'none'`.
- Contenedores distroless/non-root, secretos por Docker secrets/`.env` (en `.gitignore`), `.env.example` documentado.
- **Rotación de contraseñas:** ldap y postgres aplican las contraseñas de los secretos **en cada arranque** (ldap sin conexión con `slapmodify` antes de iniciar slapd; postgres con `ALTER USER` y un healthcheck que espera a que esté aplicada). Rotar = cambiar `.env` + `make up`, sin borrar datos.
- Logs estructurados (`log/slog`) que **nunca** incluyen contraseñas ni tokens (el único volcado del JWT es el `console.log` del navegador con el flag).
- CI: `govulncheck`, `gosec`, `npm audit`, `gitleaks`.

### "Nada hardcodeado"
Un paquete `config` por servicio que lee env vars, valida y **falla al arrancar** si falta algo (sin defaults silenciosos para secretos). En React, solo `import.meta.env` para lo que realmente sea público.

## Estructura del repo
```
/auth-svc      Go: cmd/, internal/{config,ldap,token,httpapi}
/api           Go: cmd/, internal/{config,db,migrations,session,auth,items,httpx(middleware)}
/frontend      Vite React: src/{routes,api,features/{auth,items},components}
/ldap          Imagen OpenLDAP propia: Dockerfile, entrypoint.sh, templates/*.ldif, seed/ (solo dev)
/deploy        nginx.conf
/test          Smoke tests de infraestructura (shell)
docker-compose.yml, docker-compose.dev.yml, .env.example, Makefile, .github/workflows
```

## Etapas → Milestones de GitHub (un issue por feature)
Cada issue incluye: descripción, criterios de aceptación, **tests requeridos** y checklist de seguridad aplicable.

**Etapa 0 – Fundaciones**
1. Inicializar repo, `.gitignore`, `.env.example`, `README`, `CLAUDE.md`, Makefile
2. Imagen OpenLDAP propia + `docker-compose` base (postgres, ldap con seed de dev) + healthchecks *(test: smoke tests de bind, ACLs, fail-fast y reinicio)*
3. CI en GitHub Actions: lint (shellcheck, hadolint), smoke tests de infra y `gitleaks`, con un job agregador `ci` como único check requerido. Los jobs de Go y frontend se agregan en la etapa que crea cada servicio (YAGNI)
4. Protección de rama `main`, plantillas de issue/PR, labels

**Etapa 1 – Servicio de identidad (auth-svc)**
5. `config` con validación fail-fast *(test: faltan vars → error)*
6. Cliente LDAP: bind + búsqueda de atributos *(test: testcontainers con nuestra imagen OpenLDAP; credenciales válidas/erróneas; inyección en filtros)*
7. Emisor de JWT *(test: claims, exp, firma verificable con la pública)*
8. `POST /token` + rate limit + Dockerfile *(test: handler con httptest)*

**Etapa 2 – API base**
9. `config`, pool pgx, migraciones goose, `/healthz`
10. Middleware común: security headers, CrossOriginProtection, MaxBytes, logging, recover *(tests por middleware)*

**Etapa 3 – Sesión y autenticación en la API**
11. scs con pgxstore y cookie configurada *(test: atributos de la cookie)*
12. Cliente de auth-svc + verificación de JWT (compartida con Bearer) *(tests: alg inválido, expirado, aud/iss erróneos)*
13. `POST /login`, `POST /logout`, `GET /me` (+ flag `EXPOSE_JWT_TO_CLIENT`) *(tests: flag on/off, RenewToken)*
14. Middleware `RequireUser` (cookie o Bearer) + `POST /api/auth/token` para Android *(tests: cada camino, 401)*

**Etapa 4 – Frontend base y login**
15. Scaffold Vite + TS + Router + Query + Vitest/RTL/MSW + proxy dev
16. `api.ts` + `meQueryOptions` + layout `_authed` con redirect *(tests: redirige sin sesión, pasa con sesión)*
17. Página de login + `console.log` del payload del JWT cuando viene en la respuesta *(tests: con/sin token, error de credenciales)*
18. Logout

**Etapa 5 – Items (dashboard)**
19. API: migración `items`, repositorio, `GET/POST /api/items` con validación *(tests de integración con Postgres en testcontainers)*
20. Front: dashboard con listado (estados vacío/cargando/error)
21. Front: página `/items/new` → mutación → invalidar `items` → navegar a `/dashboard` *(test: la lista se actualiza)*

**Etapa 6 – Despliegue y E2E**
22. Imagen `web` (nginx, mismo dominio) + compose de prod
23. E2E con Playwright contra el compose completo: login → dashboard → agregar → ver en la lista → logout
24. Revisión de seguridad final (`/security-review`) y hardening

## Flujo de trabajo con git/GitHub
- Tú ejecutas una vez `! gh auth login` (ahora no hay sesión). Luego yo: `gh repo create auth --public`, labels (`stage:0..6`, `backend`, `auth-svc`, `frontend`, `infra`, `security`, `test`), milestones por etapa e issues con `gh issue create`.
- Rama por issue: `feat/<n>-<slug>`; commits convencionales; PR con `Closes #n`; CI verde obligatorio; merge squash a `main`.
- Por cada issue: test en rojo → implementación → verde → refactor → review → PR.

## Siguiente paso después de aprobar este plan
1. Escribir la spec en `docs/superpowers/specs/2026-09-24-auth-dashboard-design.md` (el contenido de este plan, pulido) y hacer commit en la Etapa 0.
2. Crear repo, labels, milestones e issues con `gh`.
3. Plan de implementación detallado **por etapa** (writing-plans) justo antes de empezar cada una, no todos por adelantado (YAGNI).

## Verificación
- Por feature: `make test` (Go `go test ./... -race` con testcontainers; front `vitest run`) en local y en CI.
- Por etapa: `docker compose up` y prueba manual del flujo de esa etapa (p. ej. `curl` a `/token` en la Etapa 1).
- Final: Playwright E2E verde + `/security-review` sin hallazgos críticos; revisar en DevTools que la cookie es HttpOnly y que el JWT solo aparece en consola con el flag activo.
