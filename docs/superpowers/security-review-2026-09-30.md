# Revisión de seguridad final — 2026-09-30

Alcance: los tres repos en `main` — [`auth`](https://github.com/JesusMaVe/auth) (OpenLDAP + auth-svc), [`api`](https://github.com/JesusMaVe/api) (items + Postgres) y [`frontend`](https://github.com/JesusMaVe/frontend) (SPA + imagen nginx + E2E). Issue: auth#24.

## Herramientas

| Repo | Resultado |
|---|---|
| auth | `make lint` (shellcheck, hadolint, gofmt, go vet, gosec, govulncheck: *No vulnerabilities found*) y `make secrets-scan` (gitleaks: *no leaks found*) limpios |
| api | Igual que auth: lint, gosec, govulncheck y gitleaks limpios |
| frontend | `make lint` (oxlint, tsc, shellcheck, hadolint), `make audit` (*found 0 vulnerabilities*) y gitleaks limpios |

Además, una revisión manual de los tres repos completos (un revisor aparte) contra el checklist de la spec.

## Checklist de la spec (sección Seguridad)

| Punto | Estado | Evidencia |
|---|---|---|
| JWT: algoritmo fijo | Cumplido | `api/internal/auth/verifier.go` (`WithValidMethods(EdDSA)`); tests `alg none` y "HS256 con la pública" |
| JWT: `exp`/`iat`/`iss`/`aud` obligatorios, TTL por env | Cumplido | `verifier.go` (+ `iat` obligatorio desde api#15, test "sin iat"); `JWT_TTL` en `auth/.env.example` |
| La API solo tiene la clave pública | Cumplido | `api/scripts/import-jwt-key.sh`, `api/docker-compose.yml` |
| Token en `sessionStorage`, CSP, se borra en logout y ante 401; `console.log` solo con flag | Cumplido | `frontend/src/features/auth/token.ts`, `deploy/security-headers.conf`, `logout.test.tsx`, `client.test.ts`; la imagen se construye con `WEB_LOG_JWT=false` |
| Rate limit en `/token` por IP y usuario, errores genéricos, mismo costo para usuario inexistente | Cumplido | `auth-svc/internal/httpapi/httpapi.go`, `internal/ldap/ldap.go`; tests `TestTokenRateLimited`, "usuario inexistente tarda lo mismo…" |
| IP real detrás del proxy (`TRUSTED_PROXIES`), clave por usuario normalizada | Cumplido | `httpapi.go` (`clientIP`), `auth/docker-compose.yml` (`WEB_PROXY_IP/32`); `TestClientIPBehindTrustedProxy`, `frontend/test/web.sh` |
| Escape de filtros LDAP, contraseña vacía rechazada, LDAPS/StartTLS configurable | Cumplido | `ldap.go`; test de inyección `*)(uid=*` |
| ACLs LDAP de mínimo privilegio, `cn=config` inaccesible, non-root, `read_only`, `cap_drop` | Cumplido | `ldap/templates/config.ldif`; `auth/test/infra.sh`, `test/ldap-image.sh` |
| pgx parametrizado, validación de longitudes, `MaxBytesReader` | Cumplido | `api/internal/items/repository.go`, `items.go`, `httpx/middleware.go` |
| La API usa un rol de Postgres sin superusuario | Cumplido (nuevo, api#15) | `api/postgres/entrypoint.sh` (`apply_app_role`); `postgres-image.sh` (no puede `COPY … TO PROGRAM`), `infra.sh` |
| Headers (CSP, nosniff, Referrer-Policy, `frame-ancestors 'none'`) | Cumplido | `api/internal/httpx/middleware.go`, `frontend/deploy/security-headers.conf` (en cada `location`); `web.sh` |
| Contenedores distroless/non-root, secretos por Docker secrets, `.env` ignorado | Cumplido, con una excepción | auth-svc y api: distroless uid 65532; web: uid 101; ldap: uid 100. **postgres** no tiene `cap_drop`/`read_only` (ver Minor 3) |
| Rotación de contraseñas | Cumplido | `test/rotation.sh` en auth y api (incluye el rol de aplicación) |
| Logs sin contraseñas, tokens ni `Authorization` | Cumplido | `httpx/middleware.go`, `TestLogsNeverContainSecrets`, greps en `infra.sh` y `web.sh` |
| CI: govulncheck, gosec, npm audit, gitleaks; actions fijadas por SHA | Cumplido | Makefiles y `.github/workflows/ci.yml` de los tres repos |
| TLS | Fuera de alcance | Todo corre en localhost (decisión de la spec) |

## Hallazgos de la revisión y decisiones

**Críticos:** ninguno.

**Importantes:**

1. **La API se conectaba a Postgres como superusuario.** Corregido en api#15: rol `POSTGRES_APP_USER` sin superusuario, creado y rotado por el entrypoint, dueño de las tablas; tests de imagen e infra. El E2E del frontend corre contra esta versión (frontend#17).
2. **Bloqueo del login de un usuario conocido.** El límite por usuario se consume en cada intento, así que alguien puede mantener a un usuario en 429. **Se acepta:** es inherente al límite por usuario que pide la spec (protege contra fuerza bruta distribuida sobre una cuenta). Mitigación si se despliega en serio: clave `(usuario, IP)` más un límite global por usuario más holgado.

**Corregido además:** `iat` no era obligatorio en el verificador (incumplía la spec) — api#15.

**Menores (diferidos, sin cambio):**

1. `safeRedirect` acepta caracteres de control (`/\t/evil.com`); hoy no es explotable porque `pushState` rechaza otro origen. Mejor: comparar el origen con `new URL`.
2. postgres sin `cap_drop`/`read_only` y el wrapper del entrypoint corre como root.
3. El bind de "costo igual" para usuarios inexistentes se hace contra la cuenta de servicio con la contraseña del atacante; mejor una entrada dedicada `cn=timing`.
4. Se loguea el usuario tecleado en logins fallidos (podría ser una contraseña pegada por error).
5. La IP fija de nginx (`WEB_PROXY_IP`) no está reservada en la red (`--ip-range`): si nginx no está arriba, otro contenedor podría recibirla.
6. `X-Forwarded-For` en varias líneas: se lee solo la primera (con nginx no pasa).
7. `make up` siempre incluye el overlay de desarrollo (puertos en 127.0.0.1 y usuarios semilla).
8. Imágenes fijadas por tag, no por digest; `npm audit` no revisa devDependencies.
9. Logout solo en el cliente: el JWT vale hasta `JWT_TTL` (30 min).
10. Doble CSP en `/api` y `/auth` (la de la API y la de nginx); gana la más estricta.

**Menores diferidos de etapas anteriores:** `LDAP_TIMEOUT` por operación y no por request; `LDAP_STARTTLS=true` con `ldaps://` no se rechaza al arrancar; `uid` multivaluado; en la API no hay leeway de reloj ni log del motivo de un 401 y se acepta basura después del JSON; en el frontend un 401 no limpia la caché de consultas, un 5xx reintenta ~7 s, se pierde el formulario si el token vence, etiqueta vacía si el usuario no tiene nombre, límites validados en runtime y no en build.

**Verificado limpio:** sin XSS (`dangerouslySetInnerHTML`, `innerHTML` o `eval`), sin CORS (mismo origen), errores de base sin la URL de conexión, secretos del entrypoint de LDAP por stdin y borrados antes del `exec`, `.env` con permisos 600 y `secrets/` con 700, todos los puertos publicados en 127.0.0.1.
