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

## Estructura

| Carpeta | Contenido |
|---|---|
| `ldap/` | Imagen OpenLDAP propia |
| `test/` | Smoke tests de infraestructura |
| `scripts/` | Utilidades del repo |
| `docs/` | Spec y planes por etapa |
