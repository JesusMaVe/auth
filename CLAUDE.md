# Convenciones del proyecto

- **Spec:** `docs/superpowers/specs/2026-09-24-auth-dashboard-design.md`. Los planes por etapa están en `docs/superpowers/plans/`.
- **TDD:** cada feature empieza con un test que falla. No se da por terminado nada sin tests en verde.
- **Nada hardcodeado:** la configuración sale de variables de entorno (`.env`, generado con `make env`); los secretos van como Docker secrets (`*_FILE`). Las versiones de imágenes y herramientas se fijan en el código (Dockerfile, compose, Makefile).
- **KISS / DRY / YAGNI:** el Makefile es el único punto de entrada; el CI solo invoca targets de `make`.
- **Seguridad:** non-root, puertos de desarrollo solo en 127.0.0.1, nunca loguear secretos ni tokens.
- **Git:** un issue = una rama `feat/<n>-<slug>` = un PR con `Closes #n`, merge por squash a `main`. Conventional Commits.
- **Tests de shell:** usan `test/lib.sh`; sin `set -e`/`pipefail` en los tests.
