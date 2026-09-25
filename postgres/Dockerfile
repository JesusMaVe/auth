# syntax=docker/dockerfile:1
FROM postgres:18.6-alpine3.24

COPY --chmod=0755 entrypoint.sh /usr/local/bin/rotating-entrypoint.sh

# Healthy solo cuando postgres acepta conexiones Y la contraseña del secreto ya está aplicada.
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --start-interval=1s \
  CMD ["sh", "-c", "test -f /tmp/.password-applied && pg_isready -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\""]

ENTRYPOINT ["rotating-entrypoint.sh"]
CMD ["postgres"]
