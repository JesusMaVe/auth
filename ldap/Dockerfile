# syntax=docker/dockerfile:1
ARG ALPINE_VERSION=3.24
FROM alpine:${ALPINE_VERSION}

RUN apk add --no-cache \
      openldap \
      openldap-back-mdb \
      openldap-clients \
      openldap-passwd-argon2 \
      gettext-envsubst \
 && install -d -o ldap -g ldap -m 0700 /var/lib/openldap

COPY --chmod=0755 entrypoint.sh /usr/local/bin/entrypoint.sh
COPY templates/ /etc/openldap/templates/

# uid/gid del usuario `ldap` que crea el paquete openldap de Alpine (numérico: no depende de /etc/passwd)
USER 100:101
VOLUME /var/lib/openldap

HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --start-interval=1s \
  CMD ["sh", "-c", "ldapsearch -x -H \"ldap://127.0.0.1:${LDAP_PORT}\" -b '' -s base namingContexts >/dev/null"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
