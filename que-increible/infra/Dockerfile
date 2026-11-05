# Imagen del proxy de la tienda (demo).
# nginx:1.27-alpine (Alpine 3.22) incluye OpenSSL 3.5 con ML-DSA nativo (FIPS 204).
# Esquema híbrido de migración: certificado ML-DSA-65 + certificado Ed25519 servidos en paralelo.
# Nota: ML-DSA y Ed25519 no usan digest externo, por eso se elimina -sha256.
FROM nginx:1.27-alpine
RUN apk add --no-cache openssl \
 && openssl version | grep -Eq 'OpenSSL 3\.([5-9]|[1-9][0-9])' \
 && mkdir -p /etc/nginx/certs \
 && openssl req -x509 -newkey mldsa65 -nodes -days 825 \
      -keyout /etc/nginx/certs/portal-mldsa65.key -out /etc/nginx/certs/portal-mldsa65.crt \
      -subj "/CN=portal.que-increible.example" \
 && openssl req -x509 -newkey ed25519 -nodes -days 825 \
      -keyout /etc/nginx/certs/portal-ed25519.key -out /etc/nginx/certs/portal-ed25519.crt \
      -subj "/CN=portal.que-increible.example" \
 && chmod 600 /etc/nginx/certs/*.key
COPY nginx/tienda.conf /etc/nginx/conf.d/tienda.conf
# Recomendado: no hornear claves en la imagen; montarlas en runtime (-v o secrets) en /etc/nginx/certs/
COPY certs/ /etc/nginx/certs/
HEALTHCHECK --interval=30s CMD wget --no-check-certificate -q -O- https://localhost/ || exit 1
