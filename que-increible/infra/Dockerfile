# Imagen del proxy de la tienda (demo).
# Alpine 3.22 incluye OpenSSL 3.5 con soporte nativo de ML-KEM (FIPS 203).
FROM nginx:1.27-alpine3.22
RUN apk add --no-cache openssl \
 && openssl version | grep -Eq 'OpenSSL 3\.(5|[6-9])' \
 && mkdir -p /etc/nginx/certs /run/secrets
# NO se genera ni se hornea material privado en la imagen.
# Las claves ML-KEM-768 y el certificado de servidor se generan fuera (ver keyRegenSteps)
# y se inyectan en tiempo de ejecución (docker secret / volumen de solo lectura).
# El certificado de servidor (firma) se trata como hallazgo aparte; aquí se elimina
# la clave RSA y se habilita el intercambio híbrido X25519 + ML-KEM-768 en TLS 1.3.
COPY nginx/tienda.conf /etc/nginx/conf.d/tienda.conf
COPY certs/mlkem768_pub.pem /etc/nginx/certs/mlkem768_pub.pem
# nginx/tienda.conf debe contener:
#   ssl_protocols TLSv1.3;
#   ssl_ecdh_curve X25519MLKEM768:X25519;
#   ssl_certificate     /run/secrets/portal.crt;
#   ssl_certificate_key /run/secrets/portal.key;
VOLUME ["/run/secrets"]
HEALTHCHECK --interval=30s CMD wget --no-check-certificate -q -O- https://localhost/ || exit 1
