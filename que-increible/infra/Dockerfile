# Imagen del proxy de la tienda (demo).
FROM nginx:1.27-alpine
RUN apk add --no-cache openssl \
 && openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 825 \
      -keyout /etc/nginx/certs/portal.key -out /etc/nginx/certs/portal.crt \
      -subj "/CN=portal.que-increible.example"
COPY nginx/tienda.conf /etc/nginx/conf.d/tienda.conf
COPY certs/ /etc/nginx/certs/
HEALTHCHECK --interval=30s CMD wget --no-check-certificate -q -O- https://localhost/ || exit 1
