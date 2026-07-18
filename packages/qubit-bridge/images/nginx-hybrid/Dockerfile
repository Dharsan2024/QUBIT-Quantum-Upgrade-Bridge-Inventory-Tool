FROM nginx:alpine

# Alpine 3.22+ guarantees OpenSSL 3.5.x support for X25519MLKEM768
RUN apk add --no-cache openssl && \
    openssl version | grep -Eq 'OpenSSL 3\.(5|6|7|8|9)' || (echo "Requires OpenSSL >= 3.5" && exit 1)

COPY entrypoint.sh /docker-entrypoint.d/99-generate-certs.sh
RUN chmod +x /docker-entrypoint.d/99-generate-certs.sh

COPY conf.d/default.conf /etc/nginx/conf.d/default.conf

EXPOSE 8443
