#!/bin/sh
set -e

CERT_DIR="/etc/nginx/certs"
CERT_FILE="${CERT_DIR}/server.crt"
KEY_FILE="${CERT_DIR}/server.key"

mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "Generating self-signed RSA-2048 certificate for hybrid bridge fallback..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -subj "/CN=demo.local/O=QUBIT Hybrid Bridge/C=US"
    chmod 644 "$CERT_FILE"
    chmod 600 "$KEY_FILE"
else
    echo "Using existing certificate in $CERT_DIR"
fi
