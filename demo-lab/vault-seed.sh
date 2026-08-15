#!/bin/sh
# Seeds a Vault dev-mode server with real transit keys and an issued PKI cert, so
# `qubit scan-vault` (backlog item B1) has something real to scan end-to-end.
# Run inside the `vault-seed` service in compose.vault.yml (or standalone against any Vault dev
# server with VAULT_ADDR/VAULT_TOKEN set).
set -e

echo "Waiting for Vault to be ready..."
until vault status >/dev/null 2>&1; do sleep 1; done

echo "Enabling transit secrets engine..."
vault secrets enable transit || true

echo "Creating transit keys (well-established types guaranteed present in any Vault build --"
echo "ml-dsa/slh-dsa/hybrid are Enterprise-only in OSS Vault, verified against the local source"
echo "clone; see docs/design/07-ecosystem-factcheck.md sec11)..."
vault write -f transit/keys/demo-rsa-2048 type=rsa-2048
vault write -f transit/keys/demo-ecdsa-p256 type=ecdsa-p256
vault write -f transit/keys/demo-aes-256 type=aes256-gcm96
vault write -f transit/keys/demo-ed25519 type=ed25519
vault write transit/keys/demo-hmac type=hmac key_size=32

echo "Enabling PKI secrets engine..."
vault secrets enable pki || true
vault secrets tune -max-lease-ttl=87600h pki

echo "Generating root CA..."
vault write -field=certificate pki/root/generate/internal \
    common_name="qubit-demo-root" ttl=87600h >/tmp/root_ca.crt

echo "Creating PKI role..."
vault write pki/roles/demo-role \
    allowed_domains="demo.local" allow_subdomains=true max_ttl=720h

echo "Issuing a certificate..."
vault write pki/issue/demo-role common_name="app.demo.local" >/dev/null

echo "Vault demo seed complete."
echo "Try: qubit scan-vault http://localhost:8200 --token \$VAULT_DEV_ROOT_TOKEN_ID"
