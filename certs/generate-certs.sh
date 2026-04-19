#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

# Preflight: openssl must exist
if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: openssl is not installed or not on PATH." >&2
  exit 1
fi

# Preflight: if any target paths exist as DIRECTORIES (likely created by a
# previous failed docker bind-mount), remove them so we can write files.
for f in ca.crt ca.key keycloak.crt keycloak.key api.crt api.key; do
  if [ -d "$f" ]; then
    echo "Removing stray directory at $f (left over from bad bind-mount)..."
    rmdir "$f" 2>/dev/null || rm -rf "$f"
  fi
done

echo "==> Generating local CA..."
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 \
  -out ca.crt -subj "/CN=ZeroTrustLocalCA"

echo "==> Generating Keycloak cert..."
cat > keycloak.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
subjectAltName = @alt_names
[alt_names]
DNS.1 = keycloak
DNS.2 = localhost
IP.1  = 127.0.0.1
EOF

openssl genrsa -out keycloak.key 2048
openssl req -new -key keycloak.key -out keycloak.csr \
  -subj "/CN=keycloak"
openssl x509 -req -in keycloak.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out keycloak.crt -days 365 -sha256 -extfile keycloak.ext

echo "==> Generating API cert..."
cat > api.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
subjectAltName = @alt_names
[alt_names]
DNS.1 = api
DNS.2 = localhost
EOF

openssl genrsa -out api.key 2048
openssl req -new -key api.key -out api.csr -subj "/CN=api"
openssl x509 -req -in api.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out api.crt -days 365 -sha256 -extfile api.ext

chmod 644 *.crt
chmod 640 *.key

echo "==> Cleaning up CSRs, ext files, and serials..."
rm -f ./*.csr ./*.ext ./*.srl

echo
echo "==> Verification (all must be 'regular file'):"
for f in ca.crt keycloak.crt keycloak.key api.crt api.key; do
  if [ -f "$f" ]; then
    printf "  %-20s %s\n" "$f" "$(file -b "$f" 2>/dev/null || echo OK)"
  else
    echo "  MISSING: $f" >&2
    exit 1
  fi
done

echo
echo "Done. Now run: docker compose up --build"
