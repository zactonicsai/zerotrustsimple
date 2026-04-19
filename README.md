# Zero Trust Docker Compose Demo

Local Zero Trust stack: Keycloak (IdP) + Go API (resource server) + Python
client (service account), all over TLS.

## ⚠️ Order matters

**Generate the certs BEFORE running `docker compose up`.** If the cert files
don't exist on the host at startup, Docker will auto-create directories with
those names (a well-known bind-mount footgun), and nothing will work.

## Setup

```bash
# 1. Generate local certificates (one-time)
cd certs
chmod +x generate-certs.sh
./generate-certs.sh
cd ..

# 2. Build and start
docker compose up --build
```

The cert script has preflight checks that detect and remove stray
directories left over from previous bad runs, so it's safe to re-run.

## Directory mounts

Unlike the original version, this compose file mounts the whole `./certs`
directory into each container at `/certs` (or `/etc/x509` for Keycloak),
rather than individual files. That means:

- A missing cert fails loudly (`open /certs/ca.crt: no such file`) instead
  of silently becoming a directory.
- Regenerating certs doesn't require fiddling with bind-mount state.

The Go API and Python client both perform preflight checks on `CA_CERT` to
confirm it's a regular file before trying to use it.

## Expected output

The first `docker compose up` takes 45-90 seconds while Keycloak imports the
realm and its healthcheck turns green. The API will sit in a retry loop
printing `waiting for keycloak OIDC discovery` until Keycloak is ready, and
then:

```
Got token: eyJhbGciOiJSUzI1NiIs...
API said: {'message': 'Zero Trust says hello', ...}
Unauthenticated call status: 401
Forged-token call status: 401
```

## Keycloak admin

- URL: https://localhost:8443
- User: `admin`
- Pass: `admin`

Browser will warn about the self-signed CA. Either trust `certs/ca.crt` at
the OS level or click through.

## Cleanup

```bash
docker compose down -v
```

## Recovering from the "is a directory" error

If you ran `docker compose up` before generating certs:

```bash
docker compose down -v
# Remove stray directories Docker created in place of cert files
rm -rf certs/ca.crt certs/ca.key certs/keycloak.crt certs/keycloak.key \
       certs/api.crt certs/api.key
cd certs && ./generate-certs.sh && cd ..
docker compose up --build
```

The generate script now also auto-cleans these on its own if it detects them.
# zerotrustsimple
