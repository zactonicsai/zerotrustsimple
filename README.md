# Zero Trust Docker Compose Demo (with mTLS)

Local Zero Trust stack demonstrating **two-layer authentication** on every request:

1. **mTLS** — client presents a cert signed by our CA (TLS layer)
2. **OIDC/JWT** — client presents a bearer token signed by Keycloak (HTTP layer)

Plus a **cross-check**: the cert's CN and the token's `azp` claim must match.
Compromise either credential alone and you still can't call the API.

## Architecture

```
Python Client  ── TLS + client_id/secret ──▶  Keycloak    (gets JWT)
Python Client  ── mTLS + Bearer JWT ───────▶  Go API      (gets data)
Go API         ── TLS fetch ──────────────▶  Keycloak    (JWKS for verification)
```

Every hop is TLS. The Python↔API hop is additionally mTLS.

## Prerequisites

- Docker + Docker Compose
- OpenSSL

## Setup

**Order matters.** Generate certs BEFORE starting the stack.

```bash
# 1. Generate CA, server certs (keycloak, api), and CLIENT cert (python-client)
cd certs
chmod +x generate-certs.sh
./generate-certs.sh
cd ..

# 2. Build and start
docker compose up --build
```

The cert script now generates **7 files**:

| File | Role |
|------|------|
| `ca.crt` / `ca.key` | Root CA (trust anchor, distributed everywhere) |
| `keycloak.crt` / `keycloak.key` | Server cert for Keycloak |
| `api.crt` / `api.key` | Server cert for Go API |
| `client.crt` / `client.key` | **Client cert for Python (mTLS)** |

## What to Expect

```
Got token: eyJhbGciOiJSUzI1NiIs...
API said: {
  'message': 'Zero Trust says hello (mTLS + JWT verified)',
  'token_azp': 'python-client',
  'tls_client_cn': 'python-client',
  ...
}

[negative] calling with token but NO client cert...
  ✓ TLS handshake rejected (expected): SSLError

[negative] calling with cert but NO bearer token...
  status: 401 (expect 401)
  body: missing bearer token

[negative] calling with cert and FORGED token...
  status: 401 (expect 401)
```

The three negatives each prove a different security property:

- **No cert → TLS handshake fails.** The API never sees the HTTP request. Rejection happens at the OpenSSL layer.
- **No token → 401 at middleware.** TLS handshake succeeds (cert is valid), but the middleware rejects.
- **Forged token → 401 at verifier.** Same, but the rejection is at the signature-verification step.

## Defense in Depth

The two layers are **independent** and catch different threats:

| Attack | Stopped by |
|--------|------------|
| Attacker on the network, no credentials | TLS + mTLS |
| Attacker steals client's private key (cert) | JWT (no valid token) |
| Attacker steals client's JWT | mTLS (no client cert) |
| Attacker steals BOTH | Cross-check (only if they can match an identity cert to its azp) |

The cross-check (cert CN == token azp) is what makes it defense-in-depth rather than just redundancy. An attacker who compromises service A's cert and service B's token can't combine them — the API will see the mismatch and reject.

## The mTLS Changes, File by File

**`certs/generate-certs.sh`** — now issues a `client.crt` / `client.key` pair with `extendedKeyUsage=clientAuth` and CN=`python-client`.

**`api/main.go`** — replaces `ListenAndServeTLS` with a manual `http.Server` whose `TLSConfig` has:
```go
ClientCAs:  caPool,                            // who we accept client certs from
ClientAuth: tls.RequireAndVerifyClientCert,    // strict: no cert = no connection
```
And the middleware now reads `r.TLS.PeerCertificates[0].Subject.CommonName` and cross-checks it against the JWT's `azp` claim.

**`client/client.py`** — adds `cert=(CLIENT_CERT, CLIENT_KEY)` to every `requests` call against the API. Leaves the Keycloak call unchanged (Keycloak still authenticates by client secret).

**`docker-compose.yml`** — adds `CLIENT_CERT` and `CLIENT_KEY` env vars to the `client` service.

## Production Caveats

This stack is for learning. Before using in production:

- **Use a separate CA for client certs** than the one that signs server certs. Limits blast radius if the CA is compromised.
- **Automate cert lifecycle.** Our certs live 365 days; production rotation is typically much shorter. Look at `cert-manager`, SPIFFE/SPIRE, or HashiCorp Vault.
- **Use a service mesh** (Istio, Linkerd, Consul) rather than handling mTLS application-side. Sidecars take care of issuance, rotation, and revocation.
- **Add CRL or OCSP** so revoked certs can't be reused until expiry.
- **Don't reuse the CA for data-plane and control-plane.** Separate trust domains.
- **Use shorter JWT lifetimes** (60s–5min) with refresh tokens.

## Keycloak Admin

- URL: https://localhost:8443
- User: `admin`
- Pass: `admin`

## Cleanup

```bash
docker compose down -v
```

## Troubleshooting

**`tls: client didn't provide a certificate`** in API logs
→ The client forgot `cert=` — check `CLIENT_CERT` / `CLIENT_KEY` env vars are set.

**`tls: unknown certificate authority`**
→ The API's CA pool doesn't trust the cert that was presented. Verify `ca.crt` is mounted in both containers.

**`cert/token identity mismatch`** in API logs
→ The cert's CN doesn't match the token's `azp`. In our setup both must be `python-client`. Regenerate certs if you changed the CN.

**`is a directory` errors**
→ You ran `docker compose up` before generating certs. Run:
```bash
docker compose down -v
rm -rf certs/*.crt certs/*.key
cd certs && ./generate-certs.sh && cd ..
docker compose up --build
```
