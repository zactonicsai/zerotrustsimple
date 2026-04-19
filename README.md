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
# zerotrustsimple

# Zero Trust Architecture — A Line-by-Line Tutorial

> **Never trust. Always verify.**
> A working Docker Compose stack — Keycloak, a Go API, a Python client — picked apart line by line. By the end, you will understand not just *what* the code does, but *why* every single request has to prove itself, even from inside your own network.

---

## Table of Contents

- [00 · Overview](#00--overview)
- [01 · Core Concepts](#01--core-concepts)
- [02 · Architecture](#02--architecture)
- [03 · Project Structure](#03--project-structure)
- [04 · TLS Certificates](#04--tls-certificates)
- [05 · Docker Compose](#05--docker-compose)
- [06 · Keycloak Realm](#06--keycloak-realm)
- [07 · The Go API](#07--the-go-api)
- [08 · API Dockerfile](#08--api-dockerfile)
- [09 · The Python Client](#09--the-python-client)
- [10 · Run & Observe](#10--run--observe)
- [11 · Testing the System](#11--testing-the-system)
- [12 · Glossary](#12--glossary)

---

## Prerequisites

- Docker + Docker Compose (modern version with `compose` subcommand)
- OpenSSL (for generating local certs)
- Terminal comfort
- ~4GB free RAM
- **Time budget: ~90 minutes** including runtime

---

## 00 · Overview

### The Shift in Thinking

**Old model — Castle & Moat:**
Build a hard shell (firewall), then *trust everything inside*. Once past the gate, you're family. A single breach means total compromise.

**New model — Zero Trust:**
Trust *no one*. Every request — even from the next container over — must present cryptographic proof. The network stops being a security boundary.

### The Goal

By the end of this lesson you'll have a local stack where **a Python script calls a Go API**, but the Go API refuses to answer unless the request carries a freshly-signed, audience-scoped, TLS-delivered JWT from **Keycloak**. Remove any of those pieces and you get `401 Unauthorized`.

### What You'll Build (High Level)

1. **Generate a local Certificate Authority** and TLS certs for Keycloak and the API.
2. **Boot Keycloak** with a pre-imported realm defining two clients: a resource server and a machine client.
3. **Build a Go API** that fetches Keycloak's public keys and verifies every incoming JWT.
4. **Write a Python client** that exchanges its credentials for a token, then calls the API.
5. **Prove the model works** by showing unauthenticated and forged-token calls fail.

---

## 01 · Core Concepts

Five ideas underpin everything that follows.

### OIDC (OpenID Connect)

A thin identity layer on top of OAuth 2.0. OAuth 2.0 alone answers "can this caller do X?" It was designed for delegated authorization (Google letting Spotify read your contacts). OIDC adds "who is this caller?" by standardizing an `id_token` — a JWT with identity claims.

In our stack, Keycloak is the OIDC provider. It exposes a *discovery document* at `/.well-known/openid-configuration` that tells any client where to find the token endpoint, the JWKS endpoint, the supported algorithms, and so on. The Go API reads this discovery doc at startup — no hardcoded URLs.

**Key insight:** OIDC's power is *standardization*. Any OIDC-compliant library can talk to any OIDC-compliant provider. Swap Keycloak for Auth0 or Okta tomorrow and the Go code barely changes.

### JWT (JSON Web Token)

Three base64url-encoded JSON objects glued together with dots:

```
eyJhbGciOi...  .  eyJzdWIiOi...  .  SflKxwRJ...
   HEADER           PAYLOAD          SIGNATURE
```

- **Header** declares the signing algorithm (e.g. `RS256`) and the key ID.
- **Payload** contains *claims*: `iss`, `sub`, `aud`, `exp`, plus anything custom.
- **Signature** is the header+payload signed with the issuer's private key. Anyone with the matching public key can verify it wasn't tampered with.

**Critical point:** The payload is *readable* by anyone — base64 is encoding, not encryption. Never put secrets in a JWT payload. The signature guarantees integrity, not confidentiality.

### JWKS (JSON Web Key Set)

A JSON document listing an issuer's *public keys*, fetched over HTTPS from a URL like `/realms/zerotrust/protocol/openid-connect/certs`.

Here's why it matters: the Go API never has Keycloak's public key hardcoded. At startup (and periodically after), it fetches JWKS. Each JWT's header has a `kid` (key ID) that tells the API which key in the set to use for verification.

**Operational win:** Key rotation is invisible. Keycloak generates a new signing key, publishes both old and new in JWKS, issues new tokens signed with the new key. The API fetches the updated JWKS, verifies new tokens with the new key and old tokens with the old key. Zero downtime, zero config changes.

### Client Credentials Grant

OAuth 2.0 defines several "grants" — ways to obtain a token. The most familiar is **authorization code** (the flow that happens when you click "Sign in with Google"). That requires a browser, a user, and a redirect URL.

Client credentials is the opposite: *no user involved*. The client sends its own `client_id` and `client_secret` directly to the token endpoint:

```
POST /token
grant_type=client_credentials
client_id=python-client
client_secret=<redacted>
```

Keycloak responds with a token whose `sub` is a "service account user" it auto-created for this client.

**When to use it:** Backend-to-backend calls. Cron jobs. Microservice-to-microservice. Anywhere no human is present to click "allow."

### TLS (Transport Layer Security)

TLS does two jobs: (1) encrypts data in transit, and (2) proves the server's identity via a certificate signed by a trusted CA.

In our stack, every single link is TLS — client→Keycloak, client→API, API→Keycloak. Even though all three sit on the same Docker bridge network, none of them talk over plain HTTP. This is where "don't trust the network" gets made real.

**Mutual TLS (mTLS)** is a stronger variant where *both sides* present certs. We didn't implement mTLS here — we stopped at server-only TLS + JWT bearer tokens — but mTLS is a common Zero Trust upgrade, especially for service mesh scenarios.

### Audience (aud)

The `aud` claim says "this token is intended for service X." When the Go API verifies a token, it checks whether `aud` contains `zerotrust-api`. If not, reject.

**Why this matters:** Imagine the Python client also calls a *different* service — say, an invoice API. Without audience checks, a token for the invoice API could be replayed against our API. With audience checks, each API only accepts tokens explicitly minted for it. This is the Zero Trust principle of *least privilege* applied to tokens.

**Keycloak gotcha:** By default, Keycloak's client-credentials tokens have `aud: "account"`, which fails the check. You *must* add an audience protocol mapper (we do) to make the check pass.

---

## 02 · Architecture

### Request Flow

```
        ┌─────────────────────────────────────────────────────────────┐
        │  DOCKER NETWORK: ztnet                                      │
        │                                                             │
        │            ┌────────────────────────┐                       │
        │            │   PYTHON CLIENT        │                       │
        │            │   client_id + secret   │                       │
        │            │   → exchanges for JWT  │                       │
        │            └──┬──────────────────▲──┘                       │
        │               │  (1) POST       │ (2) signed JWT            │
        │               │      /token     │                           │
        │               ▼                 │                           │
        │       ┌───────────────┐         │       ┌───────────────┐   │
        │       │  KEYCLOAK     │◄────────────────┤    GO API     │   │
        │       │  TLS :8443    │   (4) GET       │  TLS :8444    │   │
        │       │               │   /jwks.json    │               │   │
        │       │  • issues JWT │                 │  • verify sig │   │
        │       │  • hosts JWKS │                 │  • check aud  │   │
        │       │  • signs RS256│                 │  • check exp  │   │
        │       └──────┬────────┘                 └──────▲────────┘   │
        │              │                                 │            │
        │              │ state                           │ (3) GET    │
        │              ▼                                 │    /api    │
        │       ┌───────────────┐              Bearer  <token>        │
        │       │  POSTGRES:16  │                                     │
        │       └───────────────┘                                     │
        │                                                             │
        │                            ALL ARROWS = TLS                 │
        └─────────────────────────────────────────────────────────────┘
```

### Flow Steps Explained

1. **Client → Keycloak:** Python client POSTs its credentials to Keycloak's token endpoint.
2. **Keycloak → Client:** Keycloak returns a signed JWT (with `aud: zerotrust-api` thanks to our audience mapper).
3. **Client → API:** Python client calls the Go API with `Authorization: Bearer <token>`.
4. **API → Keycloak:** Go API fetches JWKS (public keys) to verify the token's signature. This happens once, then results are cached.

### Read This Slowly

Notice **arrow #4**: the API reaches *out* to Keycloak to fetch public keys. It doesn't have them hardcoded. This is why key rotation "just works" — Keycloak rolls the key, the API re-fetches JWKS, life goes on.

### Zero Trust Moment

The Python client and the API sit on the *same Docker network*. In a castle-and-moat world, that shared network would be enough. Here it isn't. Arrow #3 must carry a valid JWT or arrow #3 fails.

---

## 03 · Project Structure

Every file we'll walk through:

```
zero-trust-demo/
├── docker-compose.yml       # Orchestrates all 4 services
├── certs/
│   └── generate-certs.sh    # Creates local CA + server certs
├── keycloak/
│   └── realm-export.json    # Realm + clients, imported at boot
├── api/
│   ├── Dockerfile           # Multi-stage Go build
│   ├── go.mod               # Go module + one dependency
│   └── main.go              # ~115 lines; the entire API
└── client/
    ├── Dockerfile           # Thin Python image
    ├── requirements.txt     # Just `requests`
    └── client.py            # The caller
```

---

## 04 · TLS Certificates

**File:** `certs/generate-certs.sh`

Before we can do TLS, we need certificates. In production you'd get these from **Let's Encrypt** or your internal **Certificate Authority**. For local dev we mint our own.

### Why a Custom CA?

Because inside Docker, services reach each other by container name (`keycloak`, `api`), not by a public hostname. Let's Encrypt won't issue a cert for the name `keycloak`. So we become our own CA, issue certs with **Subject Alternative Names** matching the container names, and trust our own CA inside every container.

### The Script

```bash
#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

# ─── Generate a self-signed root CA ───────────────────
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 \
  -days 365 -out ca.crt -subj "/CN=ZeroTrustLocalCA"

# ─── Extensions file: CRITICAL for Docker name resolution ──
cat > keycloak.ext <<EOF
basicConstraints=CA:FALSE
subjectAltName = @alt_names
[alt_names]
DNS.1 = keycloak
DNS.2 = localhost
EOF

# ─── Sign a server cert for Keycloak ───────────────────
openssl genrsa -out keycloak.key 2048
openssl req -new -key keycloak.key -out keycloak.csr \
  -subj "/CN=keycloak"
openssl x509 -req -in keycloak.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out keycloak.crt -days 365 \
  -sha256 -extfile keycloak.ext

# Same process for the API cert (not shown)...
```

### Line by Line

| Line | Explanation |
|------|-------------|
| **L2** | `set -euo pipefail` — bash strict mode. Fail on any error (`-e`), unset variable (`-u`), or mid-pipe failure (`-o pipefail`). Standard defensive shell. |
| **L7** | Generates a 4096-bit **RSA private key** for the CA. 4096 bits is overkill for a dev CA (2048 would do) but we're being paranoid. |
| **L8–9** | `req -x509` creates a *self-signed* certificate. A real CA is the trust root — nothing signs it. The `-subj "/CN=ZeroTrustLocalCA"` sets its identity. |
| **L12–18** | The **extensions file**. `subjectAltName` lists the hostnames this cert will be valid for. Modern TLS ignores the CN field entirely — *only* SANs are trusted. `DNS.1 = keycloak` is what makes `https://keycloak:8443` work *inside Docker*. |
| **L21** | Keycloak's **own** private key. Separate from the CA's. The server holds this; the client never sees it. |
| **L22–23** | Creates a **Certificate Signing Request** (CSR). Think of it as: "Dear CA, please attest that this public key belongs to `keycloak`." |
| **L24–26** | The CA signs the CSR, producing `keycloak.crt`. Now Keycloak has a cert that any container which trusts `ca.crt` will accept. |

### About Subject Alternative Names

Modern TLS clients **ignore** the Common Name (CN) field of a certificate. Hostname validation happens against the `subjectAltName` extension. Our cert works *both* inside Docker (where containers reach each other as `keycloak`) and from the host (where you hit `localhost`) because both names are listed.

Common error: omit the SAN, connect via hostname, get `x509: certificate is not valid for any names, but wanted to match keycloak`.

---

## 05 · Docker Compose

**File:** `docker-compose.yml`

One file describes four services, their wiring, their volumes, and their startup order.

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: keycloak_pw
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keycloak"]
    networks: [ztnet]

  keycloak:
    image: quay.io/keycloak/keycloak:24.0
    command: start --import-realm --health-enabled=true
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_HTTPS_CERTIFICATE_FILE: /etc/x509/keycloak.crt
      KC_HTTPS_CERTIFICATE_KEY_FILE: /etc/x509/keycloak.key
      KC_HTTP_ENABLED: "false"
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
    ports: ["8443:8443"]
    volumes:
      - ./certs:/etc/x509:ro
      - ./keycloak/realm-export.json:/opt/keycloak/data/import/realm-export.json:ro
    depends_on:
      postgres: { condition: service_healthy }
    healthcheck:  # probes /health/ready on mgmt port 9000
      test: ["CMD-SHELL", "..."]
    networks: [ztnet]

  api:
    build: ./api
    environment:
      OIDC_ISSUER: https://keycloak:8443/realms/zerotrust
      OIDC_AUDIENCE: zerotrust-api
    volumes: ["./certs:/certs:ro"]
    depends_on:
      keycloak: { condition: service_healthy }
    networks: [ztnet]

  client:
    build: ./client
    environment:
      KEYCLOAK_URL: https://keycloak:8443
      API_URL: https://api:8444
      CLIENT_ID: python-client
      CLIENT_SECRET: change-me-in-realm-export
      CA_CERT: /certs/ca.crt
    volumes: ["./certs:/certs:ro"]
    depends_on: [api]
    networks: [ztnet]

networks:
  ztnet: { driver: bridge }
```

### Line by Line

| Lines | Explanation |
|-------|-------------|
| **L2–10** | **Postgres.** Keycloak needs a database to persist realms, users, sessions. The healthcheck lets us chain dependencies properly. |
| **L13** | Keycloak **24**. The Keycloak config API changed significantly at v17+ — everything uses `KC_*` env vars now. |
| **L14** | `--import-realm` tells Keycloak to boot and automatically import any JSON file in `/opt/keycloak/data/import/`. This is how we ship the tutorial with a pre-configured realm. |
| **L18–20** | Keycloak is explicitly told to serve TLS and *refuse* plain HTTP. Zero Trust: no insecure port, ever. |
| **L25** | **Directory bind-mount** (not file). Mounting individual files has a footgun: if the file doesn't exist on the host, Docker silently creates a directory. Mounting the whole folder avoids this. |
| **L28** | `service_healthy` — the API won't start until Keycloak's healthcheck goes green. Prevents the classic "connection refused" race condition. |
| **L36** | The **issuer URL**. This is the one Keycloak bakes into the `iss` claim of every JWT. The API will later check that incoming tokens match this exact string. |
| **L37** | The **audience** — the client ID in Keycloak that represents *this API*. Tokens not intended for `zerotrust-api` will be rejected. |
| **L46–47** | Inside the Docker network, services use container names. `https://keycloak:8443` resolves via Docker's embedded DNS. This is why our cert's SAN includes `keycloak`. |
| **L49** | The client secret. In production this lives in a secret manager, *not* in version control. |
| **L56** | A user-defined **bridge network**. Services on the same bridge can reach each other by name. Everything outside the bridge must come through published ports (only 8443 and 8444 are exposed). |

### About Healthchecks & Dependencies

A Docker healthcheck is a command that runs inside a container at regular intervals. Exit 0 = healthy, nonzero = unhealthy.

Compose's `depends_on: { service: { condition: service_healthy } }` waits for a dep to be *healthy*, not just *started*. Without this, the API container starts the moment Keycloak's container starts — but Keycloak takes 30–60s to actually bind its TLS listener. The API tries to connect, gets `connection refused`, crashes.

Pair healthchecks with application-level retries (like our OIDC discovery loop) for belt-and-suspenders robustness.

---

## 06 · Keycloak Realm

**File:** `keycloak/realm-export.json`

A Keycloak **realm** is an isolated tenant — users, groups, roles, clients. We ship a pre-configured one so the stack works at first boot.

```json
{
  "realm": "zerotrust",
  "enabled": true,
  "accessTokenLifespan": 300,
  "clients": [
    {
      "clientId": "zerotrust-api",
      "bearerOnly": true,
      "publicClient": false
    },
    {
      "clientId": "python-client",
      "secret": "change-me-in-realm-export",
      "serviceAccountsEnabled": true,
      "standardFlowEnabled": false,
      "directAccessGrantsEnabled": false,
      "protocolMappers": [
        {
          "name": "audience-zerotrust-api",
          "protocolMapper": "oidc-audience-mapper",
          "config": {
            "included.client.audience": "zerotrust-api",
            "access.token.claim": "true"
          }
        }
      ]
    }
  ]
}
```

### Line by Line

| Lines | Explanation |
|-------|-------------|
| **L4** | **Access token lifespan: 300 seconds** (5 min). Short lifetimes limit blast radius if a token leaks. Clients must refresh. |
| **L7–9** | The `zerotrust-api` client represents *the resource server*. `bearerOnly: true` means "this client never initiates login flows — it only accepts bearer tokens." It's the *target* of tokens, not an issuer. |
| **L12–13** | The `python-client` is the *caller*. It has a secret it trades for tokens. |
| **L14** | `serviceAccountsEnabled: true` flips on the **client credentials grant**. Keycloak will auto-create a "service account user" attached to this client. |
| **L15–16** | We *explicitly disable* the browser redirect flow and the password grant. This client is a backend service — it has one job, client-credentials. Disabling unused flows reduces attack surface. |
| **L17–26** | The **audience protocol mapper**. By default, Keycloak's client-credentials tokens have `aud: "account"`, which the Go API would reject. This mapper injects `zerotrust-api` into the `aud` array so the API's check passes. |

### ⚠️ Common Bug

Forget the audience mapper and you'll see `oidc: expected audience "zerotrust-api"` in the API logs even though the token is otherwise valid. **90% of first-time Keycloak + go-oidc integrations hit this.**

---

## 07 · The Go API

**File:** `api/main.go`

The heart of the system. ~115 lines of Go that refuse to answer a single question without a signed, unexpired, correctly-addressed JWT.

### 7A · Imports & Dependencies

```go
package main

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "encoding/json"
    "log"
    "net/http"
    "os"
    "strings"
    "time"

    "github.com/coreos/go-oidc/v3/oidc"
)
```

| Lines | Explanation |
|-------|-------------|
| **L5–6** | `crypto/tls` + `crypto/x509` — Go's standard library for TLS. We'll build a custom TLS config that trusts our local CA. |
| **L14** | **The one external dependency:** `coreos/go-oidc`. It handles JWKS fetching, signature verification, and claim validation. Worth reading the source of — it's about 2000 lines of very careful code. |

### About coreos/go-oidc

The de facto Go library for OIDC relying-party code. Originally written at CoreOS (now Red Hat), currently maintained as part of the Dex federated identity project.

Key things it does for you:
- Fetches and parses the OIDC discovery document
- Fetches and caches JWKS (with sensible TTL and retry)
- Handles `kid`-based key selection
- Verifies RS256/ES256/etc signatures
- Checks `iss`, `aud`, `exp`, `nbf`, `iat`

What it *doesn't* do: fetch tokens. That's the *client's* job (our Python script). `go-oidc` is purely for relying parties verifying tokens they receive.

### 7B · The Auth Middleware

This function wraps every protected handler. **Every. Single. Request. Runs through here.**

```go
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if !strings.HasPrefix(authHeader, "Bearer ") {
            http.Error(w, "missing bearer token", http.StatusUnauthorized)
            return
        }
        rawToken := strings.TrimPrefix(authHeader, "Bearer ")

        token, err := verifier.Verify(r.Context(), rawToken)
        if err != nil {
            log.Printf("token verification failed: %v", err)
            http.Error(w, "invalid token", http.StatusUnauthorized)
            return
        }

        var claims map[string]interface{}
        if err := token.Claims(&claims); err != nil {
            http.Error(w, "claims parse error", http.StatusUnauthorized)
            return
        }

        ctx := context.WithValue(r.Context(), "claims", claims)
        next(w, r.WithContext(ctx))
    }
}
```

| Lines | Explanation |
|-------|-------------|
| **L19** | The **middleware pattern**. Takes a handler, returns a *wrapped* handler that runs auth first. Pure Go idiom. |
| **L21–25** | Extract the `Authorization: Bearer ...` header. No header → 401. *Before* any cryptographic work — fail fast. |
| **L28** | **The money line.** `verifier.Verify()` does four things: parses the JWT, fetches JWKS if not cached, checks the RS256 signature, validates `iss` / `aud` / `exp`. If any step fails, `err` is non-nil. |
| **L30** | We log the reason server-side but send a generic `"invalid token"` to the client. *Never leak verification details to callers* — that's reconnaissance data for an attacker. |
| **L35–39** | Extract **claims** (the JSON payload) into a map for the downstream handler to use. |
| **L41–42** | Attach claims to the request context and call the next handler. The protected handler can now read `ctx.Value("claims")` safely — the token is validated. |

### About Claims

Claims are the named fields inside a JWT's payload. OIDC standardizes several:

- `iss` (issuer) — who minted this token
- `sub` (subject) — who the token is about
- `aud` (audience) — who the token is for
- `exp` (expiration) — unix timestamp after which it's invalid
- `iat` (issued at) — unix timestamp of issuance
- `azp` (authorized party) — the client that requested the token

Keycloak also ships custom claims: `realm_access.roles`, `resource_access.{client}.roles`, `preferred_username`, etc. Your API can use these for authorization decisions (e.g. "only users with role `admin` can delete").

### 7C · Bootstrapping the Verifier

This runs once at startup. It's where we configure trust.

```go
func main() {
    issuer := os.Getenv("OIDC_ISSUER")
    audience := os.Getenv("OIDC_AUDIENCE")

    caPEM, _ := os.ReadFile(os.Getenv("CA_CERT"))
    caPool := x509.NewCertPool()
    caPool.AppendCertsFromPEM(caPEM)

    httpClient := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{RootCAs: caPool},
        },
    }
    ctx := oidc.ClientContext(context.Background(), httpClient)

    var provider *oidc.Provider
    for attempt := 1; attempt <= 60; attempt++ {
        provider, err = oidc.NewProvider(ctx, issuer)
        if err == nil { break }
        time.Sleep(3 * time.Second)
    }

    verifier = provider.Verifier(&oidc.Config{
        ClientID: audience,
    })

    mux := http.NewServeMux()
    mux.HandleFunc("/api/resource", authMiddleware(protectedHandler))

    log.Fatal(http.ListenAndServeTLS(":8444",
        os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"), mux))
}
```

| Lines | Explanation |
|-------|-------------|
| **L61–63** | Read our local CA's public cert, parse it into an `x509.CertPool`. This pool is what Go will consult when deciding whether to trust a TLS server. |
| **L65–69** | Build a custom HTTP client whose TLS config *only* trusts our CA. The standard system trust store is bypassed. This client will be used for the JWKS fetch. |
| **L70** | `oidc.ClientContext` — quirky API, but important. It stores our custom HTTP client in the context so `go-oidc`'s internal fetches use it instead of `http.DefaultClient`. |
| **L72–77** | The **retry loop**. Keycloak takes 30–60s to boot. We try every 3 seconds for 3 minutes. `NewProvider` hits `{issuer}/.well-known/openid-configuration` — the OIDC **discovery endpoint**. |
| **L79–81** | Create the `Verifier`. Passing `ClientID: audience` tells it to enforce the `aud` claim check. |
| **L86–87** | `ListenAndServeTLS` (not `ListenAndServe`). Plain HTTP is never even bound. There's no port 8080 to "accidentally" use. |

### About the Discovery Endpoint

Every OIDC provider exposes a well-known URL: `{issuer}/.well-known/openid-configuration`. It returns a JSON document describing the provider's endpoints and capabilities:

```json
{
  "issuer": "https://keycloak:8443/realms/zerotrust",
  "token_endpoint": ".../protocol/openid-connect/token",
  "jwks_uri": ".../protocol/openid-connect/certs",
  "id_token_signing_alg_values_supported": ["RS256"]
}
```

Libraries like `go-oidc` use this to auto-configure. You give them the issuer URL once; they figure out everything else. It's why changing OIDC providers is mostly a config change, not a rewrite.

---

## 08 · API Dockerfile

**File:** `api/Dockerfile`

A textbook Go container: compile in one stage, copy the binary to a tiny runtime image. The final image is ~10MB.

```dockerfile
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download || true
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -o /api .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=build /api /api
ENTRYPOINT ["/api"]
```

| Lines | Explanation |
|-------|-------------|
| **L1** | `AS build` names this stage so we can reference it later. **Multi-stage build** pattern: the final image never sees the Go toolchain. |
| **L3–4** | Copy *only* `go.mod` first, then download deps. Docker caches layer-by-layer, so if we edit `main.go` but not `go.mod`, this layer is reused — rebuilds are fast. |
| **L6** | `CGO_ENABLED=0` produces a static binary that runs on Alpine (which uses musl libc, not glibc). Without this flag, you get cryptic "not found" errors on start. |
| **L8–10** | Start fresh from Alpine. Copy only the binary. `ca-certificates` is here so *if* the API ever needed to reach a public TLS endpoint, it could. For our JWKS fetch we use our custom CA pool, so this is belt-and-suspenders. |

---

## 09 · The Python Client

**File:** `client/client.py`

A service account impersonator. Gets a token, calls the API, proves that unauthenticated requests fail.

```python
import os, sys, time
import requests

KEYCLOAK_URL  = os.environ["KEYCLOAK_URL"]
API_URL       = os.environ["API_URL"]
CLIENT_ID     = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
CA_CERT       = os.environ["CA_CERT"]

TOKEN_ENDPOINT = f"{KEYCLOAK_URL}/realms/zerotrust/protocol/openid-connect/token"


def get_token() -> str:
    resp = requests.post(
        TOKEN_ENDPOINT,
        data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        verify=CA_CERT,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def call_api(token: str) -> dict:
    resp = requests.get(
        f"{API_URL}/api/resource",
        headers={"Authorization": f"Bearer {token}"},
        verify=CA_CERT,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


if __name__ == "__main__":
    token = get_token()
    print(call_api(token))
    # negative tests: no token, bad token
    bad = requests.get(f"{API_URL}/api/resource", verify=CA_CERT)
    print("unauth →", bad.status_code)
```

### Line by Line

| Lines | Explanation |
|-------|-------------|
| **L10** | **The token endpoint URL.** Every OIDC provider exposes this at a discoverable path; Keycloak's is `/realms/{realm}/protocol/openid-connect/token`. |
| **L16** | `grant_type=client_credentials` — the machine-to-machine flow. No user, no browser redirect, no PKCE. Just "here are my creds, give me a token." |
| **L20** | `verify=CA_CERT` — **this is the critical bit**. Without it, `requests` would use the system CA store (which doesn't know our local CA) and the connection would fail. With it, Keycloak's cert is validated against our CA. |
| **L23** | `raise_for_status()` — turns non-2xx responses into Python exceptions. Critical for fail-fast behavior. |
| **L29** | The `Authorization: Bearer <token>` header is the OAuth2 standard for presenting a token. |
| **L40** | **The negative test.** A request with no Auth header. We expect this to return 401. If it doesn't, our Zero Trust is broken. |

### Why `requests`?

It's the de facto HTTP client for Python. Under the hood it wraps `urllib3`, which wraps Python's `ssl` module. The `verify=` parameter plumbs straight through to OpenSSL's certificate chain validation. There's no magic — just well-layered libraries.

---

## 10 · Run & Observe

### Step 01 — Generate local certificates (one time)

```bash
cd certs && chmod +x generate-certs.sh && ./generate-certs.sh && cd ..
```

### Step 02 — Build images and start the stack

```bash
docker compose up --build
```

First run takes 60–90s while Keycloak imports the realm. The API will log `waiting for keycloak OIDC discovery` until Keycloak is ready. This is expected.

### Step 03 — Expected output

```
Got token: eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIi...
API said: {'message': 'Zero Trust says hello', ...}
Unauthenticated call status: 401
Forged-token call status: 401
```

### What Just Happened

The Python client:

1. Opened a TLS connection to Keycloak (validating Keycloak's cert against our CA)
2. Presented its `client_id`/`secret`
3. Received a signed JWT
4. Opened another TLS connection to the Go API (validating *its* cert too)
5. Presented the JWT → got data back
6. Did two control calls with missing / forged tokens → got 401 rejections

**That's the entire Zero Trust model in one script.**

---

## 11 · Testing the System

The interesting tests aren't the happy path — they're the failure modes. Each one proves a specific attacker question is answered correctly.

### Manual curl test

```bash
TOKEN=$(curl -s --cacert certs/ca.crt \
  -X POST https://localhost:8443/realms/zerotrust/protocol/openid-connect/token \
  -d "grant_type=client_credentials" \
  -d "client_id=python-client" \
  -d "client_secret=change-me-in-realm-export" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl --cacert certs/ca.crt -H "Authorization: Bearer $TOKEN" \
  https://localhost:8444/api/resource
```

### Decode the JWT

Paste the token into [jwt.io](https://jwt.io), or locally:

```bash
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

You'll see claims like `iss`, `aud`, `exp`, `azp`, `sub`. The API middleware is checking `iss`, `aud`, `exp` on every request.

### Attacker scenarios

These test the specific security properties:

| Scenario | Expected | What it proves |
|----------|----------|----------------|
| No auth header | 401 | Request rejected before any crypto |
| Forged/malformed token | 401 | Signature check fails |
| Tampered payload (flip a byte, re-base64) | 401 | Signature no longer matches |
| Expired token (wait past `exp`) | 401 | Claim validation |
| Token for wrong audience | 401 | `aud` check |
| Plain HTTP call | Connection refused | API only binds TLS |
| Skip `--cacert` | Client-side TLS failure | Client also enforces identity |

### Watch the logs

Keep a second terminal running `docker compose logs -f api` while you experiment. Every rejection prints its reason:

```
token verification failed: oidc: token is expired
token verification failed: oidc: expected audience "zerotrust-api"
token verification failed: failed to verify signature: ...
```

Each error message corresponds to a specific security check.

---

## 12 · Glossary

| Term | Definition |
|------|------------|
| **JWT** | JSON Web Token. Three base64 parts separated by dots: header, payload, signature. |
| **OIDC** | OpenID Connect. Identity layer on top of OAuth 2.0. |
| **JWKS** | JSON Web Key Set. The public keys an OIDC provider uses to sign tokens. |
| **IdP** | Identity Provider. Keycloak, in our case. |
| **Resource Server** | The API that enforces token validation. |
| **Bearer Token** | Any holder of the token is assumed authorized. Must be kept secret. |
| **Realm** | Keycloak's isolation unit. Users, clients, roles. |
| **Audience (aud)** | The intended recipient of a token. Rejecting mismatches prevents token reuse. |
| **Issuer (iss)** | Who minted the token. Must match the IdP's exact URL. |
| **Client Credentials Grant** | OAuth2 flow for machine-to-machine auth. No user involved. |
| **CA** | Certificate Authority. Signs certs, vouches for identities. |
| **SAN** | Subject Alternative Name. The hostname(s) a cert is valid for. |
| **mTLS** | Mutual TLS. Both sides present certs. |
| **Service Account** | A non-human identity in Keycloak, attached to a client. |

---

## Next Steps

Once you have the stack running, try extending it:

1. **Shorten the token lifetime to 60 seconds** in `realm-export.json`, then loop the client calling the API every 30 seconds. Watch what happens at the 60-second mark. Implement token caching with auto-refresh — the single most common production pattern.

2. **Add role-based authorization.** In `protectedHandler`, pull `resource_access.zerotrust-api.roles` from claims and require `api:read`. Add a `/api/admin` endpoint requiring `api:write`. Assign only one role and watch it get 403 on the other endpoint.

3. **Add mutual TLS.** Require the client to present its own cert to the API. Now the client proves both *what* it is (cert) and *who* it's acting as (token).

4. **Break things on purpose.** Edit the token's payload manually, re-encode, watch the signature check fail. Change the issuer URL and watch discovery fail. These failure modes build intuition for what each check is actually doing.

---

## License & Credits

This tutorial was built to demonstrate Zero Trust principles in the smallest possible working stack. No production use without hardening:

- Replace hardcoded secrets with a secret manager (Vault, AWS Secrets Manager)
- Use a real CA (Let's Encrypt, internal PKI)
- Enable admin account protection in Keycloak
- Add rate limiting, request logging, audit trails
- Consider mTLS for service-to-service communication
- Use shorter token lifetimes with refresh token rotation

Built with Keycloak 24, Go 1.22, Python 3.12.