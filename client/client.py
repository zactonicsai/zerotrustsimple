"""
Zero Trust client — presents BOTH:
  1. A client certificate (mTLS) to the Go API.
  2. A JWT bearer token obtained from Keycloak.

The token is the answer to "who am I acting as."
The cert is the answer to "what process is making this call."
Both must agree on identity (cert CN == token azp) or the API rejects.

Note: we only present the client cert to the Go API, not to Keycloak.
Keycloak authenticates us with client_id/secret. Adding mTLS to the
Keycloak call would require Keycloak's "mTLS-bound access tokens"
feature, which is a deeper topic.
"""
import os
import sys
import time
import requests

KEYCLOAK_URL  = os.environ["KEYCLOAK_URL"]
API_URL       = os.environ["API_URL"]
CLIENT_ID     = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
CA_CERT       = os.environ["CA_CERT"]
CLIENT_CERT   = os.environ["CLIENT_CERT"]   # for mTLS to the API
CLIENT_KEY    = os.environ["CLIENT_KEY"]    # for mTLS to the API

TOKEN_ENDPOINT = f"{KEYCLOAK_URL}/realms/zerotrust/protocol/openid-connect/token"


def preflight():
    """Verify every cert file exists before we try to use it."""
    for label, path in [("CA_CERT", CA_CERT),
                        ("CLIENT_CERT", CLIENT_CERT),
                        ("CLIENT_KEY", CLIENT_KEY)]:
        if not os.path.isfile(path):
            if os.path.isdir(path):
                print(f"FATAL: {label}={path} is a directory, not a file. "
                      "Run certs/generate-certs.sh on the host before docker compose up.")
            else:
                print(f"FATAL: {label}={path} does not exist.")
            sys.exit(1)


def get_token() -> str:
    """Fetch a JWT from Keycloak via client credentials.
    No mTLS here — Keycloak authenticates us by secret."""
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
    """Call the Go API — mTLS + bearer token.

    The `cert=(cert, key)` tuple is what makes this mTLS. requests
    passes it to urllib3 which passes it to OpenSSL, which presents
    the cert during the TLS handshake.
    """
    resp = requests.get(
        f"{API_URL}/api/resource",
        headers={"Authorization": f"Bearer {token}"},
        verify=CA_CERT,
        cert=(CLIENT_CERT, CLIENT_KEY),
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def call_api_without_cert(token: str):
    """Negative test: valid token but NO client cert. Should fail at TLS
    handshake (the API rejects before any HTTP is exchanged).
    requests will raise an SSLError."""
    return requests.get(
        f"{API_URL}/api/resource",
        headers={"Authorization": f"Bearer {token}"},
        verify=CA_CERT,
        # cert= intentionally omitted
        timeout=5,
    )


def call_api_without_token():
    """Negative test: valid cert but NO token. Should pass TLS handshake
    (mTLS OK) but get 401 from the bearer-token middleware."""
    return requests.get(
        f"{API_URL}/api/resource",
        verify=CA_CERT,
        cert=(CLIENT_CERT, CLIENT_KEY),
        timeout=5,
    )


def main():
    preflight()

    token = None
    for attempt in range(40):
        try:
            token = get_token()
            break
        except requests.RequestException as e:
            print(f"[{attempt}] waiting for keycloak: {e}")
            time.sleep(3)
    if token is None:
        print("keycloak never came up")
        sys.exit(1)

    print(f"Got token: {token[:40]}...")

    # --- Happy path: cert + token ---
    result = call_api(token)
    print("API said:", result)

    # --- Negative: token but no cert ---
    print("\n[negative] calling with token but NO client cert...")
    try:
        bad = call_api_without_cert(token)
        print(f"  UNEXPECTED: got status {bad.status_code}")
    except requests.exceptions.SSLError as e:
        print(f"  ✓ TLS handshake rejected (expected): {type(e).__name__}")
    except requests.exceptions.ConnectionError as e:
        # Some TLS rejection surface as ConnectionError depending on Python/OpenSSL version
        print(f"  ✓ Connection rejected at TLS layer (expected): {type(e).__name__}")

    # --- Negative: cert but no token ---
    print("\n[negative] calling with cert but NO bearer token...")
    bad = call_api_without_token()
    print(f"  status: {bad.status_code} (expect 401)")
    print(f"  body: {bad.text.strip()}")

    # --- Negative: cert + forged token ---
    print("\n[negative] calling with cert and FORGED token...")
    bad = requests.get(
        f"{API_URL}/api/resource",
        headers={"Authorization": "Bearer not-a-real-token"},
        verify=CA_CERT,
        cert=(CLIENT_CERT, CLIENT_KEY),
        timeout=5,
    )
    print(f"  status: {bad.status_code} (expect 401)")


if __name__ == "__main__":
    main()
