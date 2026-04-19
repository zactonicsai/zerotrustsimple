import os
import sys
import time
import requests

KEYCLOAK_URL = os.environ["KEYCLOAK_URL"]
API_URL = os.environ["API_URL"]
CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
CA_CERT = os.environ["CA_CERT"]

TOKEN_ENDPOINT = f"{KEYCLOAK_URL}/realms/zerotrust/protocol/openid-connect/token"


def preflight():
    if not os.path.isfile(CA_CERT):
        if os.path.isdir(CA_CERT):
            print(
                f"FATAL: {CA_CERT} is a directory, not a file. "
                "Run certs/generate-certs.sh on the host before docker compose up."
            )
        else:
            print(f"FATAL: {CA_CERT} does not exist.")
        sys.exit(1)


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
    result = call_api(token)
    print("API said:", result)

    bad = requests.get(f"{API_URL}/api/resource", verify=CA_CERT, timeout=5)
    print(f"Unauthenticated call status: {bad.status_code}")

    bad = requests.get(
        f"{API_URL}/api/resource",
        headers={"Authorization": "Bearer not-a-real-token"},
        verify=CA_CERT,
        timeout=5,
    )
    print(f"Forged-token call status: {bad.status_code}")


if __name__ == "__main__":
    main()
