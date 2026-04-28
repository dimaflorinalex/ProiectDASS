"""
PoC 5.4 - User enumeration via distinct error messages
=======================================================
v1 returns different messages for a missing account vs. a wrong password,
allowing an attacker to enumerate valid usernames.
v2 returns a single generic message for both cases.

Requirements: v1 on http://127.0.0.1:5000, v2 on http://127.0.0.1:5001
"""

import requests
import re

V1 = "http://127.0.0.1:5000"
V2 = "http://127.0.0.1:5001"
KNOWN_EMAIL = "admin@authx.internal"    # must exist in the target DB
UNKNOWN_EMAIL = "ghost@authx.internal"  # must not exist
WRONG_PASSWORD = "wrongpass"


def login_attempt(base, email, password):
    r = requests.post(f"{base}/login", data={"email": email, "password": password})
    match = re.search(r'class="alert alert-error"[^>]*>([^<]+)<', r.text)
    message = match.group(1).strip() if match else "(no message)"
    return r.status_code, message


def probe(base, label):
    print(f"[*] [{label}] Probing non-existent email {UNKNOWN_EMAIL!r}:")
    s1, m1 = login_attempt(base, UNKNOWN_EMAIL, WRONG_PASSWORD)
    print(f"    HTTP {s1}  |  \"{m1}\"")

    print(f"[*] [{label}] Probing existing email {KNOWN_EMAIL!r} (wrong password):")
    s2, m2 = login_attempt(base, KNOWN_EMAIL, WRONG_PASSWORD)
    print(f"    HTTP {s2}  |  \"{m2}\"")

    if m1 != m2:
        print(f"    [!] Messages differ - user enumeration is possible.")
    else:
        print(f"    [+] Same message for both cases - enumeration prevented.")


def separator(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


def main():
    separator("v1-vulnerable - attack")
    probe(V1, "v1")

    separator("v2-secure - re-test")
    probe(V2, "v2")


if __name__ == "__main__":
    main()
