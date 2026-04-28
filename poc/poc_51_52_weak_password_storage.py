"""
PoC 5.1 / 5.2 - Weak password policy + insecure password storage
=================================================================
Demonstrates that v1 accepts any password (including a single character)
and stores it as an unsalted MD5 hash.

Also re-runs the same registration against v2 to show the policy is enforced.

Requirements: v1 on http://127.0.0.1:5000, v2 on http://127.0.0.1:5001
"""

import requests
import sqlite3
import os

V1 = "http://127.0.0.1:5000"
V2 = "http://127.0.0.1:5001"
EMAIL = "poc_weak@authx.internal"
WEAK_PASSWORD = "a"
STRONG_PASSWORD = "Secure@99"  # meets v2 policy

V1_DB = os.path.join(os.path.dirname(__file__), "..", "v1-vulnerable", "authx.db")
V2_DB = os.path.join(os.path.dirname(__file__), "..", "v2-secure", "authx.db")


def register(base, email, password):
    r = requests.post(f"{base}/register", data={"email": email, "password": password})
    return r.status_code, r.text


def dump_password(db_path, email):
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT email, password FROM users WHERE email=?", (email,)
    ).fetchone()
    conn.close()
    return row


def separator(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print("="*60)


def main():
    # -- v1: attack -----------------------------------------------
    separator("v1-vulnerable - attack")

    print(f"[*] Registering '{EMAIL}' with weak password: {WEAK_PASSWORD!r}")
    status, _ = register(V1, EMAIL, WEAK_PASSWORD)
    print(f"    HTTP {status}")
    if status in (201, 409):
        print("    [!] Weak password accepted - no policy enforced.")
    else:
        print(f"    Unexpected response ({status}). Is v1 running on port 5000?")
        return

    print()
    print("[*] Reading stored hash from v1 database...")
    row = dump_password(V1_DB, EMAIL)
    if row:
        print(f"    email : {row[0]}")
        print(f"    hash  : {row[1]}")
        print("    [!] MD5 - no salt, reversible in seconds via rainbow tables.")
    else:
        print("    User not found in v1 DB.")

    # -- v2: re-test ----------------------------------------------
    separator("v2-secure - re-test")

    print(f"[*] Attempting same weak password {WEAK_PASSWORD!r} on v2...")
    status2, _ = register(V2, EMAIL, WEAK_PASSWORD)
    print(f"    HTTP {status2}")
    if status2 == 400:
        print("    [+] Weak password rejected by policy.")
    else:
        print(f"    Unexpected response ({status2}).")

    print()
    print(f"[*] Registering with a strong password {STRONG_PASSWORD!r} on v2...")
    status3, _ = register(V2, EMAIL, STRONG_PASSWORD)
    print(f"    HTTP {status3}")
    if status3 in (201, 409):
        print("[*] Reading stored hash from v2 database...")
        row2 = dump_password(V2_DB, EMAIL)
        if row2:
            print(f"    email : {row2[0]}")
            print(f"    hash  : {row2[1][:20]}...  (bcrypt - salted, slow)")
            print("    [+] bcrypt hash - cracking is computationally infeasible.")


if __name__ == "__main__":
    main()
