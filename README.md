# AuthX - Break the Login

A Flask web application built in two versions to demonstrate common authentication vulnerabilities and their fixes.

**Team Members**  
- Dima Florin-Alexandru - Group 462, Faculty of Mathematics and Computer Science, University of Bucharest
- Assisted by Copilot (Claude Sonnet 4.6) for polishing documentation and increasing coverage of security fixes.

---

## Repository structure

```
ProiectDASS/
├── v1-vulnerable/          # Intentionally insecure version (port 5000)
│   ├── app.py
│   ├── models.py
│   ├── requirements.txt
│   ├── environment.yml
│   └── templates/
├── v2-secure/              # Hardened version (port 5001)
│   ├── app.py
│   ├── models.py
│   ├── requirements.txt
│   ├── environment.yml
│   └── templates/
├── poc/                    # Proof-of-concept attack scripts
│   ├── poc_51_52_weak_password_storage.py
│   ├── poc_53_brute_force.py
│   ├── poc_54_user_enumeration.py
│   ├── poc_55_insecure_session.py
│   └── poc_56_reset_token.py
├── REPORT.md
└── README.md
```

---

## Requirements

- [Miniconda](https://docs.conda.io/en/latest/miniconda.html) (or Anaconda)

---

## Setup

Each version has its own isolated conda environment.

```bash
# Create and activate the environment for v1
conda env create -f v1-vulnerable/environment.yml
conda activate dass-v1

# Create and activate the environment for v2
conda env create -f v2-secure/environment.yml
conda activate dass-v2
```

---

## Running the applications

### v1 - Vulnerable (port 5000)

```bash
cd v1-vulnerable
conda run -n dass-v1 --no-capture-output python app.py
```

Open `http://127.0.0.1:5000`

### v2 - Secure (port 5001)

```bash
cd v2-secure
conda run -n dass-v2 --no-capture-output python app.py
```

Open `http://127.0.0.1:5001`

---

## Default accounts

Neither version seeds the database. Register accounts manually via the `/register` page.

To create a **MANAGER** account, register normally (role defaults to `ANALYST`), then update the role directly:

```bash
# From the version's directory (where authx.db lives)
python -c "
import sqlite3
conn = sqlite3.connect('authx.db')
conn.execute(\"UPDATE users SET role='MANAGER' WHERE email='your@email.com'\")
conn.commit()
"
```

---

## Running the PoC scripts

All scripts run against **both versions** in sequence - first demonstrating the attack on v1, then confirming it is blocked on v2. Make sure both apps are running before executing them.

```bash
conda run -n dass-v1 --no-capture-output python poc/poc_51_52_weak_password_storage.py    # weak policy + MD5 storage
conda run -n dass-v1 --no-capture-output python poc/poc_53_brute_force.py                 # brute force / no rate limiting
conda run -n dass-v1 --no-capture-output python poc/poc_54_user_enumeration.py            # user enumeration via error messages
conda run -n dass-v1 --no-capture-output python poc/poc_55_insecure_session.py            # insecure session cookie
conda run -n dass-v1 --no-capture-output python poc/poc_56_reset_token.py                 # predictable & reusable reset token
```

> **Note:** `poc_51_52_weak_password_storage.py` reads `authx.db` directly from `v1-vulnerable/`. The path is resolved automatically relative to the script, so it works from any working directory.

---

## Vulnerabilities covered (not exhaustive)

| # | Category | v1 flaw | v2 fix |
|---|----------|---------|--------|
| 5.1 | Password policy | Any password accepted | Min 8 chars, upper/lower/digit/symbol |
| 5.2 | Password storage | MD5 without salt | bcrypt with auto-generated salt |
| 5.3 | Brute force | No limit on attempts | Lockout after 5 failures (5 min) |
| 5.4 | User enumeration | Distinct error messages | Single generic `"Invalid credentials."` |
| 5.5 | Session management | Predictable `uid` cookie, no flags | Random token, `HttpOnly; SameSite=Strict; max-age=1800` |
| 5.6 | Password reset | Predictable, reusable, no expiry | `secrets.token_urlsafe(32)`, 15-min expiry, one-time use |
| 5.7 | IDOR on tickets | No ownership check on edit/delete | Ownership verified before every write |
