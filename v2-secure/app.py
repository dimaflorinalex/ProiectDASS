from flask import (
    Flask, request, render_template, redirect,
    url_for, make_response
)
import sqlite3
import bcrypt
import re
import secrets
import time
from datetime import datetime, timedelta
from models import get_connection, setup_database

app = Flask(__name__)
setup_database()

# ─────────────────────────── in-memory stores ───────────────────
# reset_tokens: { token: { user_id, expires } }
reset_tokens: dict = {}

# sessions: { session_token: user_id }
sessions: dict = {}

# login_attempts: { email: { count, blocked_until } }
login_attempts: dict = {}

MAX_ATTEMPTS = 5
BLOCK_MINUTES = 5
SESSION_SECONDS = 1800      # 30 minutes


# ─────────────────────────── helpers ────────────────────────────

def record_event(user_id, action, resource="app", resource_id="0"):
    """Insert an event into audit_logs."""
    conn = get_connection()
    ip = request.remote_addr or "unknown"
    uid = user_id if user_id else None
    conn.execute(
        "INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address)"
        " VALUES (?, ?, ?, ?, ?)",
        (uid, action, resource, resource_id, ip),
    )
    conn.commit()
    conn.close()


def get_current_user(token: str):
    """Return the user dict for a valid session token or None."""
    if not token or token not in sessions:
        return None
    conn = get_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE id=?", (sessions[token],)
    ).fetchone()
    conn.close()
    return dict(user) if user else None


def is_strong_password(password: str) -> bool:
    """Enforce: min 8 chars, uppercase, lowercase, digit, special char."""
    return (
        len(password) >= 8
        and bool(re.search(r"[A-Z]", password))
        and bool(re.search(r"[a-z]", password))
        and bool(re.search(r"\d", password))
        and bool(re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:,.<>?/]', password))
    )


# ─────────────────────────── auth ───────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    start = time.monotonic()

    # 4.3 Rate limiting check
    now = datetime.now()
    attempt_data = login_attempts.get(email, {"count": 0, "blocked_until": None})
    if attempt_data["blocked_until"] and now < attempt_data["blocked_until"]:
        return render_template("login.html", error="Too many failed attempts. Try again later."), 429

    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()

    # 4.4 Uniform response: always run bcrypt to prevent timing oracle
    dummy = bcrypt.hashpw(b"__dummy__", bcrypt.gensalt())
    if user:
        valid = bcrypt.checkpw(password.encode(), user["password"].encode())
    else:
        bcrypt.checkpw(password.encode(), dummy)
        valid = False

    # 4.4 Enforce a minimum response time to prevent timing-based enumeration
    elapsed = time.monotonic() - start
    if elapsed < 0.5:
        time.sleep(0.5 - elapsed)

    if not valid:
        attempt_data["count"] += 1
        if attempt_data["count"] >= MAX_ATTEMPTS:
            attempt_data["blocked_until"] = now + timedelta(minutes=BLOCK_MINUTES)
        login_attempts[email] = attempt_data
        record_event(None, "LOGIN_FAIL", "auth", email)
        # 4.4 Single generic message - does not reveal whether account exists
        return render_template("login.html", error="Invalid credentials."), 401

    # Successful login - reset rate limit counter
    login_attempts[email] = {"count": 0, "blocked_until": None}

    # 4.5 Rotate session token on every login
    session_token = secrets.token_urlsafe(32)
    sessions[session_token] = user["id"]
    record_event(user["id"], "LOGIN", "auth", str(user["id"]))

    resp = make_response(redirect(url_for("dashboard")))
    # 4.5 Secure cookie: HttpOnly, SameSite=Strict, 30-minute expiry
    resp.set_cookie(
        "session_token",
        session_token,
        httponly=True,
        secure=False,       # set True when serving over HTTPS
        samesite="Strict",
        max_age=SESSION_SECONDS,
    )
    return resp


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    if not email or not password:
        return render_template("register.html", error="All fields are required."), 400

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return render_template("register.html", error="Invalid email format."), 400

    # 4.1 Enforce strong password policy
    if not is_strong_password(password):
        return render_template(
            "register.html",
            error="Password must be at least 8 characters and include uppercase, lowercase, a digit, and a special character."
        ), 400

    conn = get_connection()
    try:
        # 4.2 Hash with bcrypt (includes per-user salt automatically)
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        conn.execute(
            "INSERT INTO users (email, password, role) VALUES (?, ?, ?)",
            (email, hashed, "ANALYST"),
        )
        conn.commit()
        uid = conn.execute(
            "SELECT id FROM users WHERE email=?", (email,)
        ).fetchone()[0]
        record_event(uid, "REGISTER", "auth", str(uid))
    except sqlite3.IntegrityError:
        return render_template("register.html", error="Email already registered."), 409
    finally:
        conn.close()

    return render_template("register.html", message="Account created! You can now log in."), 201


@app.route("/logout")
def logout():
    token = request.cookies.get("session_token")
    user_id = None

    # 4.5 Invalidate server-side session on logout
    if token and token in sessions:
        user_id = sessions.pop(token)

    record_event(user_id, "LOGOUT", "auth", str(user_id) if user_id else "0")
    resp = make_response(redirect(url_for("login")))
    resp.set_cookie("session_token", "", expires=0)
    return resp


# ─────────────────────────── password reset ────────────────────

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot.html")

    email = request.form.get("email", "").strip()
    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()

    if not user:
        return render_template("forgot.html", error="Email not found."), 404

    # 4.6 Cryptographically random one-time token with 15-minute expiry
    token = secrets.token_urlsafe(32)
    reset_tokens[token] = {
        "user_id": user["id"],
        "expires": datetime.now() + timedelta(minutes=15),
    }
    reset_url = url_for("reset_password", token=token, _external=True)
    record_event(user["id"], "FORGOT_PASSWORD", "auth", str(user["id"]))
    return render_template("forgot.html", reset_link=reset_url)


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    token = request.args.get("token") or request.form.get("token", "")
    if request.method == "GET":
        return render_template("reset.html", token=token)

    new_pass = request.form.get("password", "")
    if not token or not new_pass:
        return render_template("reset.html", error="Missing data.", token=token), 400

    if not is_strong_password(new_pass):
        return render_template(
            "reset.html",
            error="Password must be at least 8 characters and include uppercase, lowercase, a digit, and a special character.",
            token=token,
        ), 400

    data = reset_tokens.get(token)
    if not data:
        return render_template("reset.html", error="Invalid or already-used token.", token=token), 400

    # 4.6 Check token expiry
    if datetime.now() > data["expires"]:
        reset_tokens.pop(token, None)
        return render_template("reset.html", error="Token has expired.", token=token), 400

    uid = data["user_id"]
    hashed = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt()).decode()
    conn = get_connection()
    conn.execute("UPDATE users SET password=? WHERE id=?", (hashed, uid))
    conn.commit()
    conn.close()

    # 4.6 Invalidate token immediately after use (one-time use)
    reset_tokens.pop(token, None)
    record_event(uid, "RESET_PASSWORD", "users", str(uid))
    return render_template("reset.html", message="Password updated! Please log in.", token="")


# ─────────────────────────── dashboard / tickets ────────────────

@app.route("/dashboard")
def dashboard():
    token = request.cookies.get("session_token")
    user = get_current_user(token)
    if not user:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=user)


@app.route("/tickets", methods=["GET", "POST"])
def tickets():
    token = request.cookies.get("session_token")
    user = get_current_user(token)
    if not user:
        return redirect(url_for("login"))

    uid = user["id"]
    conn = get_connection()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        desc = request.form.get("description", "")
        sev = request.form.get("severity", "LOW")
        if sev not in ("LOW", "MED", "HIGH"):
            sev = "LOW"
        if title:
            conn.execute(
                "INSERT INTO tickets (title, description, severity, owner_id)"
                " VALUES (?, ?, ?, ?)",
                (title, desc, sev, uid),
            )
            conn.commit()
            tid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            record_event(uid, "CREATE_TICKET", "tickets", str(tid))

    q = request.args.get("q", "")
    if q:
        if user["role"] == "MANAGER":
            rows = conn.execute(
                "SELECT * FROM tickets WHERE title LIKE ?", (f"%{q}%",)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM tickets WHERE owner_id=? AND title LIKE ?",
                (uid, f"%{q}%"),
            ).fetchall()
    else:
        if user["role"] == "MANAGER":
            rows = conn.execute("SELECT * FROM tickets").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM tickets WHERE owner_id=?", (uid,)
            ).fetchall()
    conn.close()
    return render_template("tickets.html", tickets=[dict(r) for r in rows], user=user, q=q)


@app.route("/audit")
def audit():
    token = request.cookies.get("session_token")
    user = get_current_user(token)
    if not user:
        return redirect(url_for("login"))
    if user["role"] != "MANAGER":
        return render_template("audit.html", logs=[], error="Access denied."), 403
    conn = get_connection()
    logs = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("audit.html", logs=[dict(l) for l in logs])


# ─────────────────────────── ticket CRUD ────────────────────────

@app.route("/tickets/<int:ticket_id>/edit", methods=["GET", "POST"])
def edit_ticket(ticket_id):
    token = request.cookies.get("session_token")
    user = get_current_user(token)
    if not user:
        return redirect(url_for("login"))

    conn = get_connection()
    ticket = conn.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone()
    if not ticket:
        conn.close()
        return redirect(url_for("tickets"))

    # Access control: only the owner or a MANAGER may edit
    if ticket["owner_id"] != user["id"] and user["role"] != "MANAGER":
        conn.close()
        record_event(user["id"], "UNAUTHORIZED_TICKET_EDIT", "tickets", str(ticket_id))
        return redirect(url_for("tickets"))

    if request.method == "POST":
        title  = request.form.get("title", "").strip()
        desc   = request.form.get("description", "")
        sev    = request.form.get("severity", ticket["severity"])
        status = request.form.get("status", ticket["status"])
        if sev not in ("LOW", "MED", "HIGH"):
            sev = ticket["severity"]
        if status not in ("OPEN", "IN_PROGRESS", "RESOLVED"):
            status = ticket["status"]
        if title:
            conn.execute(
                "UPDATE tickets SET title=?, description=?, severity=?, status=?,"
                " updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (title, desc, sev, status, ticket_id),
            )
            conn.commit()
            record_event(user["id"], "UPDATE_TICKET", "tickets", str(ticket_id))
        conn.close()
        return redirect(url_for("tickets"))

    uid = user["id"]
    if user["role"] == "MANAGER":
        rows = conn.execute("SELECT * FROM tickets").fetchall()
    else:
        rows = conn.execute("SELECT * FROM tickets WHERE owner_id=?", (uid,)).fetchall()
    conn.close()
    return render_template(
        "tickets.html",
        tickets=[dict(r) for r in rows],
        user=user,
        q="",
        edit_ticket=dict(ticket),
    )


@app.route("/tickets/<int:ticket_id>/delete", methods=["POST"])
def delete_ticket(ticket_id):
    token = request.cookies.get("session_token")
    user = get_current_user(token)
    if not user:
        return redirect(url_for("login"))

    conn = get_connection()
    ticket = conn.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone()
    if not ticket:
        conn.close()
        return redirect(url_for("tickets"))

    # Access control: only the owner or a MANAGER may delete
    if ticket["owner_id"] != user["id"] and user["role"] != "MANAGER":
        conn.close()
        record_event(user["id"], "UNAUTHORIZED_TICKET_DELETE", "tickets", str(ticket_id))
        return redirect(url_for("tickets"))

    conn.execute("DELETE FROM tickets WHERE id=?", (ticket_id,))
    conn.commit()
    record_event(user["id"], "DELETE_TICKET", "tickets", str(ticket_id))
    conn.close()
    return redirect(url_for("tickets"))


if __name__ == "__main__":
    app.run(debug=False, port=5001)
