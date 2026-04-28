from flask import (
    Flask, request, render_template, redirect,
    url_for, make_response, session
)
import sqlite3
import hashlib
from models import get_connection, setup_database

app = Flask(__name__)
app.secret_key = "authx-secret-2024"   # weak, hardcoded
setup_database()


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


def weak_hash(password: str) -> str:
    """4.2 - weak hash: plain MD5, no salt."""
    return hashlib.md5(password.encode()).hexdigest()


# ─────────────────────────── auth ───────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    conn = get_connection()
    # parameterised query - but vulnerable to user enumeration via distinct messages
    user = conn.execute(
        "SELECT * FROM users WHERE email = ?", (email,)
    ).fetchone()
    conn.close()

    # 4.4 User Enumeration - distinct messages reveal whether the account exists
    if not user:
        record_event(None, "LOGIN_FAIL_NO_USER", "auth", email)
        return render_template("login.html", error="Account does not exist."), 401

    hashed_input = weak_hash(password)
    if user["password"] != hashed_input:
        record_event(user["id"], "LOGIN_FAIL_WRONG_PASS", "auth", str(user["id"]))
        return render_template("login.html", error="Wrong password."), 401

    # 4.5 Cookie without HttpOnly/Secure/SameSite
    record_event(user["id"], "LOGIN", "auth", str(user["id"]))
    resp = make_response(redirect(url_for("dashboard")))
    resp.set_cookie("uid", str(user["id"]))  # predictable value, no security flags
    return resp


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    if not email or not password:
        return render_template("register.html", error="All fields are required."), 400

    # 4.1 Weak password policy - no complexity check whatsoever
    conn = get_connection()
    try:
        # 4.2 Insecure storage - MD5 without salt
        conn.execute(
            "INSERT INTO users (email, password, role) VALUES (?, ?, ?)",
            (email, weak_hash(password), "ANALYST"),
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
    uid = request.cookies.get("uid")
    record_event(uid, "LOGOUT", "auth", str(uid) if uid else "0")
    resp = make_response(redirect(url_for("login")))
    resp.set_cookie("uid", "", expires=0)
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

    # 4.6 Predictable token: derived from user_id, no expiry
    token = f"tok-{user['id']}-reset"
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

    # extract user_id directly from the token string
    try:
        uid = int(token.split("-")[1])
    except (IndexError, ValueError):
        return render_template("reset.html", error="Invalid token.", token=token), 400

    # 4.6 no check whether this token was already used
    conn = get_connection()
    conn.execute(
        "UPDATE users SET password=? WHERE id=?",
        (weak_hash(new_pass), uid),
    )
    conn.commit()
    conn.close()
    record_event(uid, "RESET_PASSWORD", "users", str(uid))
    return render_template("reset.html", message="Password updated! Please log in.", token=token)


# ─────────────────────────── dashboard / tickets ────────────────

@app.route("/dashboard")
def dashboard():
    uid = request.cookies.get("uid")
    if not uid:
        return redirect(url_for("login"))
    conn = get_connection()
    user = conn.execute(
        "SELECT id, email, role FROM users WHERE id=?", (uid,)
    ).fetchone()
    conn.close()
    if not user:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=dict(user))


@app.route("/tickets", methods=["GET", "POST"])
def tickets():
    uid = request.cookies.get("uid")
    if not uid:
        return redirect(url_for("login"))

    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        conn.close()
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        desc = request.form.get("description", "")
        sev = request.form.get("severity", "LOW")
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
    return render_template("tickets.html", tickets=[dict(r) for r in rows], user=dict(user), q=q)


@app.route("/audit")
def audit():
    uid = request.cookies.get("uid")
    if not uid:
        return redirect(url_for("login"))
    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not user or user["role"] != "MANAGER":
        conn.close()
        return render_template("audit.html", logs=[], error="Access denied."), 403
    logs = conn.execute(
        "SELECT * FROM audit_logs ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return render_template("audit.html", logs=[dict(l) for l in logs])


# ─────────────────────────── ticket CRUD ────────────────────────

@app.route("/tickets/<int:ticket_id>/edit", methods=["GET", "POST"])
def edit_ticket(ticket_id):
    uid = request.cookies.get("uid")
    if not uid:
        return redirect(url_for("login"))
    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        conn.close()
        return redirect(url_for("login"))

    # 4.7 IDOR: no ownership check — any authenticated user can edit any ticket
    ticket = conn.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone()
    if not ticket:
        conn.close()
        return redirect(url_for("tickets"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        desc  = request.form.get("description", "")
        sev   = request.form.get("severity", ticket["severity"])
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
            record_event(uid, "UPDATE_TICKET", "tickets", str(ticket_id))
        conn.close()
        return redirect(url_for("tickets"))

    if user["role"] == "MANAGER":
        rows = conn.execute("SELECT * FROM tickets").fetchall()
    else:
        rows = conn.execute("SELECT * FROM tickets WHERE owner_id=?", (uid,)).fetchall()
    conn.close()
    return render_template(
        "tickets.html",
        tickets=[dict(r) for r in rows],
        user=dict(user),
        q="",
        edit_ticket=dict(ticket),
    )


@app.route("/tickets/<int:ticket_id>/delete", methods=["POST"])
def delete_ticket(ticket_id):
    uid = request.cookies.get("uid")
    if not uid:
        return redirect(url_for("login"))
    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        conn.close()
        return redirect(url_for("login"))

    # 4.7 IDOR: no ownership check — any authenticated user can delete any ticket
    conn.execute("DELETE FROM tickets WHERE id=?", (ticket_id,))
    conn.commit()
    record_event(uid, "DELETE_TICKET", "tickets", str(ticket_id))
    conn.close()
    return redirect(url_for("tickets"))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
