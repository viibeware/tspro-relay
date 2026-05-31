# SPDX-License-Identifier: AGPL-3.0-or-later
"""TS Pro Relay — outbound email relay for Trusted Servants Pro (with admin UI).

A small Flask app that lets the main TSP portal send mail on hosts that
block outbound SMTP ports (25/465/587) — e.g. DigitalOcean. The portal
POSTs each message as JSON to ``/api/send`` over HTTPS (Bearer-auth);
the relay, running somewhere with SMTP egress, delivers it.

This module serves BOTH:
  * the JSON send API (``/api/send``, Bearer-authenticated) + ``/healthz``
  * a session-authenticated admin UI so an operator can configure the
    SMTP server, manage the shared API key, and watch a live transaction
    log — without ever editing env vars or JSON by hand.

All configuration + the transaction log live in a SQLite DB on the
``/data`` volume. SMTP password and API key are encrypted at rest with
Fernet (key derived from ``RELAY_SECRET_KEY``).
"""
import base64
import functools
import hashlib
import hmac
import logging
import os
import secrets
import smtplib
import sqlite3
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr, parseaddr

from cryptography.fernet import Fernet, InvalidToken
from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

logging.basicConfig(
    level=os.environ.get("RELAY_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("tsp-relay")

__version__ = "0.1.1"

DATA_DIR = os.environ.get("RELAY_DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "relay.db")
SECURITY_CHOICES = ("none", "starttls", "ssl")
LOG_KEEP = 2000          # rows retained; older transactions are pruned
LOG_PAGE = 200           # rows shown on the log page

app = Flask(__name__)


# --------------------------------------------------------------------------
# Secrets / crypto
# --------------------------------------------------------------------------
def _seed():
    return (os.environ.get("RELAY_SECRET_KEY", "").strip() or "dev-insecure-change-me")


app.secret_key = hashlib.sha256((_seed() + "|session").encode()).hexdigest()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # HTTPS is expected in production (behind a reverse proxy). Allow plain
    # HTTP only when explicitly opted in for local testing.
    SESSION_COOKIE_SECURE=os.environ.get("RELAY_INSECURE_COOKIES", "").lower()
    not in ("1", "true", "yes"),
    MAX_CONTENT_LENGTH=64 * 1024 * 1024,
)


def _fernet():
    key = base64.urlsafe_b64encode(hashlib.sha256(_seed().encode()).digest())
    return Fernet(key)


def encrypt(value):
    if not value:
        return None
    return _fernet().encrypt(value.encode()).decode()


def decrypt(token):
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except (InvalidToken, ValueError, TypeError):
        log.warning("decrypt failed — RELAY_SECRET_KEY may have changed; "
                    "re-enter the affected value")
        return ""


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        os.makedirs(DATA_DIR, exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


@app.teardown_appcontext
def _close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            smtp_host TEXT, smtp_port INTEGER,
            smtp_security TEXT NOT NULL DEFAULT 'starttls',
            smtp_username TEXT, smtp_password_enc TEXT,
            default_from TEXT, from_name TEXT,
            allowed_from TEXT,
            max_attach_mb INTEGER NOT NULL DEFAULT 25,
            api_key_enc TEXT,
            turnstile_enabled INTEGER NOT NULL DEFAULT 0,
            turnstile_site_key TEXT,
            turnstile_secret_enc TEXT
        );
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            username TEXT NOT NULL, password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS txn_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            status TEXT NOT NULL,
            from_email TEXT, to_csv TEXT, subject TEXT,
            recipients INTEGER NOT NULL DEFAULT 0,
            attachments INTEGER NOT NULL DEFAULT 0,
            error TEXT, source_ip TEXT
        );
        """
    )
    # Additive migration for DBs created before a column existed (the
    # /data volume persists across upgrades, so CREATE TABLE IF NOT
    # EXISTS won't backfill new columns). Mirrors the main app's
    # PRAGMA-driven ALTER TABLE pattern.
    have = {r[1] for r in con.execute("PRAGMA table_info(settings)")}
    for col, ddl in (
        ("turnstile_enabled", "INTEGER NOT NULL DEFAULT 0"),
        ("turnstile_site_key", "TEXT"),
        ("turnstile_secret_enc", "TEXT"),
    ):
        if col not in have:
            try:
                con.execute(f"ALTER TABLE settings ADD COLUMN {col} {ddl}")
            except sqlite3.OperationalError as e:
                # init_db() runs at import time in every gunicorn worker,
                # so two workers can race on the same ALTER. The loser
                # sees "duplicate column name" — tolerate it.
                if "duplicate column name" not in str(e).lower():
                    raise
    # Seed the settings singleton.
    if not con.execute("SELECT 1 FROM settings WHERE id=1").fetchone():
        con.execute(
            "INSERT INTO settings (id, smtp_port, smtp_security, max_attach_mb, api_key_enc) "
            "VALUES (1, ?, ?, ?, ?)",
            (587, "starttls", 25,
             _fernet().encrypt(secrets.token_urlsafe(36).encode()).decode()),
        )
    # Seed the admin from env (first boot only).
    if not con.execute("SELECT 1 FROM admin WHERE id=1").fetchone():
        user = (os.environ.get("RELAY_ADMIN_USER", "").strip() or "admin")
        pw = (os.environ.get("RELAY_ADMIN_PASSWORD", "").strip() or "admin")
        if pw == "admin":
            log.warning("seeding admin/admin — set RELAY_ADMIN_PASSWORD and "
                        "change it from the UI immediately")
        con.execute("INSERT INTO admin (id, username, password_hash) VALUES (1, ?, ?)",
                    (user, generate_password_hash(pw)))
    con.commit()
    con.close()


def get_settings():
    return get_db().execute("SELECT * FROM settings WHERE id=1").fetchone()


def get_admin():
    return get_db().execute("SELECT * FROM admin WHERE id=1").fetchone()


def add_log(status, from_email="", to_csv="", subject="", recipients=0,
            attachments=0, error="", source_ip=""):
    db = get_db()
    db.execute(
        "INSERT INTO txn_log (ts, status, from_email, to_csv, subject, "
        "recipients, attachments, error, source_ip) VALUES (?,?,?,?,?,?,?,?,?)",
        (datetime.now(timezone.utc).isoformat(timespec="seconds"), status,
         from_email, to_csv, subject, recipients, attachments, error, source_ip),
    )
    # Prune so the table can't grow unbounded.
    db.execute(
        "DELETE FROM txn_log WHERE id NOT IN "
        "(SELECT id FROM txn_log ORDER BY id DESC LIMIT ?)", (LOG_KEEP,))
    db.commit()


# --------------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------------
def login_required(view):
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if not session.get("uid"):
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped


def csrf_token():
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf"] = tok
    return tok


def check_csrf():
    sent = request.form.get("csrf_token", "")
    if not sent or not hmac.compare_digest(sent, session.get("csrf", "")):
        abort(400, "CSRF token invalid")


def static_url(filename):
    """Like url_for('static', ...) but appends a cache-busting ``?v=``
    derived from the file's modification time. When a CSS/JS/image file
    changes, its mtime changes, the URL changes, and the browser fetches
    the new copy — so edits show up on a normal refresh without a hard
    reload. Falls back to the plain URL if the file can't be stat'd, so a
    missing/renamed asset never 500s the page."""
    url = url_for("static", filename=filename)
    try:
        ver = int(os.path.getmtime(os.path.join(app.static_folder, filename)))
        return f"{url}?v={ver}"
    except OSError:
        return url


@app.context_processor
def _inject():
    return {"csrf_token": csrf_token, "client_ip": _client_ip,
            "static_url": static_url, "app_version": __version__}


def _client_ip():
    # Honour a single reverse-proxy hop (the expected production topology).
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "?"


def turnstile_active(s):
    """True when the login challenge is fully configured + enabled."""
    return bool(s and s["turnstile_enabled"] and s["turnstile_site_key"]
                and s["turnstile_secret_enc"])


def verify_turnstile(s, token):
    """Validate a Cloudflare Turnstile token against the siteverify API.

    Uses only the stdlib (urllib) so the relay keeps a tiny dependency
    footprint. Returns True on success. Fails closed on any error
    (network, malformed response) so a broken challenge can't be used
    to bypass the gate — except that callers only invoke this when the
    challenge is active in the first place."""
    import json
    import urllib.parse
    import urllib.request
    if not token:
        return False
    secret = decrypt(s["turnstile_secret_enc"])
    if not secret:
        return False
    data = urllib.parse.urlencode({
        "secret": secret,
        "response": token,
        "remoteip": _client_ip(),
    }).encode()
    try:
        req = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify", data=data)
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode())
        return bool(body.get("success"))
    except Exception as e:  # noqa: BLE001
        log.warning("turnstile verify failed: %s", e)
        return False


# --------------------------------------------------------------------------
# Send core (shared by /api/send and the UI "send test")
# --------------------------------------------------------------------------
def _from_allowed(from_email, allowed_csv):
    allowed = [a.strip().lower() for a in (allowed_csv or "").split(",") if a.strip()]
    if not allowed:
        return True
    addr = (parseaddr(from_email)[1] or "").lower()
    if not addr:
        return False
    return addr in allowed or addr.rsplit("@", 1)[-1] in allowed


def _recipients(value):
    items = value if isinstance(value, list) else str(value or "").replace(";", ",").split(",")
    return [r.strip() for r in items if r and r.strip()]


def deliver(s, payload):
    """Deliver one message described by ``payload`` using settings row ``s``.

    Returns (ok: bool, error: str|None, meta: dict). ``meta`` carries the
    resolved from/to/subject/counts for logging."""
    from_email = (payload.get("from_email") or s["default_from"] or "").strip()
    from_name = payload.get("from_name") or s["from_name"] or ""
    recipients = _recipients(payload.get("to"))
    subject = payload.get("subject") or ""
    meta = {"from_email": from_email, "to_csv": ", ".join(recipients),
            "subject": subject, "recipients": len(recipients), "attachments": 0}

    if not s["smtp_host"]:
        return False, "Relay SMTP host is not configured", meta
    if not from_email:
        return False, "from_email is required", meta
    if not _from_allowed(from_email, s["allowed_from"]):
        return False, "from_email is not permitted by this relay", meta
    if not recipients:
        return False, "At least one recipient is required", meta

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((from_name, from_email))
    msg["To"] = ", ".join(recipients)
    reply_to = (payload.get("reply_to") or "").strip()
    if reply_to:
        msg["Reply-To"] = formataddr((payload.get("reply_to_name") or "", reply_to))
    msg.set_content(payload.get("text") or "")
    if payload.get("html"):
        msg.add_alternative(payload["html"], subtype="html")

    max_bytes = int(s["max_attach_mb"] or 25) * 1024 * 1024
    total = 0
    for att in (payload.get("attachments") or []):
        if not isinstance(att, dict) or not att.get("content_b64"):
            continue
        try:
            blob = base64.b64decode(att["content_b64"])
        except (ValueError, TypeError):
            return False, "An attachment was not valid base64", meta
        total += len(blob)
        if total > max_bytes:
            return False, "Attachments exceed the relay size limit", meta
        mime = att.get("mime_type") or "application/octet-stream"
        if "/" not in mime:
            mime = "application/octet-stream"
        maintype, _, subtype = mime.partition("/")
        msg.add_attachment(blob, maintype=maintype, subtype=subtype or "octet-stream",
                           filename=att.get("filename") or "attachment")
        meta["attachments"] += 1

    host = s["smtp_host"]
    security = (s["smtp_security"] or "starttls").lower()
    port = int(s["smtp_port"] or (465 if security == "ssl" else 587))
    username = s["smtp_username"]
    password = decrypt(s["smtp_password_enc"])
    try:
        if security == "ssl":
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, timeout=30, context=ctx) as srv:
                if username:
                    srv.login(username, password)
                srv.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=30) as srv:
                srv.ehlo()
                if security == "starttls":
                    srv.starttls(context=ssl.create_default_context())
                    srv.ehlo()
                if username:
                    srv.login(username, password)
                srv.send_message(msg)
    except Exception as e:  # noqa: BLE001
        return False, f"SMTP delivery failed: {e}", meta
    return True, None, meta


# --------------------------------------------------------------------------
# JSON API (consumed by the TSP app)
# --------------------------------------------------------------------------
def _authorized(s):
    api_key = decrypt(s["api_key_enc"])
    if not api_key:
        return False
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return False
    return hmac.compare_digest(auth[7:].strip(), api_key)


@app.get("/healthz")
def healthz():
    s = get_settings()
    return jsonify(ok=True, configured=bool(s and s["smtp_host"] and s["api_key_enc"]),
                   smtp_host_set=bool(s and s["smtp_host"]))


@app.get("/api/health")
def api_health():
    """Authenticated health probe for the TSP app's relay connection
    test. Unlike ``/healthz`` (public, reachability only), this checks
    the Bearer API key — so the portal can confirm the key it holds
    actually matches this relay — and reports whether the relay's own
    SMTP delivery is configured (``configured``). Sends no mail."""
    s = get_settings()
    if not _authorized(s):
        return jsonify(ok=False, error="Unauthorized"), 401
    return jsonify(ok=True,
                   configured=bool(s and s["smtp_host"]),
                   smtp_host_set=bool(s and s["smtp_host"]),
                   version=__version__)


@app.post("/api/send")
def api_send():
    s = get_settings()
    if not _authorized(s):
        add_log("unauthorized", error="Bad or missing API key", source_ip=_client_ip())
        return jsonify(ok=False, error="Unauthorized"), 401
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(ok=False, error="Expected a JSON object body"), 400

    ok, err, meta = deliver(s, data)
    add_log("sent" if ok else "failed", from_email=meta["from_email"],
            to_csv=meta["to_csv"], subject=meta["subject"],
            recipients=meta["recipients"], attachments=meta["attachments"],
            error=err or "", source_ip=_client_ip())
    if ok:
        log.info("relayed to %d recipient(s) from %s", meta["recipients"], meta["from_email"])
        return jsonify(ok=True)
    code = 403 if "not permitted" in (err or "") else (
        413 if "size limit" in (err or "") else (
            500 if "not configured" in (err or "") else (
                400 if "required" in (err or "") or "base64" in (err or "") else 502)))
    return jsonify(ok=False, error=err), code


# --------------------------------------------------------------------------
# Admin UI
# --------------------------------------------------------------------------
@app.get("/")
def index():
    return redirect(url_for("logs" if session.get("uid") else "login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    s = get_settings()
    if request.method == "POST":
        check_csrf()
        if turnstile_active(s) and not verify_turnstile(
                s, request.form.get("cf-turnstile-response", "")):
            flash("Bot challenge failed — please try again.", "danger")
            return render_template("login.html", turnstile=turnstile_active(s),
                                   turnstile_site_key=s["turnstile_site_key"])
        a = get_admin()
        u = (request.form.get("username") or "").strip()
        p = request.form.get("password") or ""
        if a and u == a["username"] and check_password_hash(a["password_hash"], p):
            session.clear()
            session["uid"] = 1
            csrf_token()
            nxt = request.args.get("next") or url_for("logs")
            if not nxt.startswith("/"):
                nxt = url_for("logs")
            return redirect(nxt)
        flash("Incorrect username or password.", "danger")
    return render_template("login.html", turnstile=turnstile_active(s),
                           turnstile_site_key=s["turnstile_site_key"] if s else None)


@app.post("/logout")
def logout():
    check_csrf()
    session.clear()
    return redirect(url_for("login"))


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    db = get_db()
    s = get_settings()
    if request.method == "POST":
        check_csrf()
        action = request.form.get("action", "smtp")

        if action == "smtp":
            try:
                port = int((request.form.get("smtp_port") or "").strip() or 0) or None
            except ValueError:
                flash("Port must be a number.", "danger")
                return redirect(url_for("settings"))
            sec = (request.form.get("smtp_security") or "starttls").strip()
            sec = sec if sec in SECURITY_CHOICES else "starttls"
            try:
                max_mb = max(1, int((request.form.get("max_attach_mb") or "25").strip()))
            except ValueError:
                max_mb = 25
            fields = {
                "smtp_host": (request.form.get("smtp_host") or "").strip() or None,
                "smtp_port": port,
                "smtp_security": sec,
                "smtp_username": (request.form.get("smtp_username") or "").strip() or None,
                "default_from": (request.form.get("default_from") or "").strip() or None,
                "from_name": (request.form.get("from_name") or "").strip() or None,
                "allowed_from": (request.form.get("allowed_from") or "").strip() or None,
                "max_attach_mb": max_mb,
            }
            db.execute(
                "UPDATE settings SET smtp_host=:smtp_host, smtp_port=:smtp_port, "
                "smtp_security=:smtp_security, smtp_username=:smtp_username, "
                "default_from=:default_from, from_name=:from_name, "
                "allowed_from=:allowed_from, max_attach_mb=:max_attach_mb WHERE id=1", fields)
            new_pw = request.form.get("smtp_password") or ""
            if request.form.get("smtp_password_clear") == "1":
                db.execute("UPDATE settings SET smtp_password_enc=NULL WHERE id=1")
            elif new_pw:
                db.execute("UPDATE settings SET smtp_password_enc=? WHERE id=1", (encrypt(new_pw),))
            db.commit()
            flash("SMTP settings saved.", "success")

        elif action == "regen_key":
            db.execute("UPDATE settings SET api_key_enc=? WHERE id=1",
                       (encrypt(secrets.token_urlsafe(36)),))
            db.commit()
            flash("A new API key was generated. Update it in the TSP app.", "success")

        elif action == "password":
            a = get_admin()
            cur = request.form.get("current_password") or ""
            new = request.form.get("new_password") or ""
            conf = request.form.get("confirm_password") or ""
            if not check_password_hash(a["password_hash"], cur):
                flash("Current password is incorrect.", "danger")
            elif len(new) < 8:
                flash("New password must be at least 8 characters.", "danger")
            elif new != conf:
                flash("New passwords do not match.", "danger")
            else:
                db.execute("UPDATE admin SET password_hash=? WHERE id=1",
                           (generate_password_hash(new),))
                new_user = (request.form.get("username") or "").strip()
                if new_user:
                    db.execute("UPDATE admin SET username=? WHERE id=1", (new_user,))
                db.commit()
                flash("Admin credentials updated.", "success")

        elif action == "turnstile":
            site_key = (request.form.get("turnstile_site_key") or "").strip() or None
            db.execute("UPDATE settings SET turnstile_site_key=? WHERE id=1", (site_key,))
            new_secret = request.form.get("turnstile_secret") or ""
            if request.form.get("turnstile_secret_clear") == "1":
                db.execute("UPDATE settings SET turnstile_secret_enc=NULL WHERE id=1")
            elif new_secret.strip():
                db.execute("UPDATE settings SET turnstile_secret_enc=? WHERE id=1",
                           (encrypt(new_secret.strip()),))
            # Re-read so "enabled" can only stick when both keys are present.
            row = get_settings()
            wants = request.form.get("turnstile_enabled") == "1"
            enabled = 1 if (wants and row["turnstile_site_key"]
                            and row["turnstile_secret_enc"]) else 0
            db.execute("UPDATE settings SET turnstile_enabled=? WHERE id=1", (enabled,))
            db.commit()
            if wants and not enabled:
                flash("Enter both the site key and secret key to enable the challenge.",
                      "danger")
            else:
                flash("Login bot protection saved.", "success")

        elif action == "test":
            to = (request.form.get("test_to") or "").strip()
            if not to:
                flash("Enter a recipient for the test email.", "danger")
            else:
                ok, err, meta = deliver(s, {
                    "to": [to],
                    "subject": "Trusted Servants Pro relay — test email",
                    "text": "This is a test message from your TSP email relay. "
                            "If you received it, the relay is configured correctly.",
                })
                add_log("sent" if ok else "failed", from_email=meta["from_email"],
                        to_csv=meta["to_csv"], subject=meta["subject"],
                        recipients=meta["recipients"], error=err or "",
                        source_ip="(relay UI test)")
                flash(f"Test email sent to {to}." if ok else f"Test failed: {err}",
                      "success" if ok else "danger")
        return redirect(url_for("settings"))

    return render_template("settings.html", s=s, api_key=decrypt(s["api_key_enc"]),
                           admin=get_admin(), security_choices=SECURITY_CHOICES)


@app.get("/logs")
@login_required
def logs():
    rows = get_db().execute(
        "SELECT * FROM txn_log ORDER BY id DESC LIMIT ?", (LOG_PAGE,)).fetchall()
    stats = get_db().execute(
        "SELECT "
        " COUNT(*) AS total, "
        " SUM(status='sent') AS sent, "
        " SUM(status='failed') AS failed, "
        " SUM(status='unauthorized') AS unauthorized "
        "FROM txn_log").fetchone()
    return render_template("logs.html", rows=rows, stats=stats, shown=len(rows),
                           page_size=LOG_PAGE)


@app.post("/logs/clear")
@login_required
def logs_clear():
    check_csrf()
    get_db().execute("DELETE FROM txn_log")
    get_db().commit()
    flash("Transaction log cleared.", "success")
    return redirect(url_for("logs"))


# Initialise the database at import time so it's ready under gunicorn.
init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
