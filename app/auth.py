"""Server-side sessions, the global default-deny gate, CSRF, and role checks."""
import hashlib
import hmac
import secrets
from functools import wraps

from flask import abort, current_app, g, redirect, request, url_for

from . import db
from .audit import audit

COOKIE = "tv_session"
SAFE = {"GET", "HEAD", "OPTIONS"}
# The ONLY endpoints reachable without a session. Everything else is denied by default.
PUBLIC = {"auth.login_form", "auth.login_submit", "healthz", "static"}


def token_hash(tok):
    return hashlib.sha256(tok.encode()).hexdigest()


def create_session(user_id):
    tok, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    db.run(
        """INSERT INTO sessions(id,user_id,csrf,expires_at)
           VALUES (%s,%s,%s, now() + make_interval(hours => %s))""",
        (token_hash(tok), user_id, csrf, current_app.config["SESSION_MAX_HOURS"]),
    )
    return tok


def roles_required(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **k):
            if g.user["role"] not in roles:
                audit("role_check", "denied", actor=g.user, path=request.path, needed=list(roles))
                abort(404)
            return f(*a, **k)
        return wrapper
    return deco


def init(app):
    @app.before_request
    def gate():
        g.user = g.session = None
        tok = request.cookies.get(COOKIE)
        if tok:
            row = db.one(
                """SELECT s.id AS sid, s.csrf, u.id, u.email, u.role
                     FROM sessions s JOIN users u ON u.id = s.user_id
                    WHERE s.id = %s AND s.expires_at > now() AND u.active
                      AND s.last_seen > now() - make_interval(mins => %s)""",
                (token_hash(tok), app.config["SESSION_IDLE_MINUTES"]),
            )
            if row:
                g.user = {"id": row["id"], "email": row["email"], "role": row["role"]}
                g.session = {"id": row["sid"], "csrf": row["csrf"]}
                db.run("UPDATE sessions SET last_seen = now() WHERE id = %s", (row["sid"],))
        if request.endpoint in PUBLIC:
            return None
        if g.user is None:
            return redirect(url_for("auth.login_form"))
        if request.method not in SAFE:
            sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(sent, g.session["csrf"]):
                audit("csrf_check", "denied", actor=g.user, path=request.path)
                abort(400)
        return None

    @app.context_processor
    def inject():
        return {"user": g.get("user"), "csrf_token": (g.session or {}).get("csrf", "")}
