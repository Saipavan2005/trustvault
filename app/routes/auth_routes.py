from flask import Blueprint, current_app, g, make_response, redirect, render_template, request, url_for
from itsdangerous import BadSignature, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

from .. import auth, db
from ..audit import audit

bp = Blueprint("auth", __name__)
DUMMY_HASH = generate_password_hash("not-a-real-password")   # equalise timing for unknown emails


def _login_token():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="login-csrf").dumps("x")


def _login_token_ok(tok):
    try:
        URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="login-csrf").loads(tok, max_age=900)
        return True
    except BadSignature:
        return False


@bp.get("/login")
def login_form():
    if g.user:
        return redirect(url_for("docs.list_docs"))
    return render_template("login.html", token=_login_token(), error=None)


@bp.post("/login")
def login_submit():
    cfg = current_app.config
    if not _login_token_ok(request.form.get("login_token", "")):
        return render_template("login.html", token=_login_token(), error="Reload the page and try again."), 400
    email = request.form.get("email", "").strip().lower()[:254]
    password = request.form.get("password", "")[:200]
    u = db.one("SELECT * FROM users WHERE email = %s", (email,))
    locked = bool(u and db.one("SELECT 1 AS x FROM users WHERE id=%s AND locked_until > now()", (u["id"],)))
    good = check_password_hash(u["password_hash"] if u else DUMMY_HASH, password)
    if not (u and good and u["active"] and not locked):
        if u:
            db.run("""UPDATE users SET failed_logins = failed_logins + 1,
                         locked_until = CASE WHEN failed_logins + 1 >= %s
                                        THEN now() + make_interval(mins => %s) ELSE locked_until END
                       WHERE id = %s""", (cfg["MAX_FAILED_LOGINS"], cfg["LOCKOUT_MINUTES"], u["id"]))
            db.conn().commit()
        audit("login", "denied", actor=None, email=email,
              reason="locked" if locked else ("disabled" if u and not u["active"] else "bad_credentials"))
        return render_template("login.html", token=_login_token(),
                               error="Email or password is wrong, or the account is locked."), 401
    db.run("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = %s", (u["id"],))
    old = request.cookies.get(auth.COOKIE)
    if old:                                                  # new session id on every login
        db.run("DELETE FROM sessions WHERE id = %s", (auth.token_hash(old),))
    tok = auth.create_session(u["id"])
    audit("login", "allowed", actor={"id": u["id"], "email": u["email"]})
    resp = redirect(url_for("docs.list_docs"))
    resp.set_cookie(auth.COOKIE, tok, httponly=True, secure=cfg["COOKIE_SECURE"], samesite="Lax",
                    max_age=cfg["SESSION_MAX_HOURS"] * 3600)
    return resp


@bp.post("/logout")
def logout():
    db.run("DELETE FROM sessions WHERE id = %s", (g.session["id"],))
    audit("logout", "allowed", actor=g.user)
    resp = make_response(redirect(url_for("auth.login_form")))
    resp.delete_cookie(auth.COOKIE)
    return resp


@bp.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "owner").strip()

        if not email or "@" not in email:
            error = "Please provide a valid email address."
        elif not password or len(password) < 6:
            error = "Password must be at least 6 characters."
        else:
            existing = db.one("SELECT id FROM users WHERE email = %s", (email,))
            if existing:
                error = "An account with that email already exists."
            else:
                from werkzeug.security import generate_password_hash
                import uuid
                pw_hash = generate_password_hash(password)
                user_id = str(uuid.uuid4())
                try:
                    db.execute(
                        "INSERT INTO users (id, email, password_hash, role, active) VALUES (%s, %s, %s, %s, true)",
                        (user_id, email, pw_hash, role)
                    )
                    success = "Account created successfully! You can now sign in."
                except Exception:
                    try:
                        db.execute(
                            "INSERT INTO users (email, password_hash, role) VALUES (%s, %s, %s)",
                            (email, pw_hash, role)
                        )
                        success = "Account created successfully! You can now sign in."
                    except Exception as err:
                        error = f"Registration error: {str(err)}"

    return render_template("login.html", register_mode=True, error=error, success=success)
