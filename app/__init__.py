import os

from flask import Flask, render_template
from werkzeug.middleware.proxy_fix import ProxyFix

from . import auth, db


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", ""),
        DATABASE_URL=os.environ.get("DATABASE_URL", ""),
        S3_BUCKET=os.environ.get("S3_BUCKET", ""),
        ANCHOR_BUCKET=os.environ.get("ANCHOR_BUCKET", ""),
        AWS_REGION=os.environ.get("AWS_REGION", "ap-south-1"),
        STORAGE_BACKEND=os.environ.get("STORAGE_BACKEND", "s3"),
        LOCAL_STORAGE_DIR=os.environ.get("LOCAL_STORAGE_DIR", "local_storage"),
        MAX_CONTENT_LENGTH=11 * 1024 * 1024,
        SESSION_IDLE_MINUTES=30,
        SESSION_MAX_HOURS=8,
        COOKIE_SECURE=True,
        MAX_FAILED_LOGINS=5,
        LOCKOUT_MINUTES=15,
    )
    if test_config:
        app.config.update(test_config)
    if len(app.config["SECRET_KEY"]) < 32:
        raise RuntimeError("SECRET_KEY must be set (32+ characters)")
    # nginx overwrites X-Forwarded-For with the real client address; trust exactly one hop.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    app.teardown_appcontext(db.close_db)
    auth.init(app)

    from .routes import admin, auth_routes, docs
    app.register_blueprint(auth_routes.bp)
    app.register_blueprint(docs.bp)
    app.register_blueprint(admin.bp)

    @app.get("/healthz", endpoint="healthz")
    def healthz():
        return "ok"

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self'; style-src 'self'; script-src 'none'; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    for code, msg in ((400, "That request could not be processed."), (404, "Not found."),
                      (405, "Not found."), (413, "That file is too large (10 MB limit)."),
                      (500, "Something went wrong. Nothing was changed.")):
        app.register_error_handler(
            code, lambda e, code=code, msg=msg: (render_template("error.html", msg=msg),
                                                  404 if code == 405 else code))
    return app
