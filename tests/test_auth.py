import re

from app import db


def test_every_route_requires_login_or_is_allowlisted(app):
    from app.auth import PUBLIC
    c = app.test_client()
    for rule in app.url_map.iter_rules():
        if rule.endpoint in PUBLIC:
            continue
        url = re.sub(r"<[^>]+>", "1", rule.rule)
        for m in rule.methods - {"HEAD", "OPTIONS"}:
            r = c.open(url, method=m, base_url="https://localhost")
            assert r.status_code == 302 and "/login" in r.headers["Location"], (rule.rule, m)


def test_public_allowlist_is_exactly_login_health_static(app):
    from app.auth import PUBLIC
    assert PUBLIC == {"auth.login_form", "auth.login_submit", "healthz", "static"}


def test_post_without_csrf_token_is_rejected(alice, doc):
    assert alice.post(f"/documents/{doc}/delete", csrf=False).status_code == 400
    assert alice.get(f"/documents/{doc}/download").status_code == 200       # not deleted


def test_logout_kills_the_session(alice):
    assert alice.get("/documents").status_code == 200
    alice.post("/logout")
    assert alice.get("/documents").status_code == 302


def test_disabled_user_session_dies_immediately(app, bob, admin):
    assert bob.get("/documents").status_code == 200
    assert admin.post(f"/admin/users/{bob.id}/disable").status_code == 302
    assert bob.get("/documents").status_code == 302
    assert bob.login().status_code == 401


def test_session_cookie_flags(app, alice):
    r = alice.c.get("/login", base_url=alice.base)
    page = r.get_data(as_text=True)
    resp = app.test_client().post("/login", base_url="https://localhost", data={
        "login_token": re.search(r'name="login_token" value="([^"]+)"', page).group(1),
        "email": alice.email, "password": alice.password})
    cookie = resp.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=Lax" in cookie


def test_lockout_after_repeated_failures(app, alice):
    from tests.conftest import Client
    bad = Client(app, alice.email, "wrong-password")
    for _ in range(5):
        assert bad.login().status_code == 401
    assert alice.login().status_code == 401          # correct password, but the account is locked
    with app.app_context():
        db.run("UPDATE users SET locked_until=NULL, failed_logins=0 WHERE id=%s", (alice.id,))
        db.conn().commit()


def test_login_without_valid_token_is_refused(app):
    r = app.test_client().post("/login", base_url="https://localhost",
                               data={"login_token": "forged", "email": "a@b.c", "password": "x"})
    assert r.status_code == 400


def test_security_headers(alice):
    r = alice.get("/documents")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["Cache-Control"] == "no-store"
