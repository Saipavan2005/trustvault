import os
import re
import secrets

import psycopg
import pytest

from app import create_app, db
from app.users import create_user

APP_URL = os.environ.get("TEST_DATABASE_URL")
MIG_URL = os.environ.get("TEST_MIGRATOR_URL")
pytestmark = pytest.mark.skipif(not APP_URL, reason="TEST_DATABASE_URL not set")


@pytest.fixture(scope="session")
def app(tmp_path_factory):
    if not APP_URL:
        pytest.skip("TEST_DATABASE_URL not set (see README: Running the tests)")
    return create_app({"DATABASE_URL": APP_URL, "SECRET_KEY": "t" * 40, "STORAGE_BACKEND": "local",
                       "LOCAL_STORAGE_DIR": str(tmp_path_factory.mktemp("store")), "TESTING": True})


class Client:
    """A browser with its own cookie jar that follows the real login + CSRF flow."""
    def __init__(self, app, email, password):
        self.app, self.email, self.password = app, email, password
        self.c = app.test_client()
        self.base = "https://localhost"

    def _tok(self, html, name):
        return re.search(rf'name="{name}" value="([^"]+)"', html).group(1)

    def login(self):
        page = self.c.get("/login", base_url=self.base).get_data(as_text=True)
        return self.c.post("/login", base_url=self.base, data={
            "login_token": self._tok(page, "login_token"), "email": self.email, "password": self.password})

    def csrf(self):
        page = self.c.get("/documents", base_url=self.base).get_data(as_text=True)
        return self._tok(page, "csrf_token")

    def get(self, url, **k):
        return self.c.get(url, base_url=self.base, **k)

    def post(self, url, data=None, csrf=True, **k):
        data = dict(data or {})
        if csrf:
            data["csrf_token"] = self.csrf()
        return self.c.post(url, base_url=self.base, data=data, **k)


def _user(app, role):
    pw = secrets.token_urlsafe(14)
    email = f"{role}-{secrets.token_hex(4)}@test.local"
    with app.app_context():
        u = create_user(email, pw, role)
        db.conn().commit()
    cl = Client(app, email, pw)
    assert cl.login().status_code == 302
    cl.id = u["id"]
    return cl


@pytest.fixture
def alice(app): return _user(app, "owner")      # owns documents
@pytest.fixture
def bob(app): return _user(app, "viewer")       # never granted unless a test grants it
@pytest.fixture
def mallory(app): return _user(app, "owner")    # another owner: must not reach alice's documents
@pytest.fixture
def admin(app): return _user(app, "admin")


PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF"


@pytest.fixture
def upload(app):
    def _up(client, name="plan.pdf", data=PDF, category="HR"):
        import io
        r = client.post("/documents", data={"file": (io.BytesIO(data), name), "category": category},
                        content_type="multipart/form-data")
        assert r.status_code == 302, r.get_data(as_text=True)
        return r.headers["Location"].rsplit("/", 1)[1]
    return _up


@pytest.fixture
def doc(alice, upload): return upload(alice)


@pytest.fixture
def audit_rows(app):
    def _q(**f):
        with psycopg.connect(APP_URL) as c:
            cond = " AND ".join(f"{k} = %s" for k in f) or "TRUE"
            return c.execute(f"SELECT action, outcome, actor_id, document_id::text FROM audit_log WHERE {cond}",
                             tuple(f.values())).fetchall()
    return _q


@pytest.fixture
def migrator():
    if not MIG_URL:
        pytest.skip("TEST_MIGRATOR_URL not set")
    return psycopg.connect(MIG_URL)
