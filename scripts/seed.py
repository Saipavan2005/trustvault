"""Create one account per role plus sample documents. Passwords come from env vars or are generated and
printed ONCE. Usage: set -a; . /etc/trustvault.env; set +a; python scripts/seed.py"""
import hashlib
import os
import secrets
import uuid

from app import create_app, db
from app.storage import get_store
from app.users import create_user

ACCOUNTS = [("admin@trustvault.demo", "admin", "SEED_ADMIN_PASSWORD"),
            ("owner@trustvault.demo", "owner", "SEED_OWNER_PASSWORD"),
            ("owner2@trustvault.demo", "owner", "SEED_OWNER2_PASSWORD"),
            ("viewer@trustvault.demo", "viewer", "SEED_VIEWER_PASSWORD")]

app = create_app()
with app.app_context():
    ids = {}
    for email, role, env in ACCOUNTS:
        pw = os.environ.get(env) or secrets.token_urlsafe(12) + "A1"
        if db.one("SELECT 1 AS x FROM users WHERE email=%s", (email,)):
            print(f"exists  {email}")
            ids[email] = db.one("SELECT id FROM users WHERE email=%s", (email,))["id"]
            continue
        u = create_user(email, pw, role)
        ids[email] = u["id"]
        print(f"created {email:28} {role:7} password: {pw}")
    store = get_store()
    for owner, name, cat, body in [
        ("owner@trustvault.demo", "Salary letter - A Rao.txt", "HR", b"Demo salary letter. Fictional data."),
        ("owner@trustvault.demo", "Customer contract - Acme.txt", "Contracts", b"Demo contract. Fictional data."),
        ("owner2@trustvault.demo", "Audit papers Q3.txt", "Audit", b"Demo audit papers. Fictional data.")]:
        if db.one("SELECT 1 AS x FROM documents WHERE name=%s AND owner_id=%s", (name, ids[owner])):
            continue
        key = f"docs/{uuid.uuid4()}"
        store.put(key, body)
        db.run("""INSERT INTO documents(id,owner_id,name,category,s3_key,sha256,size,mime)
                  VALUES (%s,%s,%s,%s,%s,%s,%s,'txt')""",
               (str(uuid.uuid4()), ids[owner], name, cat, key, hashlib.sha256(body).hexdigest(), len(body)))
        print("sample document:", name)
