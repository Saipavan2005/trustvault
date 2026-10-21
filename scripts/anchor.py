"""Write the current audit chain head to the Object Lock bucket (run hourly by a systemd timer).
Needs only: SELECT on audit_log, INSERT on anchors, s3:PutObject on the anchor bucket."""
import psycopg

from app import create_app
from app.storage import get_store

app = create_app()
with app.app_context(), psycopg.connect(app.config["DATABASE_URL"]) as c:
    head = c.execute("SELECT id, hash, ts FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    if not head:
        raise SystemExit("audit log is empty; nothing to anchor")
    last = c.execute("SELECT audit_id FROM anchors ORDER BY id DESC LIMIT 1").fetchone()
    if last and last[0] == head[0]:
        raise SystemExit("no new audit rows since the last anchor")
    key = f"anchors/{head[0]:012d}.json"
    get_store().put_anchor(key, {"audit_id": head[0], "hash": head[1], "ts": head[2]})
    c.execute("INSERT INTO anchors(audit_id, s3_key) VALUES (%s, %s)", (head[0], key))
    print("anchored", key)
