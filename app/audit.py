"""Hash-chained, append-only audit trail.

Each row stores hash = SHA256(prev_hash | canonical JSON of the record). Rows are written on their OWN
connection and committed immediately, so a refused request (which aborts with 404) still leaves its
record. If the audit write fails the request fails (fail closed).
"""
import hashlib
import json
from datetime import datetime, timezone

import psycopg
from flask import current_app, has_request_context, request

GENESIS = "GENESIS"
LOCK_KEY = 424242


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def chain_hash(prev, rec):
    return hashlib.sha256((prev + "|" + canonical(rec)).encode()).hexdigest()


def record_of(row):
    """The exact fields that are hashed, from a DB row (dict)."""
    return {
        "ts": row["ts"], "actor_id": row["actor_id"], "actor_email": row["actor_email"],
        "action": row["action"],
        "document_id": str(row["document_id"]) if row["document_id"] else None,
        "target_user_id": row["target_user_id"], "outcome": row["outcome"], "ip": row["ip"],
        "detail": row["detail"],
    }


def audit(action, outcome, actor=None, document_id=None, target_user_id=None, **detail):
    rec = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "actor_id": actor["id"] if actor else None,
        "actor_email": actor["email"] if actor else None,
        "action": action,
        "document_id": str(document_id) if document_id else None,
        "target_user_id": target_user_id,
        "outcome": outcome,
        "ip": request.remote_addr if has_request_context() else None,
        "detail": canonical(detail),
    }
    with psycopg.connect(current_app.config["DATABASE_URL"]) as c:   # commits on exit
        c.execute("SELECT pg_advisory_xact_lock(%s)", (LOCK_KEY,))   # serialise the chain
        row = c.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev = row[0] if row else GENESIS
        h = chain_hash(prev, rec)
        c.execute(
            """INSERT INTO audit_log(ts,actor_id,actor_email,action,document_id,target_user_id,
                                     outcome,ip,detail,prev_hash,hash)
               VALUES (%(ts)s,%(actor_id)s,%(actor_email)s,%(action)s,%(document_id)s,
                       %(target_user_id)s,%(outcome)s,%(ip)s,%(detail)s,%(prev)s,%(hash)s)""",
            {**rec, "prev": prev, "hash": h},
        )


def verify_chain(c, anchor_reader=None):
    """Recompute the whole chain on connection `c` (dict_row). Returns a result dict."""
    rows = c.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
    prev, by_id = GENESIS, {}
    for r in rows:
        if r["prev_hash"] != prev or r["hash"] != chain_hash(prev, record_of(r)):
            return {"ok": False, "rows": len(rows), "bad_id": r["id"], "reason": "chain broken", "anchors": 0}
        prev = r["hash"]
        by_id[r["id"]] = r["hash"]
    checked = 0
    if anchor_reader:
        for a in c.execute("SELECT * FROM anchors ORDER BY id").fetchall():
            body = anchor_reader(a["s3_key"])
            if body is None or by_id.get(a["audit_id"]) != body.get("hash"):
                return {"ok": False, "rows": len(rows), "bad_id": a["audit_id"],
                        "reason": "anchor mismatch (rows altered or removed after anchoring)", "anchors": checked}
            checked += 1
    return {"ok": True, "rows": len(rows), "bad_id": None, "reason": "", "anchors": checked}
