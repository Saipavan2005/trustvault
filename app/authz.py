"""THE authorisation gate. Every route that touches a document calls authorize() and nothing else
decides access. The server checks the database on every request: no caching, no signed links."""
import uuid

from flask import abort

from . import db
from .audit import audit

LEVEL = {"read": 1, "edit": 2}          # grant permission -> level. Owner is level 3.
NEEDS = {"view": 1, "download": 1, "edit": 2, "delete": 3, "share": 3}


def authorize(user, doc_id, action):
    """Return the document row if `user` may perform `action`; otherwise audit the refusal and 404.
    404 (not 403) so nobody can probe which document ids exist. Admin has NO implicit access."""
    try:
        did = uuid.UUID(str(doc_id))
    except ValueError:
        did = None
    row, level = None, 0
    if did:
        row = db.one(
            """SELECT d.*, g.permission
                 FROM documents d
                 LEFT JOIN grants g ON g.document_id = d.id AND g.user_id = %s AND g.revoked_at IS NULL
                WHERE d.id = %s AND d.deleted_at IS NULL""",
            (user["id"], str(did)),
        )
        if row:
            if row["owner_id"] == user["id"]:
                level = 3
            elif row["permission"]:
                level = LEVEL[row["permission"]]
    ok = level >= NEEDS[action]
    audit(action, "allowed" if ok else "denied", actor=user, document_id=did,
          reason=None if ok else ("not_found" if not row else "no_access"))
    if not ok:
        abort(404)
    row["level"] = level
    return row
