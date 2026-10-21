import hashlib
import uuid
from datetime import date
from urllib.parse import quote

from flask import Blueprint, Response, abort, g, redirect, render_template, request, url_for

from .. import db
from ..audit import audit
from ..auth import roles_required
from ..authz import authorize
from ..storage import get_store
from ..validation import clean_name, clean_text, validate_upload

bp = Blueprint("docs", __name__)


def _like(s):
    return "%" + s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _date(s):
    try:
        return date.fromisoformat(s)
    except (ValueError, TypeError):
        return None


@bp.get("/")
def home():
    return redirect(url_for("docs.list_docs"))


@bp.get("/documents")
def list_docs():
    """Search is filtered IN SQL to documents the caller owns or holds an active grant on."""
    a = request.args
    p = {"uid": g.user["id"], "name": _like(a.get("q", "").strip()[:100]),
         "owner": _like(a.get("owner", "").strip()[:100]), "cat": _like(a.get("category", "").strip()[:40]),
         "d1": _date(a.get("from")), "d2": _date(a.get("to"))}
    rows = db.all_(
        """SELECT d.id, d.name, d.category, d.size, d.created_at, o.email AS owner_email,
                  CASE WHEN d.owner_id = %(uid)s THEN 'owner' ELSE gr.permission END AS access,
                  (SELECT count(*) FROM grants x WHERE x.document_id = d.id AND x.revoked_at IS NULL
                      AND d.owner_id = %(uid)s) AS shared_count
             FROM documents d
             JOIN users o ON o.id = d.owner_id
             LEFT JOIN grants gr ON gr.document_id = d.id AND gr.user_id = %(uid)s AND gr.revoked_at IS NULL
            WHERE d.deleted_at IS NULL
              AND (d.owner_id = %(uid)s OR gr.permission IS NOT NULL)
              AND d.name ILIKE %(name)s ESCAPE '\\'
              AND o.email ILIKE %(owner)s ESCAPE '\\'
              AND d.category ILIKE %(cat)s ESCAPE '\\'
              AND (%(d1)s::date IS NULL OR d.created_at::date >= %(d1)s::date)
              AND (%(d2)s::date IS NULL OR d.created_at::date <= %(d2)s::date)
            ORDER BY d.created_at DESC LIMIT 200""", p)
    return render_template("docs.html", docs=rows, q=a)


@bp.post("/documents")
@roles_required("owner")
def upload():
    f = request.files.get("file")
    name = clean_name(f.filename) if f else ""
    data = f.read() if f else b""
    ok, err, ext = validate_upload(name, data) if f else (False, "Choose a file to upload.", None)
    if not ok:
        audit("upload", "denied", actor=g.user, filename=name, reason=err)
        return render_template("error.html", msg=err), 400
    doc_id = uuid.uuid4()
    key = f"docs/{uuid.uuid4()}"                       # random key: the client's name never reaches S3
    get_store().put(key, data)
    sha = hashlib.sha256(data).hexdigest()
    db.run("""INSERT INTO documents(id,owner_id,name,category,s3_key,sha256,size,mime)
              VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
           (str(doc_id), g.user["id"], name, clean_text(request.form.get("category")), key, sha,
            len(data), ext))
    audit("upload", "allowed", actor=g.user, document_id=doc_id, sha256=sha, size=len(data), ext=ext)
    return redirect(url_for("docs.view", doc_id=doc_id))


@bp.get("/documents/<doc_id>")
def view(doc_id):
    doc = authorize(g.user, doc_id, "view")
    grants, suggestions = [], []
    if doc["level"] == 3:
        grants = db.all_(
            """SELECT gr.id, gr.permission, gr.granted_at, u.email FROM grants gr
                 JOIN users u ON u.id = gr.user_id
                WHERE gr.document_id = %s AND gr.revoked_at IS NULL ORDER BY gr.granted_at""", (doc["id"],))
        # Rule-based suggestion: people this owner already shares same-category documents with.
        # It only SUGGESTS. A grant needs an explicit confirmed POST, and both are audited.
        suggestions = db.all_(
            """SELECT DISTINCT u.id, u.email FROM grants gr
                 JOIN documents d2 ON d2.id = gr.document_id
                 JOIN users u ON u.id = gr.user_id
                WHERE d2.owner_id = %(o)s AND d2.category = %(c)s AND d2.id <> %(d)s
                  AND d2.deleted_at IS NULL AND gr.revoked_at IS NULL AND u.active AND u.id <> %(o)s
                  AND NOT EXISTS (SELECT 1 FROM grants x WHERE x.document_id = %(d)s
                                    AND x.user_id = u.id AND x.revoked_at IS NULL)""",
            {"o": doc["owner_id"], "c": doc["category"], "d": doc["id"]}) if doc["category"] else []
        if suggestions:
            audit("suggestion_shown", "allowed", actor=g.user, document_id=doc["id"],
                  suggested=[s["email"] for s in suggestions], source="same-category sharing history")
    owner = db.one("SELECT email FROM users WHERE id = %s", (doc["owner_id"],))
    return render_template("doc.html", doc=doc, grants=grants, suggestions=suggestions, owner=owner["email"])


@bp.get("/documents/<doc_id>/download")
def download(doc_id):
    doc = authorize(g.user, doc_id, "download")        # audited BEFORE any byte leaves
    resp = Response(get_store().stream(doc["s3_key"]), mimetype="application/octet-stream")
    resp.headers["Content-Disposition"] = "attachment; filename*=UTF-8''" + quote(doc["name"])
    resp.headers["Content-Length"] = str(doc["size"])
    return resp


@bp.post("/documents/<doc_id>/edit")
def edit(doc_id):
    doc = authorize(g.user, doc_id, "edit")
    changes, sets, args = {}, [], []
    name, cat = clean_name(request.form.get("name") or doc["name"]), clean_text(request.form.get("category"))
    if name != doc["name"]:
        sets.append("name=%s"); args.append(name); changes["name"] = [doc["name"], name]
    if cat != doc["category"]:
        sets.append("category=%s"); args.append(cat); changes["category"] = [doc["category"], cat]
    f = request.files.get("file")
    if f and f.filename:
        data = f.read()
        ok, err, ext = validate_upload(f.filename, data)
        if not ok:
            audit("edit_file", "denied", actor=g.user, document_id=doc["id"], reason=err)
            return render_template("error.html", msg=err), 400
        key, sha = f"docs/{uuid.uuid4()}", hashlib.sha256(data).hexdigest()
        get_store().put(key, data)
        sets += ["s3_key=%s", "sha256=%s", "size=%s", "mime=%s"]
        args += [key, sha, len(data), ext]
        changes["file"] = [doc["sha256"], sha]
    if sets:
        db.run(f"UPDATE documents SET {', '.join(sets)}, updated_at=now() WHERE id=%s", (*args, str(doc["id"])))
    audit("edit_applied", "allowed", actor=g.user, document_id=doc["id"], changes=changes)
    return redirect(url_for("docs.view", doc_id=doc["id"]))


@bp.post("/documents/<doc_id>/delete")
def delete(doc_id):
    doc = authorize(g.user, doc_id, "delete")
    db.run("UPDATE documents SET deleted_at = now() WHERE id = %s", (str(doc["id"]),))
    audit("delete_applied", "allowed", actor=g.user, document_id=doc["id"], sha256=doc["sha256"])
    return redirect(url_for("docs.list_docs"))


@bp.post("/documents/<doc_id>/grants")
def grant(doc_id):
    doc = authorize(g.user, doc_id, "share")
    email = request.form.get("email", "").strip().lower()[:254]
    perm = request.form.get("permission", "")
    target = db.one("SELECT id, email FROM users WHERE email = %s AND active", (email,))
    if perm not in ("read", "edit") or not target or target["id"] == g.user["id"]:
        audit("grant", "denied", actor=g.user, document_id=doc["id"], reason="invalid_target_or_permission")
        return render_template("error.html", msg="Choose an active user other than yourself, and read or edit."), 400
    db.run("""UPDATE grants SET revoked_at = now(), revoked_by = %s
               WHERE document_id = %s AND user_id = %s AND revoked_at IS NULL""",
           (g.user["id"], str(doc["id"]), target["id"]))
    db.run("INSERT INTO grants(document_id,user_id,permission,granted_by) VALUES (%s,%s,%s,%s)",
           (str(doc["id"]), target["id"], perm, g.user["id"]))
    audit("grant", "allowed", actor=g.user, document_id=doc["id"], target_user_id=target["id"],
          permission=perm, target_email=target["email"],
          from_suggestion=request.form.get("suggested") == "1", confirmed_by_owner=True)
    return redirect(url_for("docs.view", doc_id=doc["id"]))


@bp.post("/documents/<doc_id>/grants/<int:grant_id>/revoke")
def revoke(doc_id, grant_id):
    doc = authorize(g.user, doc_id, "share")
    row = db.one("""UPDATE grants SET revoked_at = now(), revoked_by = %s
                     WHERE id = %s AND document_id = %s AND revoked_at IS NULL RETURNING user_id""",
                 (g.user["id"], grant_id, str(doc["id"])))   # bound to THIS document: no cross-document revoke
    if not row:
        abort(404)
    audit("revoke", "allowed", actor=g.user, document_id=doc["id"], target_user_id=row["user_id"])
    return redirect(url_for("docs.view", doc_id=doc["id"]))
