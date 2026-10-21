from flask import Blueprint, g, redirect, render_template, request, url_for

from .. import db
from ..audit import audit, verify_chain
from ..auth import roles_required
from ..storage import get_store
from ..users import ROLES, create_user

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.before_request
@roles_required("admin")        # every /admin route is admin-only, even ones added later
def _admin_only():
    return None


@bp.get("/users")
def users():
    rows = db.all_("SELECT id,email,role,active,locked_until FROM users ORDER BY id")
    return render_template("admin_users.html", rows=rows, roles=ROLES)


@bp.post("/users")
def users_create():
    try:
        u = create_user(request.form.get("email", ""), request.form.get("password", ""),
                        request.form.get("role", ""))
    except Exception as e:
        db.conn().rollback()
        audit("user_create", "denied", actor=g.user, reason=str(e)[:100])
        return render_template("error.html", msg="Could not create the user. Check the email, role and a 12+ character password."), 400
    audit("user_create", "allowed", actor=g.user, target_user_id=u["id"], role=u["role"])
    return redirect(url_for("admin.users"))


@bp.post("/users/<int:uid>/disable")
def users_disable(uid):
    if uid == g.user["id"]:
        return render_template("error.html", msg="You cannot disable your own account."), 400
    db.run("UPDATE users SET active = false WHERE id = %s", (uid,))
    db.run("DELETE FROM sessions WHERE user_id = %s", (uid,))    # live sessions die immediately
    audit("user_disabled", "allowed", actor=g.user, target_user_id=uid)
    return redirect(url_for("admin.users"))


@bp.post("/users/<int:uid>/enable")
def users_enable(uid):
    db.run("UPDATE users SET active = true, failed_logins = 0, locked_until = NULL WHERE id = %s", (uid,))
    audit("user_enabled", "allowed", actor=g.user, target_user_id=uid)
    return redirect(url_for("admin.users"))


def _activity(where, args, title):
    raw = request.args.get("page", "1")
    page = max(int(raw), 1) if raw.isdigit() else 1
    outcome = request.args.get("outcome", "")
    if outcome in ("allowed", "denied"):
        where += " AND outcome = %s"; args = [*args, outcome]
    rows = db.all_(f"SELECT * FROM audit_log WHERE {where} ORDER BY id DESC LIMIT 100 OFFSET %s",
                   (*args, (page - 1) * 100))
    alerts = db.all_("""SELECT actor_email, count(*) AS n FROM audit_log
                         WHERE outcome = 'denied' AND ts::timestamptz > now() - interval '10 minutes'
                           AND actor_email IS NOT NULL
                         GROUP BY actor_email HAVING count(*) >= 5""")
    audit("admin_view", "allowed", actor=g.user, page=title)
    return render_template("admin_activity.html", rows=rows, alerts=alerts, title=title, page=page,
                           outcome=outcome, verify=None)


@bp.get("/activity")
def activity():
    return _activity("TRUE", [], "Activity")


@bp.get("/permissions")
def permissions():
    return _activity("action IN ('grant','revoke','suggestion_shown')", [], "Permission changes")


@bp.get("/documents")
def documents():
    """Metadata only. The admin cannot read content from here or anywhere else."""
    rows = db.all_("""SELECT d.id, d.name, d.category, d.size, d.created_at, d.deleted_at, o.email AS owner_email,
                             (SELECT count(*) FROM grants g WHERE g.document_id = d.id AND g.revoked_at IS NULL) AS grants
                        FROM documents d JOIN users o ON o.id = d.owner_id ORDER BY d.created_at DESC LIMIT 500""")
    return render_template("admin_docs.html", rows=rows)


@bp.post("/verify")
def verify():
    store = get_store()
    res = verify_chain(db.conn(), anchor_reader=store.get_anchor)
    audit("verify_chain", "allowed", actor=g.user, ok=res["ok"], rows=res["rows"], anchors=res["anchors"])
    return render_template("admin_activity.html", rows=[], alerts=[], title="Audit chain check", page=1,
                           outcome="", verify=res)
