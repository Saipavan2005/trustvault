import psycopg
import pytest
from psycopg.rows import dict_row

from app.audit import verify_chain

from tests.conftest import APP_URL


def test_app_role_cannot_update_or_delete_audit_rows(alice, doc):
    with psycopg.connect(APP_URL) as c:
        for sql in ("UPDATE audit_log SET outcome='allowed'", "DELETE FROM audit_log",
                    "TRUNCATE audit_log", "UPDATE anchors SET audit_id=0", "DELETE FROM anchors"):
            with pytest.raises(psycopg.Error):
                c.execute(sql)
            c.rollback()


def test_chain_verifies_after_real_activity(alice, bob, doc):
    bob.get(f"/documents/{doc}/download")
    with psycopg.connect(APP_URL, row_factory=dict_row) as c:
        assert verify_chain(c)["ok"]


def test_tampering_is_detected_even_by_someone_who_bypasses_the_triggers(alice, doc, migrator):
    """Simulates a DB owner who disables the trigger and edits history; rolled back afterwards."""
    with migrator as c:
        c.row_factory = dict_row
        c.execute("ALTER TABLE audit_log DISABLE TRIGGER USER")
        c.execute("UPDATE audit_log SET outcome = CASE outcome WHEN 'allowed' THEN 'denied' ELSE 'allowed' END "
                  "WHERE id = (SELECT max(id) - 1 FROM audit_log)")
        res = verify_chain(c)
        c.rollback()
    assert res["ok"] is False


def test_deleted_tail_is_caught_by_the_external_anchor(alice, doc, migrator):
    with psycopg.connect(APP_URL, row_factory=dict_row) as c:
        head = c.execute("SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    anchors = {"k": {"hash": head["hash"]}}
    with migrator as c:
        c.row_factory = dict_row
        c.execute("ALTER TABLE audit_log DISABLE TRIGGER USER")
        c.execute("INSERT INTO anchors(audit_id,s3_key) VALUES (%s,'k')", (head["id"],))
        c.execute("DELETE FROM audit_log WHERE id = %s", (head["id"],))
        res = verify_chain(c, anchor_reader=lambda k: anchors.get(k))
        c.rollback()
    assert res["ok"] is False and "anchor" in res["reason"]


def test_admin_verify_endpoint_and_activity_views(admin, alice, bob, doc):
    bob.get(f"/documents/{doc}/download")
    assert "Chain intact" in admin.post("/admin/verify").get_data(as_text=True)
    assert "denied" in admin.get("/admin/activity?outcome=denied").get_data(as_text=True)
    alice.post(f"/documents/{doc}/grants", data={"email": bob.email, "permission": "read"})
    assert "grant" in admin.get("/admin/permissions").get_data(as_text=True)
