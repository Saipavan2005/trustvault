"""One user must never reach another user's documents: every route, every action."""
import pytest

ROUTES = [  # (method, url template, expected-to-be-refused-for-strangers)
    ("get", "/documents/{d}"), ("get", "/documents/{d}/download"), ("post", "/documents/{d}/edit"),
    ("post", "/documents/{d}/delete"), ("post", "/documents/{d}/grants"),
    ("post", "/documents/{d}/grants/1/revoke"),
]


@pytest.mark.parametrize("method,url", ROUTES)
def test_stranger_is_refused_on_every_document_route(alice, bob, mallory, doc, method, url):
    for stranger in (bob, mallory):
        r = getattr(stranger, method)(url.format(d=doc), **({"data": {"email": "x@y.z", "permission": "read"}} if method == "post" else {}))
        assert r.status_code == 404


def test_denied_attempts_are_in_the_audit_trail(alice, bob, doc, audit_rows):
    bob.get(f"/documents/{doc}/download")
    rows = audit_rows(actor_id=bob.id, action="download", outcome="denied")
    assert rows and rows[0][3] == doc


def test_unknown_and_forbidden_look_identical(alice, bob, doc):
    a = bob.get(f"/documents/{doc}")
    b = bob.get("/documents/00000000-0000-0000-0000-000000000000")
    c = bob.get("/documents/not-a-uuid")
    assert a.status_code == b.status_code == c.status_code == 404
    assert a.get_data() == b.get_data() == c.get_data()


def test_list_and_search_never_leak(alice, bob, doc):
    assert "plan.pdf" not in bob.get("/documents").get_data(as_text=True)
    assert "plan.pdf" not in bob.get("/documents?q=plan&owner=alice&category=HR").get_data(as_text=True)
    assert "plan.pdf" in alice.get("/documents?q=plan").get_data(as_text=True)


def test_search_wildcards_are_literal(alice, upload):
    upload(alice, name="a_b.pdf")
    upload(alice, name="axb.pdf")
    page = alice.get("/documents?q=a_b").get_data(as_text=True)
    assert "a_b.pdf" in page and "axb.pdf" not in page


def test_read_grant_allows_read_only(alice, bob, doc):
    alice.post(f"/documents/{doc}/grants", data={"email": bob.email, "permission": "read"})
    assert bob.get(f"/documents/{doc}/download").status_code == 200
    assert bob.post(f"/documents/{doc}/edit", data={"name": "hacked.pdf"}).status_code == 404
    assert bob.post(f"/documents/{doc}/delete").status_code == 404
    assert bob.post(f"/documents/{doc}/grants", data={"email": bob.email, "permission": "edit"}).status_code == 404


def test_edit_grant_edits_but_cannot_delete_or_share(alice, bob, doc):
    alice.post(f"/documents/{doc}/grants", data={"email": bob.email, "permission": "edit"})
    assert bob.post(f"/documents/{doc}/edit", data={"name": "renamed.pdf", "category": "HR"}).status_code == 302
    assert bob.post(f"/documents/{doc}/delete").status_code == 404
    assert bob.post(f"/documents/{doc}/grants", data={"email": "x@y.z", "permission": "read"}).status_code == 404


def test_revoke_is_immediate(alice, bob, doc):
    alice.post(f"/documents/{doc}/grants", data={"email": bob.email, "permission": "read"})
    assert bob.get(f"/documents/{doc}/download").status_code == 200
    page = alice.get(f"/documents/{doc}").get_data(as_text=True)
    gid = page.split("/grants/")[1].split("/revoke")[0]
    assert alice.post(f"/documents/{doc}/grants/{gid}/revoke").status_code == 302
    assert bob.get(f"/documents/{doc}/download").status_code == 404
    assert "plan.pdf" not in bob.get("/documents").get_data(as_text=True)


def test_revoke_cannot_target_another_documents_grant(alice, bob, mallory, upload, doc):
    other = upload(mallory)
    mallory.post(f"/documents/{other}/grants", data={"email": bob.email, "permission": "read"})
    gid = mallory.get(f"/documents/{other}").get_data(as_text=True).split("/grants/")[1].split("/revoke")[0]
    assert alice.post(f"/documents/{doc}/grants/{gid}/revoke").status_code == 404   # alice owns `doc`, not `other`
    assert bob.get(f"/documents/{other}/download").status_code == 200


def test_admin_cannot_read_content_without_a_grant(alice, admin, doc):
    assert admin.get(f"/documents/{doc}/download").status_code == 404
    assert admin.get(f"/documents/{doc}").status_code == 404
    page = admin.get("/admin/documents").get_data(as_text=True)
    assert "plan.pdf" in page                      # metadata is visible
    assert admin.get(f"/documents/{doc}/download").status_code == 404


def test_deleted_document_is_unreachable_even_by_owner(alice, doc):
    assert alice.post(f"/documents/{doc}/delete").status_code == 302
    assert alice.get(f"/documents/{doc}/download").status_code == 404


def test_viewer_cannot_upload_and_non_admin_cannot_enter_admin(bob, alice):
    import io
    r = bob.post("/documents", data={"file": (io.BytesIO(b"%PDF-1"), "x.pdf")}, content_type="multipart/form-data")
    assert r.status_code == 404
    for u in (alice, bob):
        assert u.get("/admin/users").status_code == 404
        assert u.get("/admin/activity").status_code == 404
        assert u.post("/admin/verify").status_code == 404


def test_grant_requires_explicit_confirmation_and_is_audited(alice, bob, upload, audit_rows):
    d1, d2 = upload(alice, name="a.pdf", category="Legal"), upload(alice, name="b.pdf", category="Legal")
    alice.post(f"/documents/{d1}/grants", data={"email": bob.email, "permission": "read"})
    page = alice.get(f"/documents/{d2}").get_data(as_text=True)
    assert "Suggestion" in page and bob.get(f"/documents/{d2}/download").status_code == 404   # suggested, NOT granted
    assert audit_rows(actor_id=alice.id, action="suggestion_shown")
    alice.post(f"/documents/{d2}/grants", data={"email": bob.email, "permission": "read", "suggested": "1"})
    assert bob.get(f"/documents/{d2}/download").status_code == 200
    assert audit_rows(actor_id=alice.id, action="grant", outcome="allowed")
