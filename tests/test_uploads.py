import io
import zipfile

from tests.conftest import PDF


def _try(client, name, data):
    return client.post("/documents", data={"file": (io.BytesIO(data), name)}, content_type="multipart/form-data")


def test_html_renamed_to_pdf_is_rejected(alice):
    assert _try(alice, "evil.pdf", b"<html><script>alert(1)</script></html>").status_code == 400


def test_disallowed_extensions_are_rejected(alice):
    for name in ("a.html", "a.svg", "a.exe", "a.php", "a.pdf.html", "noext"):
        assert _try(alice, name, PDF).status_code == 400, name


def test_fake_docx_is_rejected_and_real_zip_structure_accepted(alice):
    assert _try(alice, "a.docx", b"PK\x03\x04 not really").status_code == 400
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<x/>"); z.writestr("word/document.xml", "<x/>")
    assert _try(alice, "ok.docx", buf.getvalue()).status_code == 302


def test_oversize_and_empty_rejected(alice):
    assert _try(alice, "big.pdf", PDF + b"0" * (10 * 1024 * 1024)).status_code in (400, 413)
    assert _try(alice, "empty.pdf", b"").status_code == 400


def test_path_traversal_name_is_neutralised_and_download_is_attachment(alice, upload):
    d = upload(alice, name="../../etc/passwd.pdf")
    r = alice.get(f"/documents/{d}/download")
    assert r.status_code == 200
    assert r.headers["Content-Disposition"].startswith("attachment")
    assert r.headers["Content-Type"] == "application/octet-stream"
    assert "passwd.pdf" in r.headers["Content-Disposition"] and ".." not in r.headers["Content-Disposition"]


def test_names_are_escaped_in_html(alice, upload):
    d = upload(alice, name="<img src=x onerror=alert(1)>.pdf")
    page = alice.get(f"/documents/{d}").get_data(as_text=True)
    assert "<img src=x" not in page


def test_rejected_upload_is_audited(alice, audit_rows):
    _try(alice, "evil.html", b"<html>")
    assert audit_rows(actor_id=alice.id, action="upload", outcome="denied")
