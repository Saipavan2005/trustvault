"""Upload validation: allowlist, size, magic bytes, safe names. Nothing the client says about type is trusted."""
import io
import re
import unicodedata
import zipfile

MAX_BYTES = 10 * 1024 * 1024
ALLOWED = {"pdf", "docx", "xlsx", "png", "jpg", "jpeg", "txt"}


def clean_name(raw):
    """Display name only. Never used as a path."""
    name = (raw or "").replace("\\", "/").split("/")[-1]
    name = unicodedata.normalize("NFKC", name)
    name = re.sub(r"[\x00-\x1f\x7f<>:\"|?*]", "", name).strip(" .")
    return name[:120] or "document"


def clean_text(raw, limit=40):
    s = re.sub(r"[^A-Za-z0-9 _.\-]", "", (raw or "")).strip()
    return s[:limit]


def _office_ok(data, prefix):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
            return "[Content_Types].xml" in names and any(n.startswith(prefix) for n in names)
    except zipfile.BadZipFile:
        return False


def validate_upload(filename, data):
    """Returns (ok, error, ext)."""
    name = clean_name(filename)
    if "." not in name:
        return False, "File must have an extension.", None
    ext = name.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED:
        return False, "This file type is not allowed.", ext
    if not data:
        return False, "The file is empty.", ext
    if len(data) > MAX_BYTES:
        return False, "The file is larger than 10 MB.", ext
    ok = False
    if ext == "pdf":
        ok = data.startswith(b"%PDF-")
    elif ext == "png":
        ok = data.startswith(b"\x89PNG\r\n\x1a\n")
    elif ext in ("jpg", "jpeg"):
        ok = data.startswith(b"\xff\xd8\xff")
    elif ext == "docx":
        ok = _office_ok(data, "word/")
    elif ext == "xlsx":
        ok = _office_ok(data, "xl/")
    elif ext == "txt":
        try:
            data.decode("utf-8")
            ok = b"\x00" not in data
        except UnicodeDecodeError:
            ok = False
    if not ok:
        return False, "The file content does not match its extension.", ext
    return True, "", ext
