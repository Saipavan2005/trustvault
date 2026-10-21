from werkzeug.security import generate_password_hash

from . import db

ROLES = ("admin", "owner", "viewer")


def create_user(email, password, role):
    email = email.strip().lower()
    if role not in ROLES:
        raise ValueError("bad role")
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    return db.one(
        "INSERT INTO users(email,password_hash,role) VALUES (%s,%s,%s) RETURNING id,email,role",
        (email, generate_password_hash(password), role),
    )
