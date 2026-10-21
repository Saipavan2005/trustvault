"""One DB connection per request. Commit at the end, roll back on an unhandled error."""
import psycopg
from psycopg.rows import dict_row
from flask import g, current_app


def conn():
    if "db" not in g:
        g.db = psycopg.connect(current_app.config["DATABASE_URL"], row_factory=dict_row)
    return g.db


def one(sql, args=None):
    return conn().execute(sql, args).fetchone()


def all_(sql, args=None):
    return conn().execute(sql, args).fetchall()


def run(sql, args=None):
    return conn().execute(sql, args)


def close_db(exc):
    c = g.pop("db", None)
    if c is None:
        return
    try:
        c.rollback() if exc else c.commit()
    finally:
        c.close()
