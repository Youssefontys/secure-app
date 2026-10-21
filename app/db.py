# The database connection: one helper for all SQL.

import os

import psycopg
from flask import g
from psycopg.rows import namedtuple_row

DATABASE_URL = os.environ["DATABASE_URL"]
# Times are shown in Dutch time; the database runs on UTC.
TIMEZONE = "Europe/Amsterdam"


def connection():
    if "db" not in g:
        g.db = psycopg.connect(DATABASE_URL, autocommit=True, row_factory=namedtuple_row, options=f"-c TimeZone={TIMEZONE}")
    return g.db


# At the end of every request (see app.py): close the connection of this request.
def close_connection(error=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


# One SQL statement
def query(sql, params=(), one=False):
    cur = connection().execute(sql, params)
    rows = cur.fetchall() if cur.description else []
    return (rows[0] if rows else None) if one else rows
