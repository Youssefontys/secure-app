# The database connection: a small pool, instead of a fresh TLS handshake on every request (MC-10).

import os

from psycopg.rows import namedtuple_row
from psycopg_pool import ConnectionPool

DATABASE_URL = os.environ["DATABASE_URL"]
# Times are shown in Dutch time; the database runs on UTC.
TIMEZONE = "Europe/Amsterdam"

# Made only at the first query, not at import: the pool's own background thread would otherwise outlive a
# process that fails a config check in app.py and exits before ever touching the database (MIT-23), which
# then cannot be joined cleanly at interpreter shutdown.
_pool = None


def _get_pool():
    global _pool
    if _pool is None:
        # At most as many as this process can really use at once: 4 threads per worker (app/Dockerfile).
        _pool = ConnectionPool(
            DATABASE_URL, min_size=1, max_size=4,
            kwargs={"autocommit": True, "row_factory": namedtuple_row, "options": f"-c TimeZone={TIMEZONE}"},
        )
    return _pool


# One SQL statement, on a connection borrowed from the pool and returned right after.
def query(sql, params=(), one=False):
    with _get_pool().connection() as conn:
        cur = conn.execute(sql, params)
        rows = cur.fetchall() if cur.description else []
    return (rows[0] if rows else None) if one else rows
