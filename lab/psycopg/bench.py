"""Runs in the container of the app: how fast does psycopg talk to the database? Only reads, no tables.
Five repetitions per measurement, in milliseconds. Usage: python -I /tmp/bench.py"""
import json
import os
import time

import psycopg

URL = os.environ["DATABASE_URL"]


def connect(n):
    for _ in range(n):
        with psycopg.connect(URL):
            pass


def select1(n):
    with psycopg.connect(URL, autocommit=True) as c:
        for _ in range(n):
            c.execute("select 1").fetchone()


def rows(n):
    with psycopg.connect(URL, autocommit=True) as c:
        for _ in range(n):
            c.execute("select g, md5(g::text) from generate_series(1, 1000) g").fetchall()


result = {"implementation": psycopg.pq.__impl__, "libpq": psycopg.pq.version()}
for name, fn, n in (("connect_50", connect, 50), ("select_1_5000", select1, 5000), ("rows_1000_200", rows, 200)):
    fn(5)
    times = []
    for _ in range(5):
        start = time.perf_counter()
        fn(n)
        times.append(round((time.perf_counter() - start) * 1000, 1))
    result[name] = {"ms": times, "median": sorted(times)[2]}
print(json.dumps(result))
