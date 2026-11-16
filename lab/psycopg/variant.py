"""Proof after subquestion 3: psycopg without binary, with the libpq of Debian. Changes app/ in the working folder of the
runner, never on main: requirements.txt without psycopg-binary, and libpq5 of Debian in the Dockerfile.
Usage: python lab/psycopg/variant.py"""
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[2]


def patch(rel, old, new):
    p = REPO / rel
    s = p.read_text(encoding="utf-8")
    assert s.count(old) == 1, (rel, old, s.count(old))
    p.write_text(s.replace(old, new), encoding="utf-8", newline="\n")


req = (REPO / "app/requirements.txt").read_text(encoding="utf-8").splitlines()
binary = [line for line in req if line.startswith("psycopg-binary==")]
assert len(binary) == 1, binary
(REPO / "app/requirements.txt").write_text("\n".join(line for line in req if line not in binary) + "\n",
                                           encoding="utf-8", newline="\n")
patch("app/requirements.txt", "psycopg[binary]==", "psycopg==")
# Without a pinned version: the proof measures what Debian delivers now; for main the version must be pinned.
patch("app/Dockerfile", "COPY requirements.txt .\n",
      "RUN apt-get update \\\n && apt-get install --yes --no-install-recommends libpq5 \\\n && rm -rf /var/lib/apt/lists/*\n\n"
      "COPY requirements.txt .\n")
print("app/ changed: psycopg without binary, libpq5 of Debian")
