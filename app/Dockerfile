# Pinned on version and digest (MIT-03): a tag like 3.15-slim moves along with every new build of the image.
FROM python:3.15.2-slim-trixie@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# The libpq of Debian, pinned on version (MIT-03): psycopg loads it, Debian updates it and the scan sees it, with what
# it pulls in (MIT-43). When a newer version comes out, this one disappears from Debian and the build fails: update it then.
# zlib1g too, on the version Debian Security has (CVE-2026-76844 and CVE-2026-85091): the base image of 15-11-2026 does
# not have it yet. Pinned the same way; when the base image has it, remove it here.
RUN apt-get update \
 && apt-get install --yes --no-install-recommends libpq5=17.12-0+deb13u1 zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1 \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Then remove pip itself: the app does not use it, and pip brings its own copies of urllib3, msgpack and
# setuptools, in which Trivy found known vulnerabilities (MC-11, research subquestion 1).
RUN pip install --no-cache-dir -r requirements.txt \
 && pip uninstall --yes pip

COPY . .

# An ordinary user without a shell and without write access to the code: whoever takes over
# the app is not root and cannot change the code (MC-14).
# Then remove the setuid and setgid bit from every program, so mount, su and passwd also run with the rights
# of that user and not as root (MIT-42); the VEX statements for mount rely on this.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin app \
 && find / -xdev -type f -perm /6000 -exec chmod a-s {} +
USER app

EXPOSE 5000

# Gunicorn instead of the development server of Flask, which itself says it is not for
# production (MC-14, MIT-26). Two workers, so two requests at the same time really run at the same time.
# Threads on top (MC-10): a sync worker with --workers alone handles exactly one connection at a time, so
# two slow, never-finished requests (measured: 2 trickling POSTs) left every other visitor without any
# response for 10+ seconds. 4 threads per worker means it takes many more slow clients to do that, not two.
# Without a control socket: we do not use it, and app deliberately has no home directory.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--worker-class", "gthread", \
     "--no-control-socket", "app:app"]
