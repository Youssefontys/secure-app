# Pinned on version and digest (MIT-03): a tag like 3.15-slim moves along with every new build of the image.
FROM python:3.15.1-slim-trixie@sha256:533b0b2f9b5d46fd097091cf826f27902f1d6c3bca714b6dc74551356aa97a51

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
# Then remove pip itself: the app does not use it, and pip brings its own copies of urllib3, msgpack and
# setuptools, in which Trivy found known vulnerabilities (MC-11, research subquestion 1).
RUN pip install --no-cache-dir -r requirements.txt \
 && pip uninstall --yes pip

COPY . .

# An ordinary user without a shell and without write access to the code: whoever takes over
# the app is not root and cannot change the code (MC-14).
RUN useradd --system --no-create-home --shell /usr/sbin/nologin app
USER app

EXPOSE 5000

# Gunicorn instead of the development server of Flask, which itself says it is not for
# production (MC-14, MIT-26). Two workers, so two requests at the same time really run at the same time.
# Without a control socket: we do not use it, and app deliberately has no home directory.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--no-control-socket", "app:app"]
