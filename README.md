# Secure app

Professional application for the Yellow Teaming (Security Engineering) specialisation, Fontys ICT semester 6 (Cyber Security Advanced, 2627nj).

## What this is

A small notes application that starts as a **deliberately insecure baseline** and gets its security features one week at a time, in the order of the semester: authentication and authorization in week 5, encryption and logging in week 6, application security in week 7, and CI/CD in week 8. The pipeline grows along with the research on SBOM in CI/CD: first the SBoM, then the scan, then the VEX.

Every feature that is added has an entry in `BoK/`: the use case, the misuse case it answers and the mitigation, written at the moment it is built. The app, the code, the scripts and the tests are in English; the BoK is in Dutch.

## The baseline

The baseline only does what is needed to be functional: register, log in, log out, a profile with changing the password and deleting the account, and creating, editing and deleting notes. Jinja escapes what it shows and the queries are parameterized, because Flask and psycopg do that by default. Everything else is open on purpose: plain-text passwords, unlimited login attempts, no CSRF protection, no ownership check on notes, the app logging in as the owner of the database, and the development server of Flask as root.

## Structure

- `app/` - the notes application: `app.py` creates the app, `db.py` talks to the database, `auth.py` handles registering and logging in (including the second step), `account.py` the profile, `notes.py` the notes, `totp.py` the TOTP calculation, `throttle.py` the attempt limits, `passwords.py` the rule for a new password and the Argon2id hashing, `encryption.py` the encryption of the TOTP secret and the notes, `events.py` the security events in the log, `csrf.py` the CSRF token of every form. The website (HTML, CSS, JS) is in `app/web/`
- `db/` - the database schema and the password of the app role, run by the database container on its first start
- `compose.yaml` - app and database for local use
- `.github/dependabot.yml` - weekly update proposals for the pinned packages, images and GitHub Actions
- `.github/workflows/CI-image.yml` - on every pull request to `main`, builds the image and makes its SBoM, without publishing (the job `check`); on every push to `main`, does the same and then publishes the image to ghcr.io, tagged with the commit and with the content of `app/`
- `scripts/` - `deployment.py` to deploy locally and to remove it all again. It asks what to do and starts `deploy_local.py` or `undo.py`, which take what they share from it: paths, questions, stopping and hackmode
- `tests/` - the security test against the local stack: `securitytest.py` runs one test per topic (`twofactortest.py` and the others). It only runs with `--wipe`

## Run it

Requires Docker with Compose v2 and Python 3. The script creates the four secrets in `.env` if they are missing, readable only for you, asks whether to turn on hackmode for the hacking week, and starts the stack:

```bash
python scripts/deployment.py local
```

Without a terminal, as in CI, it asks nothing and keeps what is in `.env`. To remove it all again, the containers, the database with all notes, the built image and `.env`, with no as the default per step:

```bash
python scripts/deployment.py undo
```

On Linux or macOS the command is often `python3`; the script works the same on Windows and Linux.

The app is on http://127.0.0.1:5000, and its security events are in `docker compose logs app`, one JSON line each. After a change to `db/schema.sql`, remove the database volume first with `docker compose down -v`.

With the stack running, the security test empties the local accounts and checks every mitigation:

```bash
python -u tests/securitytest.py --wipe
```

## Status

- Week 5, authentication: a new password of 12 to 64 characters; two-step verification with TOTP, required after the first password, where every code works once; attempt limits per name and per address on the password, the code and the recovery code; a recovery code, and forgot password with two of the three factors; old sessions end on logout and when the password or the second factor changes; changing the password, deleting the account and replacing the second factor ask for the current password and a code
- Week 5, authorization: every route is closed by default, except a short list of public ones, so a new route is never open by accident; a note of someone else gives 404 on opening, editing and deleting
- Week 6, encryption: passwords as an Argon2id hash with the OWASP setting, also calculated for an unknown name, and rehashed at the login when the setting changes; the TOTP secret and the notes encrypted with AES-256-GCM, each bound to its owner and place, with the key outside the database
- Week 6, logging: every security event as one JSON line, with time, kind and address, and never a password, code or secret; a typed name only when the account exists, and one line per lockout instead of one per refused attempt; an own error page that shows no details, with the error and the path in the log, safe against a line break in the URL
- Week 7, input validation: the app does not start with an unknown setting or a session key under 32 characters, and the session cookie goes only over HTTPS unless HTTPS_ONLY=0, as locally, with SameSite=Lax; usernames of 3 to 20 letters, digits and _, notes of at most 15 and 250 characters, and requests over 16 KiB refused with 413 before they are read; at most 10 new accounts per hour per address and 25 notes per account
- Week 7, CSRF and headers: a CSRF token per session on every POST; a strict Content-Security-Policy without inline script, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy and the cross-origin headers on every response, and HSTS over HTTPS; no page in a browser or proxy cache, except the static files; and a session of at most 8 hours
- Week 7, database security: the app logs in as its own role notes_app, which can only read and write its own tables, not as the owner; the password of the owner is not in the environment of the app
- Week 7, system security: every Python package, including what the others pull in, and both base images pinned on version and digest, with Dependabot proposing updates every week; the app runs with Gunicorn as an ordinary user without a shell, instead of the development server of Flask as root
- Week 7, secrets: `deployment.py local` creates every missing secret in `.env` with 256 random bits, never shows it, and makes `.env` readable only for its owner; hackmode for the hacking week, off by default, widens the limit per address and leaves the counter per name off for one demo account
- Week 7, pipeline: GitHub Actions builds the image on every pull request and push to `main` and keeps a CycloneDX SBoM of it for 90 days, with only the rights each job needs and every action pinned on a commit; on a push to `main` it publishes the image to ghcr.io

## Branches

Every topic is a branch from `main`, such as `week-5/authentication`, or stacked on an open branch it depends on, with that branch as the base of its pull request. It is merged with a merge commit, so the commit hashes the BoK refers to stay valid, and then deleted. Measurements for the research run on `lab/` branches: they are tagged, never merged, and deleted.

## License

MIT, see `LICENSE`.
