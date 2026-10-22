# Secure app

Professional application for the Yellow Teaming (Security Engineering) specialisation, Fontys ICT semester 6 (Cyber Security Advanced, 2627nj).

## What this is

A small notes application that starts as a **deliberately insecure baseline** and gets its security features one week at a time, in the order of the semester: authentication and authorization in week 5, encryption and logging in week 6, application security in week 7, and CI/CD in week 8. The pipeline grows along with the research on SBOM in CI/CD: first the SBoM, then the scan, then the VEX.

Every feature that is added has an entry in `BoK/`: the use case, the misuse case it answers and the mitigation, written at the moment it is built. The app, the code, the scripts and the tests are in English; the BoK is in Dutch.

## The baseline

The baseline only does what is needed to be functional: register, log in, log out, a profile with changing the password and deleting the account, and creating, editing and deleting notes. Jinja escapes what it shows and the queries are parameterized, because Flask and psycopg do that by default. Everything else is open on purpose: plain-text passwords, unlimited login attempts, no CSRF protection, no ownership check on notes, the app logging in as the owner of the database, and the development server of Flask as root.

## Structure

- `app/` - the notes application: `app.py` creates the app, `db.py` talks to the database, `auth.py` handles registering and logging in (including the second step), `account.py` the profile, `notes.py` the notes, `totp.py` the TOTP calculation, `throttle.py` the attempt limits, `passwords.py` the rule for a new password and the Argon2id hashing, `encryption.py` the encryption of the TOTP secret and the notes. The website (HTML, CSS, JS) is in `app/web/`
- `db/` - the database schema, run by the database container on its first start
- `compose.yaml` - app and database for local use
- `tests/` - the security test against the local stack: `securitytest.py` runs one test per topic (`twofactortest.py` and the others). It only runs with `--wipe`

## Run it

Requires Docker with Compose v2. Copy `.env.example` to `.env` and fill in the three values, then:

```bash
docker compose up --build --wait
```

The app is on http://127.0.0.1:5000. After a change to `db/schema.sql`, remove the database volume first with `docker compose down -v`.

With the stack running, the security test empties the local accounts and checks every mitigation:

```bash
python -u tests/securitytest.py --wipe
```

## Status

- Week 5, authentication: a new password of 12 to 64 characters; two-step verification with TOTP, required after the first password, where every code works once; attempt limits per name and per address on the password, the code and the recovery code; a recovery code, and forgot password with two of the three factors; old sessions end on logout and when the password or the second factor changes; changing the password, deleting the account and replacing the second factor ask for the current password and a code
- Week 5, authorization: every route is closed by default, except a short list of public ones, so a new route is never open by accident; a note of someone else gives 404 on opening, editing and deleting
- Week 6, encryption: passwords as an Argon2id hash with the OWASP setting, also calculated for an unknown name, and rehashed at the login when the setting changes; the TOTP secret and the notes encrypted with AES-256-GCM, each bound to its owner and place, with the key outside the database

## Branches

Every topic is a branch from `main`, such as `week-5/authentication`, or stacked on an open branch it depends on, with that branch as the base of its pull request. It is merged with a merge commit, so the commit hashes the BoK refers to stay valid, and then deleted. Measurements for the research run on `lab/` branches: they are tagged, never merged, and deleted.

## License

MIT, see `LICENSE`.
