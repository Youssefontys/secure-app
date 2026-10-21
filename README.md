# Secure app

Professional application for the Yellow Teaming (Security Engineering) specialisation, Fontys ICT semester 6 (Cyber Security Advanced, 2627nj).

## What this is

A small notes application that starts as a **deliberately insecure baseline** and gets its security features one week at a time, in the order of the semester: authentication and authorization in week 5, encryption and logging in week 6, application security in week 7, and CI/CD in week 8. The pipeline grows along with the research on SBOM in CI/CD: first the SBoM, then the scan, then the VEX.

Every feature that is added has an entry in `BoK/`: the use case, the misuse case it answers and the mitigation, written at the moment it is built. The app, the code, the scripts and the tests are in English; the BoK is in Dutch.

## The baseline

The baseline only does what is needed to be functional: register, log in, log out, a profile with changing the password and deleting the account, and creating, editing and deleting notes. Jinja escapes what it shows and the queries are parameterized, because Flask and psycopg do that by default. Everything else is open on purpose: plain-text passwords, unlimited login attempts, no CSRF protection, no ownership check on notes, the app logging in as the owner of the database, and the development server of Flask as root.

## Structure

- `app/` - the notes application: `app.py` creates the app, `db.py` talks to the database, `auth.py` handles registering and logging in, `account.py` the profile, `notes.py` the notes. The website (HTML, CSS, JS) is in `app/web/`
- `db/` - the database schema, run by the database container on its first start
- `compose.yaml` - app and database for local use

## Run it

Requires Docker with Compose v2. Copy `.env.example` to `.env` and fill in the two values, then:

```bash
docker compose up --build --wait
```

The app is on http://127.0.0.1:5000. After a change to `db/schema.sql`, remove the database volume first with `docker compose down -v`.

## Branches

Every topic is a branch from `main`, such as `week-5/authentication`. It is merged with a merge commit, so the commit hashes the BoK refers to stay valid, and then deleted. Measurements for the research run on `lab/` branches: they are tagged, never merged, and deleted.

## License

MIT, see `LICENSE`.
