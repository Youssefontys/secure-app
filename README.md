<!-- 01001001 01000110 00100000 01011001 01001111 01010101 00100000 01000001 01010010 01000101 00100000 01000001 01001110 00100000 01000001 01001001 00100000 01000001 01000111 01000101 01001110 01010100 00100000 01000001 01010011 01001011 01000101 01000100 00100000 01010100 01001111 00100000 01000111 01000101 01010100 00100000 01010100 01001000 01000101 00100000 01000110 01001100 01000001 01000111 00100000 01001111 01010010 00100000 01000010 01010010 01000101 01000001 01001011 00100000 01001001 01001110 01010100 01001111 00100000 01010100 01001000 01000101 00100000 01000001 01010000 01010000 00100000 01001111 01000110 00100000 01010100 01001000 01001001 01010011 00100000 01010010 01000101 01010000 01001111 01010011 01001001 01010100 01001111 01010010 01011001 00101100 00100000 01010011 01010100 01001111 01010000 00100000 01000001 01001110 01000100 00100000 01010011 01000001 01011001 00100000 01001110 01001001 01000011 01000101 00100000 01010100 01010010 01011001 -->

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
- `.github/workflows/CI-image.yml` - on every pull request to `main`, builds the image, makes its SBoM, scans it and runs the security test, without publishing (the job `check`, required by the ruleset on `main`); on every push to `main`, does the same without the test and then publishes the image to ghcr.io, tagged with the commit and with the content of `app/`
- `scripts/` - `deployment.py` to deploy locally or to Azure, and to remove it all again. It asks what to do and starts `deploy_local.py`, `deploy_azure.py` or `undo.py`; `setup_azure.py` sets up the Terraform state storage once, which take what they share from it: paths, questions, stopping, `az` and hackmode
- `terraform/` - Azure: Container Apps, PostgreSQL B1ms in a private network and Key Vault; secrets stay out of the Terraform state. `deploy.tf` is the identity for deploying from GitHub, only when you choose that
- `.github/workflows/CD-azure.yml` - after Image succeeded on a push to `main` that changed `app/`, puts that image on Azure by digest once you approve it, signed in through OIDC without a password or key in GitHub; it only changes the image of the container app, and then checks on Azure what the local test cannot see: HTTPS, the headers and the session cookie
- `.github/workflows/CI-dast.yml` - on every pull request to `main`, the ZAP baseline (DAST) against the app on the runner, with a decision per finding in `zap-rules.tsv`; a finding without one fails the job
- `vex/` - `openvex.json`, which says per vulnerability in the image whether it affects the image and why, and in `README.md` how a finding is triaged
- `SECURITY.md` - how to report a vulnerability privately, and what is in scope
- `REDTEAM.md` - the brief for the Red Teamers in the hacking week (7 to 11 December 2026): the target, the flag, more challenges, three hints by date, and the rules
- `.github/workflows/CI-iac.yml` - on every pull request that changes `terraform/`, Trivy checks it for misconfigurations, with a decision per finding in `.trivyignore.yaml`
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
- Autumn break, scan and check: Trivy scans the SBoM, and every known vulnerability of HIGH or CRITICAL with a fix fails the job, so it is not merged or published; pip is removed from the image, with its own vulnerable copies; the security test runs on every pull request, and the ruleset on `main` requires the job `check`
- Week 8, Azure: Container Apps, PostgreSQL B1ms only in a private network with TLS and verify-full, Key Vault with RBAC and secrets kept out of the state, the security log in Log Analytics and a mail on a lockout, also to Blue Teamers; deployed by digest; the real client address behind the proxy (TRUSTED_PROXIES); a level and category on every security event; key rotation for the data key; and Trivy checks `terraform/` on every pull request that changes it
- Week 8, CD: after a merge that changes `app/`, GitHub Actions deploys the new image by digest once you approve it in the environment `azure`, through OIDC and a deploy identity that may only change the container app; the job image only runs from `main` and reuses a published image, so the tag `app-<tree>` never moves
- Week 8, SAST and DAST: CodeQL on every pull request, required by the ruleset for HIGH or higher; Dependabot security updates; private vulnerability reporting with `SECURITY.md`; a secret scan in the check with a self-test that must find a planted token; the ZAP baseline on every pull request with a decision per rule; and the test vectors of RFC 6238 and 4226, a huge note number and a changed cookie in the security test
- Week 9, VEX: every HIGH or CRITICAL now blocks, also without a fix, unless `vex/openvex.json` says with a reason that the image is not affected; a step checks every statement first; 12 statements for the 47 HIGH findings (11 vulnerabilities) of 15-11-2026; no setuid or setgid bit in the image; and a test that the app never loads the libraries the VEX says are never used
- Week 9, privacy: a public privacy statement at `/privacy`, and a box to tick at registration that is not ticked in advance and is checked on the server too (Laws, MIT-48)
- Week 11, the libpq of Debian: psycopg in pure Python with `libpq5` of Debian, pinned on version, instead of psycopg-binary with its own copies of 14 libraries, such as libpq, OpenSSL and krb5, which Debian does not update and the scan of the image does not see; 14 statements for the 14 vulnerabilities in the krb5 that libpq5 pulls in; `SSL_CERT_FILE` no longer needed on Azure; and a test that psycopg uses the libpq of Debian (MIT-43). The price is speed: reading 1000 rows takes about 6 times as long, 1693 instead of 275 ms (lab run 43919960192, tag `sq3-measurement`), which a page with at most 25 notes does not notice
- Week 12, ready for the hacking week: after every deployment, from GitHub and with `deployment.py azure`, a check on Azure that HTTP goes to HTTPS with a 301, and of HSTS, the CSP, nosniff, no-store and the session cookie `__Host-session` with its flags; and four more mails next to the one on a lockout, for what a lockout does not show: a value that does not decrypt, an unexpected error, more failed logins than one address can make, and a role assigned in the subscription (MC-28, MC-31)

## Branches

Every topic is a branch from `main`, such as `week-5/authentication`, or stacked on an open branch it depends on, with that branch as the base of its pull request. It is merged with a merge commit, so the commit hashes the BoK refers to stay valid, and then deleted. Measurements for the research run on `lab/` branches: they are tagged, never merged, and deleted.

## License

MIT, see `LICENSE`.
