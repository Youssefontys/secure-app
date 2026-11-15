# Security policy

This is a student project for the Yellow Teaming specialisation at Fontys ICT: a notes application that starts deliberately insecure and gets its security features one week at a time, in the order of the semester. What is done so far is listed under Status in the README.

## Reporting a vulnerability

Report it privately through **Security → Report a vulnerability** on this repository (GitHub private vulnerability reporting). Please do not open a public issue for it.

Useful to include: what you did, what happened, what you expected, and the commit or the version of the image (the tag `app-...`) it applies to.

There is no bug bounty and no fixed response time: reports are read during the semester. A confirmed finding gets a fix and a check in the security test, and you are credited if you want to be.

## Scope

- The code on `main`: the app (`app/`), the database files (`db/`), the scripts (`scripts/`), the tests (`tests/`), Terraform (`terraform/`) and the workflows (`.github/workflows/`).
- The image on ghcr.io that is built from it.

Attack only your own copy, locally (`python scripts/deployment.py local`) or in your own Azure subscription. The deployment on Azure of this repository is only a target when the owner says so, for example in the hacking week of the course.

## Known and accepted

Read the Status in the README first: what is not there yet is planned for a later week, and the findings of the scans that are accepted have a decision with the reason in `.trivyignore.yaml` and `zap-rules.tsv`.
