# Security policy

This is a student project for the Yellow Teaming specialisation at Fontys ICT: a notes application that starts deliberately insecure and gets its security features one week at a time, in the order of the semester. What is done so far is listed under Status in the README.

## Reporting a vulnerability

Report it privately through **Security → Report a vulnerability** on this repository (GitHub private vulnerability reporting). Please do not open a public issue for it.

Useful to include: what you did, what happened, what you expected, and the commit or the version of the image (the tag `app-...`) it applies to.

You get a first answer within seven days; outside the semester it can take longer. There is no bug bounty. A confirmed finding gets a fix and a check in the security test, and you are credited if you want to be.

## Scope

- The code on `main`: the app (`app/`), the database files (`db/`), the scripts (`scripts/`), the tests (`tests/`), Terraform (`terraform/`) and the workflows (`.github/workflows/`).
- The image on ghcr.io that is built from it.

Attack only your own copy, locally (`python scripts/deployment.py local`) or in your own Azure subscription. The deployment on Azure of this repository is only a target when the owner says so, for example in the hacking week of the course.

## Safe harbor

If you test in good faith and within the scope above, I consider it authorised, and I will not report you or take any other action against you for it. Good faith means:

- only your own copy, or the deployment on Azure when the owner has said so, and then by the rules given with it (for the hacking week: `REDTEAM.md`);
- no denial of service, no social engineering, and no data of others beyond what you need to show the finding;
- you stop and report as soon as you have found something, and keep it private until it is fixed.

This only covers what is mine to allow: not Azure, GitHub, Fontys or anyone else's systems.

## Known and accepted

Read the Status in the README first: what is not there yet is planned for a later week, and the findings of the scans that are accepted have a decision with the reason: for the image in `vex/openvex.json`, for Terraform in `.trivyignore.yaml`, and for the passive scan of the app in `zap-rules.tsv`.
