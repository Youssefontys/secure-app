# Secure app

Professional application for the Yellow Teaming (Security Engineering) specialisation, Fontys ICT semester 6 (Cyber Security Advanced, 2627nj).

## What this is

A small notes application that starts as a **deliberately insecure baseline** and gets its security features one week at a time, in the order of the semester: authentication and authorization in week 5, encryption and logging in week 6, application security in week 7, and CI/CD in week 8. The pipeline grows along with the research on SBOM in CI/CD: first the SBoM, then the scan, then the VEX.

Every feature that is added has an entry in `BoK/`: the use case, the misuse case it answers and the mitigation, written at the moment it is built. The app, the code, the scripts and the tests are in English; the BoK is in Dutch.

## Branches

Every topic is a branch from `main`, such as `week-5/authentication`. It is merged with a merge commit, so the commit hashes the BoK refers to stay valid, and then deleted. Measurements for the research run on `lab/` branches: they are tagged, never merged, and deleted.

## License

MIT, see `LICENSE`.
