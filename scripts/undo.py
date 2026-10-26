# Everything gone again, locally. Start through deployment.py undo.
# Every step asks first, no by default; so without a terminal nothing happens.

import os
import shutil
import subprocess

from deployment import ENV, REPO, SECRETS, check_tools, stop, yes


def run():
    if yes("🐳 Remove locally: the containers, the database with all notes, the built image and .env?"):
        check_tools("local")
        # The database first: without .env but with the old database in the volume the app no longer starts.
        # compose.yaml requires the secrets on down too (${...:?}), so without .env placeholder values; down does not use them.
        env = {**os.environ, **dict.fromkeys(SECRETS, "undo")}
        if subprocess.run([shutil.which("docker"), "compose", "down", "--volumes", "--rmi", "local"], cwd=REPO, env=env).returncode != 0:
            stop("docker compose down did not work; .env stays, otherwise it no longer matches the database.\n"
                 "   💡 Is Docker running (on Windows: Docker Desktop)? Start it and try again.")
        ENV.unlink(missing_ok=True)
        print("   ✅ Gone. Start again: python scripts/deployment.py local")
    print("\n👋 Done.\n")
