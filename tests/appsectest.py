"""Application security: closed by default (MIT-24). Runs through securitytest.py."""
import json

from securitytest import *


def run():
    print("== closed by default (MIT-24)")
    rules = json.loads(in_app("import app, json, auth; print(json.dumps([[r.endpoint, r.rule, sorted(r.methods)]"
                              " for r in app.app.url_map.iter_rules() if r.endpoint not in auth.PUBLIC_ENDPOINTS]))").stdout)
    closed = [(e, loc(req(client(), rule.replace("<int:note_id>", "1"), None if "GET" in methods else {}))) for e, rule, methods in rules]
    check(f"all {len(rules)} non-public routes send an anonymous visitor to /login", [x for x in closed if x[1] != "302 /login"], [])
    check("  only login, register, the recovery routes, logout and static are public",
          in_app("import auth; print(sorted(auth.PUBLIC_ENDPOINTS))").stdout.strip(),
          "['auth.forgot_password', 'auth.login', 'auth.login_code', 'auth.login_recover', 'auth.logout', 'auth.register', 'static']")
