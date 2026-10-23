"""Application security: configuration as input, input validation, only POST and closed by default (MIT-22 to MIT-24).
Runs through securitytest.py."""
from securitytest import *

NAME_RULE = "Choose a username of 3 to 20 characters: letters, digits and _."


def starts(*env):
    """"start" if the app starts with these settings, otherwise the error message it stops with (MIT-23)."""
    r = in_app("import app", *env)
    return "start" if r.returncode == 0 else r.stderr.strip().splitlines()[-1].split(": ", 1)[-1]


def run():
    print("== configuration is input (MIT-23)")
    check("HTTPS_ONLY=yes does not start", starts("HTTPS_ONLY=yes"), "HTTPS_ONLY must be 0 or 1, not 'yes'.")
    check("  too short FLASK_SECRET_KEY does not start", starts("FLASK_SECRET_KEY=short"), "FLASK_SECRET_KEY must be at least 32 characters.")
    check("without HTTPS_ONLY: cookie only over HTTPS (safe by default)", in_app(
        "import app; print(app.app.config['SESSION_COOKIE_SECURE'])", run=("env", "-u", "HTTPS_ONLY", "python", "-c")).stdout.strip(), "True")

    print("== input validation (MIT-22)")
    for name in ("<script>alert(1)</script>", "ab", "a" * 21, "with space", "testacc1-b"):
        r = req(client(), "/register", {"username": name, "password": PW})
        check(f"register as {name[:24]!r}", (r[0], msg(r[1])), (400, NAME_RULE))
    check("  3 and 20 characters, with _ and digits", [req(client(), "/register", {"username": n, "password": PW})[0] for n in ("abc", "a_b_c_1234567890_xyz")],
          [302, 302])
    unlock()
    r = req(client(), "/login", {"username": "<script>alert(1)</script>", "password": PW})
    check("  logging in with an invalid name: same answer as unknown", (r[0], msg(r[1])), (400, "Incorrect username or password."))
    try:
        big = urllib.request.urlopen(urllib.request.Request(B + "/login", data=b"username=" + b"a" * (17 * 1024) + b"&password=x", method="POST")).status
    except urllib.error.HTTPError as e:
        big = e.code
    check("request of 17 KiB: 413, not read", big, 413)
    sql("DELETE FROM auth_throttle; DELETE FROM users WHERE username IN ('abc', 'a_b_c_1234567890_xyz')")

    print("== closed by default (MIT-24)")
    rules = json.loads(in_app("import app, json, auth; print(json.dumps([[r.endpoint, r.rule, sorted(r.methods)]"
                              " for r in app.app.url_map.iter_rules() if r.endpoint not in auth.PUBLIC_ENDPOINTS]))").stdout)
    closed = [(e, loc(req(client(), rule.replace("<int:note_id>", "1"), None if "GET" in methods else {}))) for e, rule, methods in rules]
    check(f"all {len(rules)} non-public routes send an anonymous visitor to /login", [x for x in closed if x[1] != "302 /login"], [])
    check("  only login, register, the recovery routes, logout and static are public",
          in_app("import auth; print(sorted(auth.PUBLIC_ENDPOINTS))").stdout.strip(),
          "['auth.forgot_password', 'auth.login', 'auth.login_code', 'auth.login_recover', 'auth.logout', 'auth.register', 'static']")

    print("== only POST acts")
    unlock()
    heads = [urllib.request.urlopen(urllib.request.Request(B + "/login", method="HEAD")).status for _ in range(3)]
    check("3 times HEAD /login: plain 200, does not count as an attempt", (heads, sql("SELECT count(*) FROM auth_throttle")), ([200] * 3, "0"))
