# Registering, logging in with password and code, logging out, and who is logged in.

import hashlib
import hmac
import re
import secrets
import time
from collections import namedtuple
from functools import wraps

import psycopg
from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for

import passwords
import throttle
import totp
from db import query

bp = Blueprint("auth", __name__)

PENDING_MAX_SECONDS = 300
CodeError = namedtuple("CodeError", "message minutes")
SETUP_ENDPOINTS = {"account.setup_2fa", "account.qr_2fa"}
# The only routes without a login; every other route is closed by default (MIT-24).
PUBLIC_ENDPOINTS = {"auth.register", "auth.login", "auth.login_code", "auth.login_recover", "auth.forgot_password", "auth.logout", "static"}
FORGOT_WRONG = "Username, recovery code or code is incorrect."


@bp.before_app_request
def load_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id is None or request.endpoint == "static":
        return
    user = query("SELECT id, username, session_version, totp_enabled FROM users WHERE id = %s", (user_id,), one=True)
    if user is None or user.session_version != session.get("session_version"):
        session.clear()
        flash("Your session is no longer valid. Please log in again.")
        return
    g.user = user


# A fresh session for this user, with the current session version.
def start_session(user_id, version):
    session.clear()
    session["user_id"] = user_id
    session["session_version"] = version


# After an UPDATE that also raises session_version: other sessions expire, the current one gets the new version.
# One statement, so never a new password or new 2FA while old sessions keep working
def keep_this_session(row):
    session["session_version"] = row.session_version


# Closed by default (MIT-24): logged in and with two-step verification, otherwise only the setup (MIT-12).
# A new route is thus never open by accident; only PUBLIC_ENDPOINTS may go without a login. After load_user.
@bp.before_app_request
def require_login():
    if request.endpoint in PUBLIC_ENDPOINTS or request.endpoint is None:
        return None
    if g.user is None:
        return redirect(url_for("auth.login"))
    if not g.user.totp_enabled and request.endpoint not in SETUP_ENDPOINTS:
        return redirect(url_for("account.setup_2fa"))
    return None


# Whoever is already logged in does not need to log in or register again.
def logged_out_only(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is not None:
            return redirect(url_for("notes.index"))
        return view(*args, **kwargs)
    return wrapper


@bp.route("/register", methods=["GET", "POST"])
@logged_out_only
def register():
    if request.method != "POST":
        return render_template("auth.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not username or not password:
        return render_template("auth.html", error="Enter a username and a password."), 400
    if error := passwords.password_problem(password):
        return render_template("auth.html", error=error), 400
    try:
        query("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
    except psycopg.errors.UniqueViolation:
        return render_template("auth.html", error="That username is already taken."), 409
    flash("Your account has been created. You can log in now.")
    return redirect(url_for("auth.login"))


@bp.route("/login", methods=["GET", "POST"])
@logged_out_only
def login():
    if request.method != "POST":
        return render_template("auth.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    # Count per address and per name per address (MIT-10), also for unknown names: reveals nothing.
    limits = throttle.password_limits(username, request.remote_addr)
    if minutes := throttle.attempt(*limits):
        return render_template("auth.html", error=throttle.message(minutes)), *throttle.refusal(minutes)
    row = query(
        "SELECT id, totp_enabled, session_version FROM users WHERE username = %s AND password = %s",
        (username, password), one=True,
    )
    if row is None:
        return render_template("auth.html", error="Incorrect username or password."), 400
    throttle.succeeded(*limits)

    session.clear()
    if row.totp_enabled:
        # Factor 1 of 2: only pending_user_id, and no route opens with that (MIT-05).
        session["pending_user_id"] = row.id
        session["pending_version"] = row.session_version
        session["pending_since"] = int(time.time())
        return redirect(url_for("auth.login_code"))
    # No two-step verification yet: after the password, set it up first (MIT-12).
    start_session(row.id, row.session_version)
    return redirect(url_for("account.setup_2fa"))


# The user of the half login, or None if it is too old or the session version changed.
def pending_login():
    user_id = session.get("pending_user_id")
    if user_id is None:
        return None
    if time.time() - session.get("pending_since", 0) > PENDING_MAX_SECONDS:
        session.clear()
        flash("That took too long. Please log in again.")
        return None
    row = query("SELECT session_version FROM users WHERE id = %s", (user_id,), one=True)
    if row is None or row.session_version != session.get("pending_version"):
        session.clear()
        flash("Your session is no longer valid. Please log in again.")
        return None
    return user_id


# The second step: the code from the authenticator app.
@bp.route("/login/2fa", methods=["GET", "POST"])
@logged_out_only
def login_code():
    user_id = pending_login()
    if user_id is None:
        return redirect(url_for("auth.login"))
    if request.method != "POST":
        return render_template("login_code.html")

    if error := check_code(user_id):
        return render_template("login_code.html", error=error.message), *throttle.refusal(error.minutes)
    # Only now logged in; start_session throws the half login away completely.
    start_session(user_id, session["pending_version"])
    return redirect(url_for("notes.index"))


# Only the SHA-256 of a recovery code: with 128 random bits a slow hash is not needed.
def hash_recovery_code(text):
    return hashlib.sha256(re.sub(r"[\s-]", "", text).lower().encode()).hexdigest()


# A new recovery code of 128 bits: the code to show once, and the hash to store.
def make_recovery_code():
    code = secrets.token_hex(16)
    return "-".join(code[i:i + 4] for i in range(0, len(code), 4)), hash_recovery_code(code)


# Sets a new recovery code for this account and returns it; an earlier code expires.
def new_recovery_code(user_id):
    code, recovery_hash = make_recovery_code()
    query("UPDATE users SET recovery_hash = %s WHERE id = %s", (recovery_hash, user_id))
    return code


# The recovery code instead of the code from the app, for whoever lost their phone.
@bp.route("/login/recover", methods=["GET", "POST"])
@logged_out_only
def login_recover():
    user_id = pending_login()
    if user_id is None:
        return redirect(url_for("auth.login"))
    if request.method != "POST":
        return render_template("login_recover.html")

    recovery_limit = throttle.limit("recovery_account", user_id)
    if minutes := throttle.attempt(recovery_limit):
        return render_template("login_recover.html", error=throttle.message(minutes)), *throttle.refusal(minutes)
    given = hash_recovery_code(request.form.get("code", ""))
    stored = query("SELECT recovery_hash FROM users WHERE id = %s", (user_id,), one=True)
    if not (stored and stored.recovery_hash and hmac.compare_digest(given, stored.recovery_hash)):
        return render_template("login_recover.html", error="Incorrect recovery code."), 400
    # Works once: 2FA off, sessions invalid; the hash in the WHERE lets one request win.
    row = query(
        "UPDATE users SET recovery_hash = NULL, totp_secret = NULL, totp_enabled = false, totp_last_step = NULL,"
        " session_version = session_version + 1 WHERE id = %s AND recovery_hash = %s RETURNING session_version",
        (user_id, given), one=True,
    )
    if row is None:
        return render_template("login_recover.html", error="Incorrect recovery code."), 400
    throttle.succeeded(recovery_limit)
    start_session(user_id, row.session_version)
    flash("Your recovery code has been used. Set up two-step verification again with your new phone.")
    return redirect(url_for("account.setup_2fa"))


# Forgot password: recovery code and code from the app, two of the three factors (MIT-14).
@bp.route("/login/forgot", methods=["GET", "POST"])
@logged_out_only
def forgot_password():
    if request.method != "POST":
        return render_template("login_forgot.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if problem := passwords.password_problem(password, request.form.get("password_repeat", "")):
        return render_template("login_forgot.html", error=problem), 400
    # Reachable without a password, so the same counters as at login: per address and per name per address.
    limits = throttle.password_limits(username, request.remote_addr)
    if minutes := throttle.attempt(*limits):
        return render_template("login_forgot.html", error=throttle.message(minutes)), *throttle.refusal(minutes)
    user = query("SELECT id, recovery_hash FROM users WHERE username = %s AND totp_enabled", (username,), one=True)
    given = hash_recovery_code(request.form.get("recovery_code", ""))
    if not (user and user.recovery_hash and hmac.compare_digest(given, user.recovery_hash)):
        return render_template("login_forgot.html", error=FORGOT_WRONG), 400
    throttle.succeeded(*limits)
    # The recovery code is right; only now does a wrong code count per account, with the lockout of the code step (MIT-06).
    if code_error := check_code(user.id):
        error = code_error.message if code_error.minutes else FORGOT_WRONG
        return render_template("login_forgot.html", error=error), *throttle.refusal(code_error.minutes)
    # All in one UPDATE: password, new recovery code, sessions; the old hash in the WHERE.
    new_code, new_hash = make_recovery_code()
    row = query(
        "UPDATE users SET password = %s, recovery_hash = %s, session_version = session_version + 1"
        " WHERE id = %s AND recovery_hash = %s RETURNING id",
        (password, new_hash, user.id, given), one=True,
    )
    if row is None:
        return render_template("login_forgot.html", error=FORGOT_WRONG), 400
    session.clear()
    # Not logged in automatically; but the new recovery code at once, otherwise there is none left.
    return render_template("recovery_code.html", code=new_code, first=False, reset=True)


@bp.route("/logout", methods=["POST"])
def logout():
    # Version up: a copied cookie expires too, on all devices.
    if g.user is not None:
        query("UPDATE users SET session_version = session_version + 1 WHERE id = %s", (g.user.id,))
    session.clear()
    return redirect(url_for("auth.login"))


# Checks the TOTP code from the form: None if it is right, otherwise a CodeError.
def check_code(user_id):
    code_limit = throttle.limit("totp_account", user_id)
    user = query("SELECT totp_secret FROM users WHERE id = %s", (user_id,), one=True)
    if not (user and user.totp_secret):
        return CodeError("Two-step verification is not set up.", 0)
    # Locked: then the right code is refused too (MIT-06).
    if minutes := throttle.attempt(code_limit):
        return CodeError(throttle.message(minutes), minutes)
    step = totp.matching_step(user.totp_secret, request.form.get("code", ""))
    # Single use (MIT-07) and lockout in one UPDATE: of two requests, one wins.
    if step is not None and query(
        "UPDATE users SET totp_last_step = %s"
        " WHERE id = %s AND (totp_last_step IS NULL OR totp_last_step < %s)"
        " AND NOT EXISTS (SELECT 1 FROM auth_throttle WHERE key = %s AND locked_until > now()) RETURNING id",
        (step, user_id, step, code_limit.key), one=True,
    ):
        throttle.succeeded(code_limit)
        return None
    # Wrong, or already used: the attempt has already been counted.
    return CodeError("Incorrect or already used code.", 0)
