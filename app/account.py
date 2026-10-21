# The own account: profile, two-step verification, changing the password, deleting the account.

import io

import segno
from flask import Blueprint, Response, abort, flash, g, redirect, render_template, request, session, url_for

import passwords
import throttle
import totp
from auth import check_code, keep_this_session, new_recovery_code
from db import query

bp = Blueprint("account", __name__, url_prefix="/account")

NO_STORE_ENDPOINTS = {"account.setup_2fa", "account.qr_2fa", "account.new_recovery", "auth.forgot_password"}


@bp.after_app_request
def no_store(response):
    if request.endpoint in NO_STORE_ENDPOINTS:
        response.headers["Cache-Control"] = "no-store"
    return response


@bp.route("")
def index():
    return render_account()


# The profile page, always of the logged-in user themselves.
def render_account(error=None, status=200, headers=None):
    profile = query(
        "SELECT username, created_at, (SELECT count(*) FROM notes WHERE user_id = users.id) AS note_count"
        " FROM users WHERE id = %s",
        (g.user.id,), one=True,
    )
    return render_template("account.html", profile=profile, error=error), status, headers or {}


@bp.route("/2fa", methods=["GET", "POST"])
def setup_2fa():
    if g.user.totp_enabled:
        return redirect(url_for("account.index"))
    # A new secret only counts after a first valid code, so you do not lock yourself out.
    query("UPDATE users SET totp_secret = %s, totp_last_step = NULL WHERE id = %s AND totp_secret IS NULL",
          (totp.new_secret(), g.user.id))
    secret = query("SELECT totp_secret FROM users WHERE id = %s", (g.user.id,), one=True).totp_secret
    # The key in groups of four, to type over if scanning does not work.
    grouped = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    if request.method != "POST":
        return render_template("setup_2fa.html", secret=grouped)

    if error := check_code(g.user.id):
        return render_template("setup_2fa.html", secret=grouped, error=error.message), *throttle.refusal(error.minutes)
    # Sessions from before the second factor started with only a password; they expire now.
    keep_this_session(query(
        "UPDATE users SET totp_enabled = true, session_version = session_version + 1"
        " WHERE id = %s RETURNING session_version",
        (g.user.id,), one=True,
    ))
    return render_template("recovery_code.html", code=new_recovery_code(g.user.id), first=True)


@bp.route("/2fa/recovery", methods=["POST"])
def new_recovery():
    # Password and code: with the session and one code, a recovery code is half of a new password.
    if refused := refuse_without_both_factors():
        return refused
    return render_template("recovery_code.html", code=new_recovery_code(g.user.id), first=False)


@bp.route("/2fa/qr.svg")
def qr_2fa():
    # Only while the setup runs; after that the secret can no longer be requested.
    user = query("SELECT username, totp_secret FROM users WHERE id = %s AND NOT totp_enabled", (g.user.id,), one=True)
    if not (user and user.totp_secret):
        abort(404)
    svg = io.BytesIO()
    segno.make(totp.provisioning_uri(user.totp_secret, user.username), error="m").save(svg, kind="svg", scale=6, border=2)
    return Response(svg.getvalue(), mimetype="image/svg+xml")


# Set up again for a new phone
@bp.route("/2fa/reset", methods=["POST"])
def reset_2fa():
    # Password and code
    if refused := refuse_without_both_factors():
        return refused
    keep_this_session(query(
        "UPDATE users SET totp_secret = NULL, totp_enabled = false, totp_last_step = NULL, recovery_hash = NULL,"
        " session_version = session_version + 1 WHERE id = %s RETURNING session_version",
        (g.user.id,), one=True,
    ))
    flash("Set up two-step verification again with your new phone.")
    return redirect(url_for("account.setup_2fa"))


# Ask again for the current password and a code from the app
def refuse_without_both_factors():
    reauth_limit = throttle.limit("reauth_account", g.user.id)
    if minutes := throttle.attempt(reauth_limit):
        return render_account(throttle.message(minutes), *throttle.refusal(minutes))
    if not passwords.is_current(g.user.id, request.form.get("current_password", "")):
        return render_account("Your current password is incorrect.", 400)
    throttle.succeeded(reauth_limit)
    # Then the second factor,
    if error := check_code(g.user.id):
        return render_account(error.message, *throttle.refusal(error.minutes))
    return None


@bp.route("/password", methods=["POST"])
def change_password():
    password = request.form.get("password", "")
    if error := passwords.password_problem(password, request.form.get("password_repeat", "")):
        return render_account(error, 400)
    if refused := refuse_without_both_factors():
        return refused

    # All other sessions expire
    keep_this_session(query(
        "UPDATE users SET password = %s, session_version = session_version + 1 WHERE id = %s RETURNING session_version",
        (password, g.user.id), one=True,
    ))
    flash("Your password has been changed.")
    return redirect(url_for("account.index"))


@bp.route("/delete", methods=["POST"])
def delete_account():
    if refused := refuse_without_both_factors():
        return refused
    # The notes go along through ON DELETE CASCADE; other sessions expire through load_user.
    query("DELETE FROM users WHERE id = %s", (g.user.id,))
    session.clear()
    flash("Your account and your notes have been deleted.")
    return redirect(url_for("auth.login"))
