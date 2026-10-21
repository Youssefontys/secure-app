# The own account: profile, changing the password, deleting the account.

from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for

from auth import login_required
from db import query

bp = Blueprint("account", __name__, url_prefix="/account")


@bp.route("")
@login_required
def index():
    return render_account()


# The profile page, always of the logged-in user themselves.
def render_account(error=None, status=200):
    profile = query(
        "SELECT username, created_at, (SELECT count(*) FROM notes WHERE user_id = users.id) AS note_count"
        " FROM users WHERE id = %s",
        (g.user.id,), one=True,
    )
    return render_template("account.html", profile=profile, error=error), status


@bp.route("/password", methods=["POST"])
@login_required
def change_password():
    password = request.form.get("password", "")
    if not password:
        return render_account("Enter a new password.", 400)
    if password != request.form.get("password_repeat", ""):
        return render_account("The two passwords do not match.", 400)
    query("UPDATE users SET password = %s WHERE id = %s", (password, g.user.id))
    flash("Your password has been changed.")
    return redirect(url_for("account.index"))


@bp.route("/delete", methods=["POST"])
@login_required
def delete_account():
    query("DELETE FROM users WHERE id = %s", (g.user.id,))
    session.clear()
    flash("Your account and your notes have been deleted.")
    return redirect(url_for("auth.login"))
