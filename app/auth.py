# Registering, logging in and logging out, and who is logged in.

from functools import wraps

import psycopg
from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for

from db import query

bp = Blueprint("auth", __name__)


# Puts the logged-in user in g.user, once per request.
@bp.before_app_request
def load_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id is not None and request.endpoint != "static":
        g.user = query("SELECT id, username FROM users WHERE id = %s", (user_id,), one=True)


# Only for a logged-in user. 
def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapper


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
    try:
        # Baseline: any password, also "1", stored as plain text.
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
    # Baseline: compared as plain text, the password is the only factor, and guessing has no limit.
    row = query("SELECT id FROM users WHERE username = %s AND password = %s", (username, password), one=True)
    if row is None:
        return render_template("auth.html", error="Incorrect username or password."), 400

    session.clear()
    session["user_id"] = row.id
    return redirect(url_for("notes.index"))


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
