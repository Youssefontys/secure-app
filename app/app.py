# Creates the Flask app and attaches auth, account and notes to it.

import os
from datetime import datetime
from zoneinfo import ZoneInfo

from flask import Flask, render_template, request
from werkzeug.exceptions import HTTPException

import account
import auth
import notes
import passwords
from db import TIMEZONE, close_connection

# The website (HTML templates and static files) is in web/, apart from the code.
app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
# Flask signs the session cookie with this key.
app.secret_key = os.environ["FLASK_SECRET_KEY"]

for blueprint in (auth.bp, account.bp, notes.bp):
    app.register_blueprint(blueprint)
app.teardown_appcontext(close_connection)
app.jinja_env.globals.update(PASSWORD_MIN=passwords.PASSWORD_MIN, PASSWORD_MAX=passwords.PASSWORD_MAX)


# Short messages for the errors a visitor can cause.
HTTP_MESSAGES = {404: "This page does not exist.", 405: "That is not possible here."}


# Status and headers (such as Allow on 405) stay; only the page becomes the own error page.
@app.errorhandler(HTTPException)
def http_error(error):
    response = error.get_response()
    response.set_data(render_template("error.html", code=error.code, message=HTTP_MESSAGES.get(error.code, "That did not work.")))
    return response


# Fail safely (MIT-25): the visitor sees no details, the log does. %r, so a line break
# in the URL does not make a false log line (log injection).
@app.errorhandler(Exception)
def unexpected_error(error):
    app.logger.exception("Unexpected error at %s %r", request.method, request.path)
    return render_template("error.html", code=500, message="Something went wrong. Please try again later."), 500


@app.template_filter("date")
def format_date(value, with_time=True):
    return value.strftime("%d-%m-%Y %H:%M" if with_time else "%d-%m-%Y")


# Per block of six hours, in Dutch time.
@app.template_global()
def greeting():
    return ("Hello", "Good morning", "Good afternoon", "Good evening")[datetime.now(ZoneInfo(TIMEZONE)).hour // 6]
