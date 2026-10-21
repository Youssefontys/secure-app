# Creates the Flask app and attaches auth, account and notes to it.

import os
from datetime import datetime
from zoneinfo import ZoneInfo

from flask import Flask

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


@app.template_filter("date")
def format_date(value, with_time=True):
    return value.strftime("%d-%m-%Y %H:%M" if with_time else "%d-%m-%Y")


# Per block of six hours, in Dutch time.
@app.template_global()
def greeting():
    return ("Hello", "Good morning", "Good afternoon", "Good evening")[datetime.now(ZoneInfo(TIMEZONE)).hour // 6]
