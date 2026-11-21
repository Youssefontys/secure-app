# CSRF token per session (MIT-20): every form sends it along, and another site does not know it (MC-05).

import hmac
import secrets

from flask import render_template, request, session

import events

# What the visitor sees if the token is missing or wrong.
REFUSED = "This form did not come from this site, or the page was too old. Reload the page and try again."


# The token of this session; the templates put it in every form.
def token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


# Every POST without the right token is refused, even if the browser sends the cookie along.
def check():
    if request.endpoint == "static":
        return None
    expected = token()
    if request.method == "POST":
        # Fetch Metadata (MC-05): a modern browser says so itself, before the token is even read. Sec-Fetch-Site is
        # missing for an older browser or a script, so fall back to Origin; both missing is not a browser calling
        # cross-site, so that is left to the token, which is only read if the request did not come from another site.
        site = request.headers.get("Sec-Fetch-Site")
        origin = request.headers.get("Origin")
        cross_site = site == "cross-site" or (site is None and origin is not None and origin != request.url_root.rstrip("/"))
        if cross_site or not hmac.compare_digest(request.form.get("csrf_token", "").encode(), expected.encode()):
            events.event("csrf_refused", endpoint=request.endpoint)
            return render_template("error.html", code=400, message=REFUSED), 400
    return None
