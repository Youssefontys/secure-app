# Notes: create, show, edit and delete.

from flask import Blueprint, abort, g, redirect, render_template, request, url_for

import encryption
from db import query

bp = Blueprint("notes", __name__)

# What is shown if a title or body does not decrypt (changed, moved or another key).
UNREADABLE = "(unreadable)"


@bp.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        title, body, error = read_note_form()
        if error:
            return render_template("notes.html", notes=fetch_notes(), error=error, title=title, body=body), 400
        query("INSERT INTO notes (user_id, title, body) VALUES (%s, %s, %s)", (g.user.id, *sealed(title, body)))
        return redirect(url_for("notes.index"))

    return render_template("notes.html", notes=fetch_notes())


# Title and body from the form, plus an error message if one is empty. 
def read_note_form():
    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    error = None if title and body else "Enter a title and a note."
    return title, body, error


def fetch_notes():
    rows = query(
        "SELECT id, title, body, created_at, updated_at FROM notes WHERE user_id = %s ORDER BY created_at DESC",
        (g.user.id,),
    )
    return [readable(note) for note in rows]


# Title and body are only stored encrypted in the database, bound to the owner (MIT-18).
def sealed(title, body):
    return encryption.encrypt(title, "note_title", g.user.id), encryption.encrypt(body, "note_body", g.user.id)


# Decrypted for the page; what does not decrypt does not count as text of the user.
def readable(note):
    title = encryption.decrypt(note.title, "note_title", g.user.id)
    body = encryption.decrypt(note.body, "note_body", g.user.id)
    return note._replace(title=title or UNREADABLE, body=body or UNREADABLE)


# The note of the logged-in user, otherwise 404: someone else's note also seems not to exist (MIT-15).
def own_note(note_id):
    note = query("SELECT id, title, body FROM notes WHERE id = %s AND user_id = %s", (note_id, g.user.id), one=True)
    if note is None:
        abort(404)
    return readable(note)


@bp.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
def edit_note(note_id):
    note = own_note(note_id)
    if request.method != "POST":
        return render_template("edit_note.html", title=note.title, body=note.body)

    title, body, error = read_note_form()
    if error:
        return render_template("edit_note.html", title=title, body=body, error=error), 400
    query(
        "UPDATE notes SET title = %s, body = %s, updated_at = now() WHERE id = %s AND user_id = %s",
        (*sealed(title, body), note_id, g.user.id),
    )
    return redirect(url_for("notes.index"))


@bp.route("/notes/<int:note_id>/delete", methods=["POST"])
def delete_note(note_id):
    # Only the own note; someone else's note gives 404, as with editing (MIT-15).
    if query("DELETE FROM notes WHERE id = %s AND user_id = %s RETURNING id", (note_id, g.user.id), one=True) is None:
        abort(404)
    return redirect(url_for("notes.index"))
