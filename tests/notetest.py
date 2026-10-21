"""Notes: creating, editing and deleting, and only on your own notes (MIT-15). Runs through securitytest.py."""
from securitytest import *


def run():
    print("== notes")
    a = account("testacc7")[0]
    check("note empty", req(a, "/", {"title": "", "body": ""})[0], 400)
    check("create", loc(req(a, "/", {"title": "Shopping", "body": "Bread and milk"})), "302 /")
    nid = re.search(r"notes/(\d+)/edit", req(a, "/")[1]).group(1)
    check("edit GET", req(a, f"/notes/{nid}/edit")[0], 200)
    check("edit empty", req(a, f"/notes/{nid}/edit", {"title": "", "body": ""})[0], 400)
    check("edit", loc(req(a, f"/notes/{nid}/edit", {"title": "T2", "body": "Changed"})), "302 /")
    check("edited visible", "edited" in req(a, "/")[1], True)
    cb = account("testacc8")[0]
    check("owner (MIT-15): testacc8 opens the note of testacc7", req(cb, f"/notes/{nid}/edit")[0], 404)
    check("  testacc8 edits the note of testacc7", req(cb, f"/notes/{nid}/edit", {"title": "x", "body": "y"})[0], 404)
    check("  testacc8 deletes the note of testacc7", req(cb, f"/notes/{nid}/delete", {})[0], 404)
    check("  the note of testacc7 unchanged", all(s in req(a, f"/notes/{nid}/edit")[1] for s in ("T2", "Changed")), True)
    check("  unknown id", req(a, "/notes/999999/edit")[0], 404)
    check("delete", loc(req(a, f"/notes/{nid}/delete", {})), "302 /")
    check("profile", req(a, "/account")[0], 200)
