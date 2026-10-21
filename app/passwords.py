# The rule for a new password and the check of the current one: one place for all routes.

from db import query

# 12 to 64 characters
PASSWORD_MIN = 12
PASSWORD_MAX = 64


# The error message if the new password is not allowed, otherwise None; repeat only where the form repeats it.
def password_problem(password, repeat=None):
    if not PASSWORD_MIN <= len(password) <= PASSWORD_MAX:
        return f"Choose a password of {PASSWORD_MIN} to {PASSWORD_MAX} characters."
    if repeat is not None and password != repeat:
        return "The two passwords do not match."
    return None


# Is this the current password of this account?
def is_current(user_id, password):
    return query("SELECT 1 FROM users WHERE id = %s AND password = %s", (user_id, password), one=True) is not None
