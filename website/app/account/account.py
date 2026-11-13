from urllib.parse import urlsplit, urlunsplit

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app import db
from app.models import User
from app.utils import admin_password

from .form import LoginForm

account_blueprint = Blueprint(
    "account", __name__, template_folder="templates", static_folder="static"
)


def _safe_next_url(target):
    """Return a local path, or the home page for an unsafe login destination."""
    if (
        not target
        or target != target.strip()
        or "\\" in target
        or any(ord(char) < 32 or ord(char) == 127 for char in target)
    ):
        return "/"
    try:
        parsed = urlsplit(target)
    except ValueError:
        return "/"
    if (
        parsed.scheme not in ("", "http", "https")
        or (parsed.scheme and not parsed.netloc)
        or (parsed.netloc and parsed.netloc.lower() != request.host.lower())
        or (target.startswith("//") and not parsed.netloc)
    ):
        return "/"
    path = parsed.path or "/"
    if path.startswith("//"):
        return "/"
    # Strip accepted authorities and root relative paths so Location is always
    # local, including when a browser normalizes the redirect destination.
    if not path.startswith("/"):
        path = "/" + path
    return urlunsplit(("", "", path, parsed.query, parsed.fragment))


@account_blueprint.route("/login", methods=["GET", "POST"])
def login():
    """Log in an existing user."""
    form = LoginForm()
    if form.validate_on_submit():
        if form.password.data == str(admin_password()):
            user = User(
                email="admin@admin.admin", first_name="admin", last_name="admin"
            )
            db.session.add(user)
            db.session.commit()
            login_user(user, form.remember_me.data)
            flash("You are now logged in. Welcome back!", "success")
            return redirect(_safe_next_url(request.args.get("next")))
        else:
            flash("Invalid password.", "error")
    return render_template("account/login.html", form=form)


@account_blueprint.route("/logout")
@login_required
def logout():
    User.query.filter_by(id=current_user.id).delete()
    logout_user()

    flash("You have been logged out.", "info")
    return redirect(url_for("home.home"))
