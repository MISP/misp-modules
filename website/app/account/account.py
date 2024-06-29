from ..db_class.db import User
from flask import Blueprint, render_template, redirect, url_for, request, flash
from .form import LoginForm
from flask_login import (
    login_required,
    login_user,
    logout_user,
    current_user
)
from ..utils.utils import admin_password
from ..db_class.db import User
from .. import db

account_blueprint = Blueprint(
    'account',
    __name__,
    template_folder='templates',
    static_folder='static'
)

@account_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    """Log in an existing user."""
    form = LoginForm()
    if form.validate_on_submit():
        if form.password.data == str(admin_password()):
            user = User(email="admin@admin.admin")
            db.session.add(user)
            db.session.commit()
            login_user(user, form.remember_me.data)
            flash('You are now logged in. Welcome back!', 'success')
            return redirect(request.args.get('next') or "/")
        else:
            flash('Invalid password.', 'error')
    return render_template('account/login.html', form=form)

@account_blueprint.route('/logout')
@login_required
def logout():
    User.query.filter_by(id=current_user.id).delete()
    logout_user()

    flash('You have been logged out.', 'info')
    return redirect(url_for('home.home'))

