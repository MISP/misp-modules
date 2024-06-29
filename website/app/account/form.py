from flask_wtf import FlaskForm
from wtforms.fields import (
    BooleanField,
    PasswordField,
    SubmitField
)
from wtforms.validators import InputRequired


class LoginForm(FlaskForm):
    password = PasswordField('Password', validators=[InputRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log in')
