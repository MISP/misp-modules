from flask_wtf import FlaskForm
from wtforms.fields import (
    StringField,
    SubmitField,
)
from wtforms.validators import InputRequired, Length


class ExternalToolForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(1, 64)])
    url = StringField('Url', validators=[InputRequired()])
    api_key = StringField('API key', validators=[InputRequired(), Length(1, 60)])
    submit = SubmitField('Create')