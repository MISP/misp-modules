from flask_wtf import FlaskForm
from wtforms import ValidationError
from wtforms.fields import (
    StringField,
    SubmitField,
    SelectMultipleField,
    TextAreaField,
    DateField,
    TimeField, 
    HiddenField,
    BooleanField
)
from wtforms.validators import InputRequired, Length, Optional

from ..db_class.db import Case, Case_Org


class CaseForm(FlaskForm):
    title = StringField('Title', validators=[Optional(), Length(1, 64)])
    description = TextAreaField('Description', validators=[Optional()])
    deadline_date = DateField('deadline_date', validators=[Optional()])
    deadline_time = TimeField("deadline_time", validators=[Optional()])
    template_select = SelectMultipleField(u'Templates', coerce=int)
    title_template = StringField('Title Template', validators=[Optional(), Length(1, 64)])
    tasks_templates = SelectMultipleField(u'Tasks Templates', coerce=int)
    submit = SubmitField('Create')

    def validate_title(self, field):
        if not field.data and 0 in self.template_select.data:
            raise ValidationError("Need to select a title or a template")
        if Case.query.filter_by(title=field.data).first():
            raise ValidationError("The title already exist")
        
    def validate_template_select(self, field):
        if 0 in field.data and not self.title.data:
            raise ValidationError("Need to select a template or a title")
        if not 0 in field.data and not self.title_template.data:
            raise ValidationError("Need a title for the case")
    
    def validate_deadline_time(self, field):
        if field.data and not self.deadline_date.data:
            raise ValidationError("Choose a date")
        
    def validate_title_template(self, field):
        if field.data and not self.template_select.data or 0 in self.template_select.data:
            raise ValidationError("A template need to be selected")
        if Case.query.filter_by(title=field.data).first():
            raise ValidationError("The title already exist")

class CaseEditForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(1, 64)])
    description = TextAreaField('Description', validators=[Optional()])
    deadline_date = DateField('deadline_date', validators=[Optional()])
    deadline_time = TimeField("deadline_time", validators=[Optional()])
    submit = SubmitField('Save')

    def validate_deadline_time(self, field):
        if field.data and not self.deadline_date.data:
            raise ValidationError("Choose a date")


class TaskForm(FlaskForm):
    title = StringField('Title', validators=[Optional(), Length(1, 64)])
    description = TextAreaField('Description', validators=[Optional()])
    url = StringField('Tool/Link', validators=[Optional(), Length(0, 64)])
    deadline_date = DateField('deadline_date', validators=[Optional()])
    deadline_time = TimeField("deadline_time", validators=[Optional()])
    template_select = SelectMultipleField(u'Templates', coerce=int)
    submit = SubmitField('Create')

    def validate_title(self, field):
        if not field.data and 0 in self.template_select.data:
            raise ValidationError("Need to select a title or a template")
        
    def validate_template_select(self, field):
        if 0 in field.data and not self.title.data:
            raise ValidationError("Need to select a template or a title")

    def validate_deadline_time(self, field):
        if field.data and not self.deadline_date.data:
            raise ValidationError("Choose a date")



class TaskEditForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(1, 64)])
    description = TextAreaField('Description', validators=[Optional()])
    url = StringField('Tool/Link', validators=[Optional(), Length(0, 64)])
    deadline_date = DateField('deadline_date', validators=[Optional()])
    deadline_time = TimeField("deadline_time", validators=[Optional()])
    submit = SubmitField('Save')

    def validate_deadline_time(self, field):
        if field.data and not self.deadline_date.data:
            raise ValidationError("Choose a date")


class AddOrgsCase(FlaskForm):
    org_id = SelectMultipleField(u'Orgs', coerce=int)
    case_id = HiddenField("")
    submit = SubmitField('Add')

    def validate_org_id(self, field):
        for org in field.data:
            if Case_Org.query.filter_by(case_id = self.case_id.data, org_id=org).first():
                raise ValidationError(f"Org {org} already in case")


class RecurringForm(FlaskForm):
    case_id = HiddenField("")
    once = DateField('One day', validators=[Optional()])
    daily = BooleanField('Daily', validators=[Optional()])
    weekly = DateField("Start date", validators=[Optional()])
    monthly = DateField("Start date", validators=[Optional()])
    remove = BooleanField('Remove', validators=[Optional()])
    submit = SubmitField('Save')
