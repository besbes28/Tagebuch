from flask_wtf import FlaskForm

from wtforms import StringField
from wtforms import SubmitField
from wtforms import PasswordField
from wtforms import BooleanField
from wtforms import ValidationError
from wtforms import TextAreaField

from wtforms.validators import DataRequired
from wtforms.validators import EqualTo
from wtforms.validators import Length

from wtforms.widgets import TextArea
from flask_ckeditor import CKEditorField
from flask_wtf.file import FileField


class SearchForm(FlaskForm):
    searched = StringField("Searched", validators=[DataRequired()])
    submit = SubmitField("Submit")


class LoginForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()])
	password = PasswordField("Password", validators=[DataRequired()])
	submit = SubmitField("Submit")


class PostForm(FlaskForm):
	title = StringField("Title", validators=[DataRequired()])
	content = CKEditorField('Content', validators=[DataRequired()])	
	slug = StringField("Slug", validators=[DataRequired()])
	submit = SubmitField("Submit")


class UserForm(FlaskForm):
	name = StringField("Name", validators=[DataRequired()])
	username = StringField("Username", validators=[DataRequired()])
	email = StringField("Email", validators=[DataRequired()])
	favorite_color = StringField("Favorite Color")
	about_author = TextAreaField("About Author")
	password_hash = PasswordField('Password', validators=[DataRequired(), EqualTo('password_hash2', message='Passwords Must Match!')])
	password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])
	profile_pic = FileField("Profile Pic")
	submit = SubmitField("Submit")


class PasswordForm(FlaskForm):
	email = StringField("What's Your Email", validators=[DataRequired()])
	password_hash = PasswordField("What's Your Password", validators=[DataRequired()])
	submit = SubmitField("Submit")
