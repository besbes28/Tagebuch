from datetime import date 
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from app.main import app

db = SQLAlchemy(app)

class Posts(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(255))
	content = db.Column(db.Text)
	date_posted = db.Column(db.DateTime, default=datetime.utcnow)
	slug = db.Column(db.String(255))
	poster_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class Users(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), nullable=False, unique=True)
	name = db.Column(db.String(200), nullable=False)
	email = db.Column(db.String(120), nullable=False, unique=True)
	favorite_color = db.Column(db.String(120))
	about_author = db.Column(db.Text(), nullable=True)
	date_added = db.Column(db.DateTime, default=datetime.utcnow)
	profile_pic = db.Column(db.String(), nullable=True)

	password_hash = db.Column(db.String(128))
	posts = db.relationship('Posts', backref='poster')


	@property
	def password(self):
		raise AttributeError('password is not a readable attribute!')

	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)

	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)

	def __repr__(self):
		return '<Name %r>' % self.name
