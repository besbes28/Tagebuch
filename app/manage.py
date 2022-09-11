from flask_migrate import Migrate
from app.main import app
from app.main import db

migrate = Migrate(app, db)
