#!/bin/bash

source venv/bin/activate
export FLASK_APP=app/main.py
flask db init
flask db migrate
flask db upgrade
exec gunicorn --chdir app main:app -b 0.0.0.0:5000 --log-level=debug

