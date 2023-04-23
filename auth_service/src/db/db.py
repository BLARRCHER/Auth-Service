from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from src.core.settings import pg_settings

db_url = f'postgresql://' \
         f'{pg_settings.user}:{pg_settings.password}@' \
         f'{pg_settings.host}/{pg_settings.db}'

db = SQLAlchemy()


def init_db(app: Flask):
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    db.init_app(app)
