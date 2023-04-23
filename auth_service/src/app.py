from datetime import timedelta

from flask import Flask
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from spectree.plugins.flask_plugin import FlaskPlugin

from flasgger import Swagger

from src.api import spec_v1
from src.api.v1.auth.handlers import auth_app, jwt_redis_blocklist
from src.api.v1.role import role_app
from src.core.settings import app_settings, jwt_settings
from src.db.db import db, init_db
from src.models.permission import *
from src.models.role import *
from src.models.user import *


def create_app():
    app = Flask(__name__)

    swagger = Swagger(app)

    app.config['JWT_SECRET_KEY'] = jwt_settings.secret_key

    if jwt_settings.token_expires:
        app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(
            minutes=jwt_settings.access_token_expires)
        app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(
            minutes=jwt_settings.refresh_token_expires)

    jwt = JWTManager(app)

    spec_flask_v1 = FlaskPlugin(spec_v1)

    @jwt.token_in_blocklist_loader
    def check_if_token_is_revoked(jwt_header, jwt_payload: dict):
        jti = jwt_payload["jti"]
        token_in_redis = jwt_redis_blocklist.get(jti)
        return token_in_redis is not None

    app.register_blueprint(auth_app, url_prefix='/api/v1/auth')
    app.register_blueprint(role_app, url_prefix='/api/v1/role')
    spec_flask_v1.register_route(app)

    init_db(app)
    Migrate(app, db)
    app.app_context().push()

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=app_settings.debug)
