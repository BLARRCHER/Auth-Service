from dataclasses import dataclass
from typing import ClassVar
from uuid import UUID

import pytest
import redis
from flask_jwt_extended import decode_token

from main_app import create_app
from src.models.role import Role
from src.core.settings import pg_settings, redis_settings
from src.models.user import User
from src.services.pwd_mgr import BCryptPwdMgr
from src.db.db import db as database
from tests.functional.src.testdata import TEST_DB, USER1_SIGNUP_CRED, \
    user1_access_token, user1_refresh_token

db_url = f'postgresql://' \
         f'{pg_settings.user}:{pg_settings.password}@' \
         f'{pg_settings.host}/{TEST_DB}'

database.url = db_url


@pytest.fixture(scope='session')
def app():
    app = create_app()
    return app


@pytest.fixture
def db(app, client, request):
    database.drop_all()
    database.create_all()
    database.session.commit()

    def fin():
        database.session.remove()

    request.addfinalizer(fin)
    return database


@pytest.fixture
def db_user(db):
    test_user = USER1_SIGNUP_CRED
    role = Role(id=UUID('cb3cbeba-5240-4a2a-8d2f-28ba4e1c8d57'),
                name='create_test',
                short_name='admin',
                description='descr')
    db.session.add(role)
    db.session.commit()
    role = db.session.query(Role).filter_by(short_name='admin').one_or_none()
    user = User(
        id=UUID('81befadf-ff5f-4246-808e-490739da472e'),
        login=test_user.login,
        password=BCryptPwdMgr().hash_password(test_user.password),
        roles=[role]
    )
    db.session.add(user)
    db.session.commit()

    return user


@pytest.fixture(scope='session')
def redis_client():
    r = redis.from_url(
        f"redis://{redis_settings.host}:{redis_settings.port}")
    yield r
    r.close()
    r.connection_pool.disconnect()


@pytest.fixture()
def clear_redis_cache(redis_client):
    yield redis_client
    redis_client.flushall()


@dataclass
class UserAuth:
    jwt_prefix: ClassVar[str] = 'Bearer '

    login: str
    access_token: str
    refresh_token: str
    decoded_token: dict | None = None

    @classmethod
    def decode(cls, token: str):
        return decode_token(token, allow_expired=True)

    def __post_init__(self):
        self.decoded_token = self.decode(self.access_token)

        self.access_token = self.jwt_prefix + self.access_token
        self.refresh_token = self.jwt_prefix + self.refresh_token


@pytest.fixture
def user1_auth():
    return UserAuth(
        login=USER1_SIGNUP_CRED.login,
        access_token=user1_access_token.strip(),
        refresh_token=user1_refresh_token.strip()
    )
