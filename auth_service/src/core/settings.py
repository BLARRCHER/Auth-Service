import os
from logging import config as logging_config

from pydantic import BaseSettings

from .logger import LOGGING

logging_config.dictConfig(LOGGING)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class PostgresSettings(BaseSettings):
    """ Настройки подключения к Postgres. """
    host: str = '127.0.0.1'
    port: int = 5432
    user: str = 'app'
    password: str = '123qwe'
    db: str = 'auth'

    class Config:
        env_prefix = 'POSTGRES_'


class RedisSettings(BaseSettings):
    """ Настройки подключения к Redis. """
    host: str = '127.0.0.1'
    port: int = 6379
    TTL: int = 300

    class Config:
        env_prefix = 'REDIS_'


class AppSettings(BaseSettings):
    """ Настройки приложения. """
    gevent_workers: int = 1
    debug: int = 1
    port: int = 3000
    host: str = '127.0.0.1'

    class Config:
        env_prefix = 'APP'


class JWTSettings(BaseSettings):
    secret_key: str = 'c9ee8603-2a2e-4956-91c6-62438b801855'
    access_token_expires: int = 10  # в минутах
    refresh_token_expires: int = 15  # в минутах
    token_expires: bool = False

    class Config:
        env_prefix = 'JWT'


redis_settings = RedisSettings()
pg_settings = PostgresSettings()
app_settings = AppSettings()
jwt_settings = JWTSettings()
