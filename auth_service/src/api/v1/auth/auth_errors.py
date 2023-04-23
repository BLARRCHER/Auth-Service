from enum import Enum


class AuthErrors(str, Enum):
    USER_IS_ALREADY_EXISTS = 'user is already exists'
    INVALID_LOGIN_OR_PASSWORD = 'invalid login or password'
    INVALID_USER = 'invalid user'
    INVALID_OLD_PASSWORD = 'old password is invalid'
