from datetime import datetime

import orjson
from pydantic import BaseModel, Field

from src.models.user import User, UserAuth


def orjson_dumps(v, *, default):
    return orjson.dumps(v, default=default).decode()


class ORJSONModel(BaseModel):
    class Config:
        json_loads = orjson.loads
        json_dumps = orjson_dumps


class BaseDTO(ORJSONModel):

    @classmethod
    def from_json(cls, raw_data):
        try:
            msg = orjson.loads(raw_data)
        except orjson.JSONDecodeError as e:
            raise ValueError('Message decoding error') from e
        return cls(**msg)


class SignUpDTO(BaseDTO):
    login: str = Field(min_length=3)
    password: str = Field(min_length=5)


class UserDTO(BaseDTO):
    login: str = Field(min_length=3)

    @classmethod
    def from_db(cls, user: User):
        return cls(login=user.login)


class LoginDTO(BaseDTO):
    login: str = Field(min_length=3)
    password: str = Field(min_length=5)


class TokenResponseDTO(BaseDTO):
    access_token: str
    refresh_token: str


class ChangePasswordDTO(BaseDTO):
    old_password: str = Field(min_length=3)
    new_password: str = Field(min_length=5)


class UserAuthDTO(BaseDTO):
    ip_address: str
    user_agent: str
    date: datetime
    platform: None | str = None
    browser: None | str = None

    @classmethod
    def from_db(cls, auth: UserAuth):
        return cls(
            ip_address=auth.ip_address,
            user_agent=auth.user_agent,
            date=auth.date,
            platform=auth.platform,
            browser=auth.browser
        )


class Message(BaseDTO):
    text: str


class AccessTokenDTO(BaseDTO):
    access_token: str


AuthHistoryDto = list[UserAuthDTO]
