from http import HTTPStatus

import redis
from flask import Blueprint, abort, jsonify, request
from flask_jwt_extended import (create_access_token, get_jwt, get_jwt_identity,
                                jwt_required)
from spectree import Response

from src.api import spec_v1
from src.api.v1.auth.auth_errors import AuthErrors
from src.core.settings import jwt_settings, redis_settings
from src.db.dto import (AccessTokenDTO, AuthHistoryDto, ChangePasswordDTO,
                        LoginDTO, Message, SignUpDTO, TokenResponseDTO,
                        UserAuthDTO, UserDTO)
from src.services.services import (InvalidPasswordError, UserFoundError,
                                   UserNotFoundError, UserService, gen_tokens,
                                   get_user_service)

jwt_redis_blocklist = redis.from_url(
    f"redis://{redis_settings.host}:{redis_settings.port}")

auth_app = Blueprint('auth', __name__)

user_service: UserService = get_user_service()


@auth_app.route('/signup', methods=['POST'])
@spec_v1.validate(
    json=SignUpDTO, resp=Response("HTTP_400", HTTP_200=UserDTO), tags=["auth"]
)
def signup():
    """
    SignUp user with login and password.
    ---
    definitions:
      login:
        type: string
      password:
        type: string
    responses:
      200:
        description: 'Регистрация пользователя'
        examples:
          {"login": "testLogin"}
    """
    signup_dto = SignUpDTO(**request.json)
    try:
        user = user_service.create_user(signup_dto)
    except UserFoundError:
        abort(HTTPStatus.BAD_REQUEST, AuthErrors.USER_IS_ALREADY_EXISTS.value)
    else:
        return jsonify(UserDTO.from_db(user).dict())


@auth_app.route('/login', methods=['POST'])
@spec_v1.validate(
    json=LoginDTO, resp=Response("HTTP_400", HTTP_200=TokenResponseDTO),
    tags=["auth"]
)
def login():
    """
    User login with password.
    ---
    definitions:
      login:
        type: string
      password:
        type: string
    responses:
      200:
        description: 'Вход в систему'
        examples:
          {"access_token": 'suhfiu345-12fnsdjk', "refresh_token": 'asdoivdf4-23fds8j34'}
    """
    try:
        login_dto = LoginDTO(**request.json)
        user = user_service.check_user(login_dto.login, login_dto.password)
    except (UserNotFoundError, InvalidPasswordError):
        abort(
            HTTPStatus.BAD_REQUEST, AuthErrors.INVALID_LOGIN_OR_PASSWORD.value)

    user_service.login_user(user, request.remote_addr, str(request.user_agent))

    access_token, refresh_token = gen_tokens(user.login)
    return jsonify(TokenResponseDTO(access_token=access_token,
                                    refresh_token=refresh_token).dict())


@auth_app.route("/logout", methods=["POST"])
@spec_v1.validate(
    resp=Response("HTTP_400", HTTP_200=Message),
    tags=["auth"], security={"Bearer": []},
)
@jwt_required()
def logout():
    """
    User logout.
    ---
    responses:
      200:
        description: 'Выход из системы'
        examples:
          '"sadndfgkj2354-24nfdsf" token successfully revoked'
    """
    token = get_jwt()
    jti = token['jti']
    ttype = token['type']

    jwt_redis_blocklist.set(jti, "", ex=jwt_settings.access_token_expires * 60)
    jwt_redis_blocklist.set(token['refresh_jti'], "",
                            ex=jwt_settings.refresh_token_expires * 60)
    return Message(text=f'{ttype.capitalize()} token successfully revoked')


@auth_app.route('/change_password', methods=['POST'])
@spec_v1.validate(
    json=ChangePasswordDTO, resp=Response("HTTP_400", HTTP_200=Message),
    tags=["auth"], security={"Bearer": []},
)
@jwt_required()
def change_password():
    """
    Password change for User.
    ---
    definitions:
      old_password:
        type: string
      new_password:
        type: string
    responses:
      200:
        description: 'Изменение пароля'
        examples:
          'password has been changed'
    """
    dto = ChangePasswordDTO(**request.json)
    try:
        user_service.change_password(login=get_jwt_identity(), dto=dto)
    except UserNotFoundError:
        abort(HTTPStatus.BAD_REQUEST, AuthErrors.INVALID_USER.value)
    except InvalidPasswordError:
        abort(HTTPStatus.BAD_REQUEST, AuthErrors.INVALID_OLD_PASSWORD.value)
    return Message(text='password has been changed')


@auth_app.route('/auth_history', methods=['GET'])
@spec_v1.validate(
    resp=Response("HTTP_400", HTTP_200=AuthHistoryDto), tags=["auth"],
    security={"Bearer": []},
)
@jwt_required()
def get_auth_history():
    """
    Get User auth history.
    ---
    responses:
      200:
        description: 'Получение истории входа'
        examples:
          {"ip_address": 192.168.0.1, "user_agent": "secret",
          "date": "20:00:20 10.03.2023", "browser": "Opera"}
    """
    try:
        history = user_service.get_auth_history(get_jwt_identity())
    except UserNotFoundError:
        abort(HTTPStatus.BAD_REQUEST, AuthErrors.INVALID_USER.value)
    else:
        return jsonify([UserAuthDTO.from_db(h).dict() for h in history])


@auth_app.route("/refresh", methods=["POST"])
@spec_v1.validate(
    resp=Response("HTTP_400", HTTP_200=AccessTokenDTO), tags=["auth"],
    security={"Bearer": []},
)
@jwt_required(refresh=True)
def refresh():
    """
    Refresh user access token by refresh token.
    ---
    definitions:
      refresh_token:
        type: string
    responses:
      200:
        description: 'Запрос на обновление access токена'
        examples:
          {"access_token": "asdasijd325-asdajsd35"}
    """
    access_token = create_access_token(identity=get_jwt_identity(),
                                       fresh=False)
    return AccessTokenDTO(access_token=access_token)
