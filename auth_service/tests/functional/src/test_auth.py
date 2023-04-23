from http import HTTPStatus

from flask import url_for
from tests.functional.src.testdata import (USER1_CHANGE_PWD,
                                           USER1_CHANGE_PWD_WITH_WRONG_OLD_PWD,
                                           USER1_LOGIN_CRED_WRONG_PWD,
                                           USER1_LOGIN_CREDS,
                                           USER1_SIGNUP_CRED,
                                           user1_expired_access_token)

from src.api.v1.auth.auth_errors import AuthErrors
from src.db.dto import AccessTokenDTO, TokenResponseDTO, UserDTO
from src.services.pwd_mgr import BCryptPwdMgr
from src.services.services import get_user_service


def test_signup_success(client, db):
    res = client.post(url_for('auth.signup'), json=USER1_SIGNUP_CRED.dict())
    res_dto = UserDTO(**res.json)

    assert get_user_service().get_user_or_404(res_dto.login)
    assert res.status_code == HTTPStatus.OK


def test_signup_already_exists_error(client, db_user):
    res = client.post(url_for('auth.signup'), json=USER1_SIGNUP_CRED.dict())

    assert res.status_code == HTTPStatus.BAD_REQUEST
    assert AuthErrors.USER_IS_ALREADY_EXISTS.value in res.text


def test_login_success(client, db_user):
    res = client.post(url_for('auth.login'), json=USER1_LOGIN_CREDS.dict())

    assert res.status_code == HTTPStatus.OK
    assert TokenResponseDTO(**res.json)
    assert len(db_user.auth_history) == 1


def test_login_with_wrong_password(client, db_user):
    res = client.post(url_for('auth.login'),
                      json=USER1_LOGIN_CRED_WRONG_PWD.dict())

    assert res.status_code == HTTPStatus.BAD_REQUEST
    assert AuthErrors.INVALID_LOGIN_OR_PASSWORD.value in res.text


def test_logout(client, user1_auth, redis_client, clear_redis_cache):
    res = client.post(url_for('auth.logout'),
                      headers={'Authorization': user1_auth.access_token})

    assert res.status_code == HTTPStatus.OK
    assert redis_client.exists(user1_auth.decoded_token['jti'])
    assert redis_client.exists(user1_auth.decoded_token['refresh_jti'])


def test_user_access_with_expired_token(client):
    token = user1_expired_access_token.strip()
    res = client.post(url_for('auth.logout'),
                      headers={
                          'Authorization': 'Bearer ' + token})

    assert res.status_code == HTTPStatus.UNAUTHORIZED
    assert 'Token has expired' in res.text


def test_password_change(client, user1_auth, db_user):
    res = client.post(url_for('auth.change_password'),
                      headers={'Authorization': user1_auth.access_token},
                      json=USER1_CHANGE_PWD.dict())

    assert res.status_code == HTTPStatus.OK
    assert BCryptPwdMgr().check_pwd(db_user.password,
                                    USER1_CHANGE_PWD.new_password)


def test_password_change_with_wrong_pwd(client, user1_auth):
    res = client.post(url_for('auth.change_password'),
                      headers={'Authorization': user1_auth.access_token},
                      json=USER1_CHANGE_PWD_WITH_WRONG_OLD_PWD.dict())

    assert res.status_code == HTTPStatus.BAD_REQUEST
    assert AuthErrors.INVALID_OLD_PASSWORD.value in res.text


def test_refresh_token(client, user1_auth):
    res = client.post(url_for('auth.refresh'),
                      headers={'Authorization': user1_auth.refresh_token})
    access_token = AccessTokenDTO(**res.json)

    assert res.status_code == HTTPStatus.OK
    assert user1_auth.decode(access_token.access_token).get('jti')
