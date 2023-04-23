from http import HTTPStatus
import copy
from uuid import UUID
from flask import url_for, jsonify

from src.models.role import Role
from src.db.dto import TokenResponseDTO
from src.services.services import get_role_service
from tests.functional.src.testdata import (ROLE, ROLE_EDIT, ROLES_LIST,
                                           ROLE_SET_FORCE, ROLE_SET,
                                           ROLE_DELETE, USER1_LOGIN_CREDS)


def test_create_role_success(client):
    access = client.post(url_for('auth.login'), json={"login": "TestLogin", "password": "new_password"})
    tokens = TokenResponseDTO(**access.json)
    res = client.post(url_for('role.create_role'), json=ROLE, headers={'Authorization': "Bearer " + tokens.access_token})
    roles = Role.list_to_json(get_role_service().get_all_roles())
    role = copy.deepcopy(ROLE)
    role.update(id=UUID(role['id']))
    role.update(permissions=[])

    assert role in roles
    assert res.status_code == HTTPStatus.OK


def test_get_roles_success(client):
    access = client.post(url_for('auth.login'), json={"login": "TestLogin", "password": "new_password"})
    tokens = TokenResponseDTO(**access.json)
    res = client.get(url_for('role.get_roles'), headers={'Authorization': "Bearer " + tokens.access_token})

    assert res.json is not None
    assert res.status_code == HTTPStatus.OK


def test_edit_role_success(client):
    access = client.post(url_for('auth.login'), json={"login": "TestLogin", "password": "new_password"})
    tokens = TokenResponseDTO(**access.json)
    res = client.put(url_for('role.edit_role'), json=ROLE_EDIT, headers={'Authorization': "Bearer " + tokens.access_token})

    assert res.json.get('message') == 'Редактирование прошло успешно'
    assert res.status_code == HTTPStatus.OK


def test_set_role_force_success(client):
    access = client.post(url_for('auth.login'), json={"login": "TestLogin", "password": "new_password"})
    tokens = TokenResponseDTO(**access.json)
    res = client.post(url_for('role.set_role'), json=ROLE_SET_FORCE, headers={'Authorization': "Bearer " + tokens.access_token})

    assert res.status_code == HTTPStatus.OK


def test_set_role_success(client):
    access = client.post(url_for('auth.login'), json={"login": "TestLogin", "password": "new_password"})
    tokens = TokenResponseDTO(**access.json)
    res = client.post(url_for('role.set_role'), json=ROLE_SET,  headers={'Authorization': "Bearer " + tokens.access_token})

    assert res.status_code == HTTPStatus.OK


def test_delete_role_success(client):
    access = client.post(url_for('auth.login'), json={"login": "TestLogin", "password": "new_password"})
    tokens = TokenResponseDTO(**access.json)
    res = client.delete(url_for('role.delete_role'), json={'ids': ROLE_DELETE}, headers={'Authorization': "Bearer " + tokens.access_token})
    roles = get_role_service().get_all_roles()

    assert res.json not in roles
    assert res.status_code == HTTPStatus.OK
