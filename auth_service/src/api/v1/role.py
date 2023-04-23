from http import HTTPStatus

from flask import Blueprint, abort, jsonify, request
from flask_jwt_extended import jwt_required
from spectree import Response

from src.api import spec_v1
from src.api.v1.role_errors import RoleErrors
from src.db.dto import ChangePasswordDTO, TokenResponseDTO
from src.models.role import Role, RoleShortName
from src.services.services import (RoleFoundError, RoleNotFoundError,
                                   RoleService, RoleUserAccessService,
                                   RoleUserService, check_permissions,
                                   get_role_service,
                                   get_role_user_access_service,
                                   get_role_user_service)

role_app = Blueprint('role', __name__)

role_user_service: RoleUserService = get_role_user_service()
role_service: RoleService = get_role_service()
role_user_access_service: RoleUserAccessService = get_role_user_access_service()


@role_app.route('/create', methods=['POST'])
@jwt_required()
@check_permissions(RoleShortName.ADMIN.value)
def create_role():
    """
    Создание роли
    ---
    definitions:
      name:
        type: string
      short_name:
        type: string
      description:
        type: string
    responses:
      200:
        description: 'Успешное создание роли'
        examples:
          'Роль успешно создана'
    """
    role = request.json
    try:
        role = role_service.create_role(**role)
    except RoleFoundError:
        abort(HTTPStatus.BAD_REQUEST, RoleErrors.ROLE_IS_ALREADY_EXISTS.value)
    else:
        return jsonify(message='Роль успешно создана')


@role_app.route('/delete', methods=['DELETE'])
@jwt_required()
@check_permissions(RoleShortName.ADMIN.value)
def delete_role():
    """
    Удаление роли
    ---
    definitions:
      Roles:
        type: object
        properties:
          role_id:
            type: array
            items:
              $ref: '#/definitions/role'
      Role:
        type: string
    responses:
      200:
        description: 'Успешное удаление ролей'
        examples:
          'Роли успешно удалены'
    """
    role_id = request.json['ids']
    if not isinstance(role_id, list):
        return jsonify(
            message='Необходимо передать список uuid ролей, '
                    'которые необходимо удалить')
    try:
        role_service.delete_roles_from_list(role_id)
    except RoleNotFoundError:
        abort(
            HTTPStatus.BAD_REQUEST, RoleErrors.ROLE_NOT_FOUND.value)
    return jsonify(roles=role_id, message='Роли успешно удалены')


@role_app.route('/edit', methods=['PUT'])
@jwt_required()
@check_permissions(RoleShortName.ADMIN.value)
def edit_role():
    """
    Редактирование роли
    ---
    definitions:
      name:
        type: string
      short_name:
        type: string
      description:
        type: string
    responses:
      200:
        description: 'Успешное редактирование роли'
        examples:
          'Редактирование прошло успешно'
    """
    role = Role(**request.json)
    return jsonify(message=f'{role_service.update_role(role)}')


@role_app.route('/view', methods=['GET'])
@jwt_required()
@check_permissions(RoleShortName.ADMIN.value)
def get_roles():
    """
    Получить список ролей
    ---
    responses:
      200:
        description: 'Получение списка ролей'
        examples:
          [{name: '1', short_name: '1', description: '1', permissions:[]}]
    """
    roles = role_service.get_all_roles()
    return jsonify(Role.list_to_json(roles))


@role_app.route('/set', methods=['POST'])
@jwt_required()
@check_permissions(RoleShortName.ADMIN.value)
def set_role():
    """
    Отключить или добавить роль пользователю
    ---
    definitions:
      user_id:
        type: string
      role_id:
        type: string
      active:
        type: string
      force:
        type: string
    responses:
      200:
        description: 'Назначение роли'
        examples:
          'Изменения применены'
    """
    data = request.json
    if not data:
        return jsonify(message='Данные для запроса не найдены!')
    active = data.get('active')
    user_id = data.get('user_id')
    role_id = data.get('role_id')
    force = data.get('force')
    if active is None:
        return jsonify(message='Поле активности/блокировки обязательно!')
    if not isinstance(active, bool):
        return jsonify(
            message='Поле активности/блокировки '
                    'может содержать только значения True или False!')
    if force is None:
        return jsonify(message='Поле насильного добавления роли обязательно')
    if not isinstance(force, bool):
        return jsonify(
            message='Поле насильного добавления роли '
                    'может содержать только значения True или False!')
    info = role_user_access_service.set(user_id, role_id, active, force)
    return jsonify(message='Изменения применены', info=f'{info}')
