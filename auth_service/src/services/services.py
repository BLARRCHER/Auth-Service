import logging
from functools import lru_cache, wraps

from flask_jwt_extended import (create_access_token, create_refresh_token,
                                get_jti, get_jwt_identity)
from werkzeug.exceptions import BadRequest

from src.core.settings import jwt_settings
from src.db.base import BaseDBService
from src.db.dto import ChangePasswordDTO, SignUpDTO
from src.models.role import Role, RoleUser
from src.models.user import User, UserAuth
from src.services.pwd_mgr import ABCPwdMgr, BCryptPwdMgr

logger = logging.getLogger()


class UserFoundError(Exception):
    pass


class UserNotFoundError(Exception):
    pass


class InvalidPasswordError(Exception):
    pass


class RoleFoundError(Exception):
    pass


class RoleNotFoundError(Exception):
    pass


class UserService:
    def __init__(self, bd_service: BaseDBService, pwd_mgr: ABCPwdMgr):
        self.service = bd_service
        self.pwd_mgr = pwd_mgr
        self.model = self.service.model

    def signup(self, signup_dto: SignUpDTO):
        try:
            return self.create_user(signup_dto)
        except BadRequest:
            raise UserFoundError

    def create_user(self, signup_dto: SignUpDTO):
        try:
            user = self.model(
                login=signup_dto.login,
                password=self.pwd_mgr.hash_password(signup_dto.password)
            )
            self.service.add(user)
        except BadRequest:
            raise UserFoundError
        else:
            return user

    def get_user_or_404(self, value: str):
        user = self.service.get_by_unique(login=value)
        if user is None:
            raise UserNotFoundError
        return user

    def check_user(self, login: str, password: str):
        user = self.get_user_or_404(login)
        if not self.pwd_mgr.check_pwd(user.password, password):
            raise InvalidPasswordError
        return user

    def login_user(
            self, user: User, remote_addr: str, user_agent: str
    ):
        user.auth_history.append(UserAuth(
            user_id=user.id,
            ip_address=remote_addr,
            user_agent=user_agent))
        self.service.commit()
        return user

    def change_password(self, login: str, dto: ChangePasswordDTO):
        user = self.check_user(login, dto.old_password)
        user.password = self.pwd_mgr.hash_password(dto.new_password)
        self.service.commit()

    def get_auth_history(self, login: str):
        user = self.get_user_or_404(login)
        return user.auth_history


class RoleUserService:
    def __init__(self, bd_service: BaseDBService):
        self.service = bd_service
        self.model = self.service.model


class RoleUserAccessService:
    @classmethod
    def set(cls, user_id: str, role_id: str, active: bool, force: bool) -> str:
        user = get_user_service().service.get_by_unique(id=user_id)
        if not user:
            raise ValueError('Пользователь не найден!')

        role = RoleService(BaseDBService(Role)).service.get_by_unique(
            id=role_id)
        if not role:
            raise ValueError('Роль не найдена!')

        role_user = RoleUserService(
            BaseDBService(RoleUser)).service.get_by_unique(role_id=role_id,
                                                           user_id=user_id)
        if (not role_user) or (role not in user.roles):
            message = 'У данного пользователя указанная роль не найдена!'
            if force:
                logger.info(
                    f'Запрос установить пользователю '
                    f'{user.login} роль - "{role.name}"')
                user.roles.append(role)
                if not BaseDBService(User).edit(user):
                    logger.info(
                        f'Пользователю {user.login} успешно '
                        f'установлена роль {role.name}')
                    role_user = RoleUserService(
                        BaseDBService(RoleUser)).service.get_by_unique(role_id=role_id,
                                                                       user_id=user_id)
            else:
                return message

        logger.info(
            f'Запрос установить пользователю {user.login} '
            f'для роли "{role.name}": active={active}.')

        if active:
            message = cls.set_active(True, role_user)
            return message
        else:
            return cls.set_active(False, role_user)

    @classmethod
    def set_active(cls, active: bool, role_user: RoleUser) -> str:
        if active:
            message = f'Роль "{role_user.role.name}" разблокирована.'
        else:
            if not role_user.active:
                return 'Роль была заблокирована.'
            message = f'Блокировка роли "{role_user.role.name}" установлена.'

        role_user.active = active
        RoleUserService(BaseDBService(RoleUser)).service.edit(role_user)

        logger.info(message)
        return message


class RoleService:
    def __init__(self, bd_service: BaseDBService):
        self.service = bd_service
        self.model = self.service.model

    def find_all_roles_in_list(self, roles_id_list: list) -> list:
        return self.model.query.filter(Role.id.in_(roles_id_list)).all()

    def get_all_roles(self):
        return self.service.get_all()

    def create_role(self, **data):
        try:
            self.service.add(Role(**data))
        except BadRequest as error:  # Нужно добавить конкретный exception
            logger.warning(
                f'Не удалось добавить роль - {data}; причина - {error}')
            raise RoleFoundError

    def delete_roles_from_list(self, roles_id: list[str]):
        instance_list = self.model.query.filter(Role.id.in_(roles_id)).all()
        if not instance_list:
            raise RoleNotFoundError
        for instance in instance_list:  # Надо добавить обработку
            # исключения на внешний ключ, если эта роль есть у кого-то
            try:
                self.service.delete(instance)
            except Exception as error:
                logger.warning(
                    f'Не удалось удалить роль - {instance}; причина - {error}')

    def update_role(self, role: Role):
        return 'Редактирование прошло успешно' if not self.service.edit(
            role) else 'Произошла ошибка'


def gen_tokens(uid: str):
    is_expiring = False if not jwt_settings.token_expires else None
    refresh_token = create_refresh_token(identity=uid, expires_delta=is_expiring)
    access_token = create_access_token(identity=uid, additional_claims={
        'refresh_jti': get_jti(refresh_token)}, expires_delta=is_expiring)
    return access_token, refresh_token


def check_permissions(
        *roles_short_names: str):  # Можно и не передавать текущего
    # пользователя, но кажется в декораторе не лучшая практика его опознавать.
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            current_user = get_user_service().service.get_by_unique(
                login=get_jwt_identity())
            user_roles = RoleUserService(
                BaseDBService(RoleUser)).service.get_query_by_fields(
                user_id=current_user.id)  # Пока не трогаю permissions,
            # они пригодятся когда будем разбирать подписки
            if set(roles_short_names).intersection(
                    {user_role.role.short_name for user_role in user_roles}
            ):
                return func(*args, **kwargs)
            else:
                message = 'Авторизация не пройдена!'
                logger.warning(
                    f'{message} Метод "{func.__name__}" не выполнен!')
                raise PermissionError(message)

        return wrapper

    return decorator


@lru_cache()
def get_user_service():
    return UserService(BaseDBService(User), BCryptPwdMgr())


@lru_cache()
def get_role_user_service():
    return RoleUserService(BaseDBService(RoleUser))


def get_role_service():
    return RoleService(BaseDBService(Role))


def get_role_user_access_service():
    return RoleUserAccessService()
