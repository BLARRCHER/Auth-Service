from enum import Enum


class RoleErrors(str, Enum):
    ROLE_IS_ALREADY_EXISTS = 'role is already exists'
    INVALID_ROLE = 'invalid role'
    ROLE_NOT_FOUND = 'role not found'
