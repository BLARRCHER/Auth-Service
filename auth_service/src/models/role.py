import uuid
from enum import Enum

from sqlalchemy.dialects.postgresql import UUID

from src.db.db import db


class RoleShortName(Enum):
    GUEST = 'guest'
    USER = 'user'
    EDITOR = 'editor'
    ADMIN = 'admin'


class RoleUser(db.Model):
    user_id = db.Column(db.ForeignKey('user.id'), primary_key=True)
    role_id = db.Column(db.ForeignKey('role.id'), primary_key=True)

    active = db.Column(db.BOOLEAN, default=True)
    end_date = db.Column(db.DateTime)

    role = db.relationship('Role', viewonly=True)
    user = db.relationship('User', viewonly=True)


class RolePermission(db.Model):
    role_id = db.Column(db.ForeignKey('role.id'), primary_key=True)
    permission_id = db.Column(db.ForeignKey('permission.id'), primary_key=True)

    role = db.relationship('Role', viewonly=True)
    permission = db.relationship('Permission', viewonly=True)


class Role(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
                   unique=True, nullable=False)
    name = db.Column(db.VARCHAR(250), unique=True)
    short_name = db.Column(db.VARCHAR(20), unique=True, nullable=False)
    description = db.Column(db.VARCHAR(250))

    users = db.relationship('User', secondary='role_user',
                            back_populates='roles')
    permissions = db.relationship('Permission', secondary='role_permission',
                                  back_populates='roles')

    def to_json(self) -> dict:
        return {
            'id': self.id,
            'short_name': self.short_name,
            'name': self.name,
            'description': self.description,
            'permissions': [permission.to_json() for permission in
                            self.permissions] if self.permissions else [],
        }

    @classmethod
    def list_to_json(cls, roles: list) -> list['Role']:
        if roles:
            return [role.to_json() for role in roles]
        else:
            return []
