import json
import uuid
from datetime import datetime

import pytz
from sqlalchemy.dialects.postgresql import UUID

from src.db.db import db


class User(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
                   unique=True, nullable=False)
    login = db.Column(db.VARCHAR(50), unique=True, nullable=False)

    password = db.Column(db.String(256), nullable=False)
    active = db.Column(db.BOOLEAN, default=True)

    created = db.Column(db.DateTime)
    modified = db.Column(db.DateTime, default=datetime.utcnow)

    is_authenticated = db.Column(db.BOOLEAN, default=False)
    is_active = db.Column(db.BOOLEAN, default=False)
    is_anonymous = db.Column(db.BOOLEAN, default=True)

    # relationships

    auth_history = db.relationship('UserAuth')
    roles = db.relationship('Role', secondary='role_user',
                            back_populates='users')

    def __repr__(self):
        return f'User: {self.id}: {self.login}'

    def to_json(self) -> dict:
        return {
            'id': self.id,
            'email': self.email,
            'login': self.login,
            'roles': [role.to_json() for role in self.roles]
            if self.roles else [],
            'auth_history': [auth.to_json() for auth in self.auth_history]
            if self.auth_history else [],
            'created': json.dumps(self.created.astimezone(pytz.UTC),
                                  default=str) if self.created else None,
            'modified': json.dumps(self.modified.astimezone(pytz.UTC),
                                   default=str) if self.modified else None,
        }


class UserAuth(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
                   unique=True, nullable=False)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('user.id'),
                        nullable=False)
    ip_address = db.Column(db.String(15))
    user_agent = db.Column(db.String(256))
    platform = db.Column(db.String(256), nullable=True)
    browser = db.Column(db.String(256), nullable=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def to_json(self) -> dict:
        return {
            'id': self.id,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'platform': self.platform,
            'browser': self.browser,
            'date': self.date,
        }
