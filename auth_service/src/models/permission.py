import uuid

from sqlalchemy.dialects.postgresql import UUID

from src.db.db import db


class Permission(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
                   unique=True, nullable=False)
    name = db.Column(db.VARCHAR(250), unique=True)
    short_name = db.Column(db.VARCHAR(20), unique=True, nullable=False)
    description = db.Column(db.VARCHAR(250))

    roles = db.relationship('Role', secondary='role_permission',
                            back_populates='permissions')

    def to_json(self) -> dict:
        return {
            'id': self.id,
            'shortName': self.short_name,
            'name': self.name,
            'description': self.description
        }
