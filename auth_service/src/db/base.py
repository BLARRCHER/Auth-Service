from typing import List

from flask import current_app
from flask_sqlalchemy import BaseQuery
from sqlalchemy import func, text
from sqlalchemy.exc import DataError, IntegrityError, SQLAlchemyError
from werkzeug.exceptions import BadRequest

from .db import db


def do_sql_with_try(function):
    def inner(self, *args, **kwargs):
        try:
            return function(self, *args, **kwargs)
        except DataError:
            return self.abort('Неверное значение или тип!')
        except IntegrityError as err:
            err_text = err.args[0].split('DETAIL:')[1].strip()
            if 'already exists.' in err_text:
                field = err_text.replace('Key', '').replace('already exists.',
                                                            '')
                message = f'{field}: введенное значение уже существует!'.strip()
            else:
                message = err_text
            return self.abort(
                message=message,
                log_message='Метод "{}" не выполнен! {}: {}'.format(
                    function.__name__, self.model, err),
            )
        except SQLAlchemyError as err:
            return self.abort(
                message='Не выполнено!',
                log_message='Метод "{}" не выполнен! {}: {}'.format(
                    function.__name__, self.model, err),
            )

    return inner


class BaseDBService:
    def __init__(self, model: db.Model):
        self.model = model

    @staticmethod
    def abort(message: str, log_message: str = None):
        db.session.rollback()
        log = log_message or message
        current_app.logger.warning(log)
        raise BadRequest(description=message)

    @do_sql_with_try
    def add(self, instance: db.Model) -> None:
        db.session.add(instance)
        db.session.commit()

    @do_sql_with_try
    def add_from_list(self, instances: List[db.Model]) -> None:
        for instance in instances:
            db.session.add(instance)
        db.session.commit()

    @do_sql_with_try
    def edit(self, instance: db.Model) -> None:
        message = 'Редактирование не выполнено! {}: {}'
        if db.session.merge(instance) and not db.session.new:
            db.session.commit()
        else:
            return self.abort(message.format(self.model, instance.id))

    @do_sql_with_try
    def delete(self, instance: db.Model) -> None:
        db.session.delete(instance)
        db.session.commit()

    @do_sql_with_try
    def get_by_unique(self, **fields) -> db.Model:
        return db.session.query(self.model).filter_by(**fields).one_or_none()

    @do_sql_with_try
    def commit(self) -> None:
        db.session.commit()

    def get_all(self) -> List[db.Model]:
        return self.model.query.all()

    def get_by_fields(self, **fields) -> db.Model:
        return db.session.query(self.model).filter_by(**fields).all()

    @do_sql_with_try
    def get_query_by_fields(self, query=None, **fields) -> BaseQuery:
        query = query or db.session.query(self.model)
        return query.filter_by(**fields)

    @do_sql_with_try
    def find_query_with_filter(
            self, search_param: str, query: BaseQuery = None) -> BaseQuery:
        """Get a query using the filter"""
        query = query or self.model.query
        return query.filter(text(search_param))

    @do_sql_with_try
    def get_sorted_query(self, query: BaseQuery, condition: str) -> BaseQuery:
        """Sort the query according to the condition"""
        return query.order_by(text(condition))

    @do_sql_with_try
    def get_a_paginate_query(self, query: BaseQuery, page: int,
                             size: int) -> BaseQuery:
        """Apply pagination to the query"""
        return query.paginate(page, size, error_out=False)

    def count_all(self) -> int:
        count = db.session.query(func.count(self.model.id)).one_or_none()
        return count[0] if count else 0
