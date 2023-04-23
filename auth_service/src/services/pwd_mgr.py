from abc import ABC, abstractmethod

from flask import Flask
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)


class ABCPwdMgr(ABC):

    @abstractmethod
    def gen_salt(self):
        pass

    @abstractmethod
    def hash_password(self, password: str):
        pass

    @abstractmethod
    def check_pwd(self, hashed: str, password: str):
        pass


class BCryptPwdMgr(ABCPwdMgr):

    def gen_salt(self):
        return ''

    def hash_password(self, password: str):
        return bcrypt.generate_password_hash(password).decode('utf-8')

    def check_pwd(self, hashed: str, password: str):
        return bcrypt.check_password_hash(hashed, password)
