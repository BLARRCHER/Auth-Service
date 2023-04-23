import os

from src.core.settings import BASE_DIR
from src.db.dto import ChangePasswordDTO, LoginDTO, SignUpDTO
from src.models.role import Role

TEST_BASE_DIR = os.path.join(BASE_DIR, '../tests/functional/src')
RESOURCE_DIR = os.path.join(TEST_BASE_DIR, 'resources')

TEST_DB = 'test_db'

TEST_LOGIN = 'TestLogin'
TEST_PASSWORD = 'password'
WRONG_PASSWORD = 'wrong_password'
NEW_PASSWORD = 'new_password'

USER1_SIGNUP_CRED = SignUpDTO(login=TEST_LOGIN, password=TEST_PASSWORD)

USER1_LOGIN_CREDS = LoginDTO(login=TEST_LOGIN, password=TEST_PASSWORD)
USER1_LOGIN_CRED_WRONG_PWD = LoginDTO(login=TEST_LOGIN,
                                      password=WRONG_PASSWORD)

USER1_CHANGE_PWD = ChangePasswordDTO(
    old_password=USER1_LOGIN_CREDS.password,
    new_password=NEW_PASSWORD
)

USER1_CHANGE_PWD_WITH_WRONG_OLD_PWD = ChangePasswordDTO(
    old_password=WRONG_PASSWORD,
    new_password=NEW_PASSWORD
)

ROLE = dict(id='6e03c486-4942-4eed-af7b-74f385182880', name='Test', short_name='Test', description='Test')
ROLES_LIST = [dict(id='6e03c486-4942-4eed-af7b-74f385182880', permissions=[], name='Test', short_name='Test', description='Test'),
              dict(id='cb3cbeba-5240-4a2a-8d2f-28ba4e1c8d57', permissions=[], name='create_test', short_name='admin', desctiption='descr')]
ROLE_EDIT = dict(id='6e03c486-4942-4eed-af7b-74f385182880', name='Edit', short_name='Edit', description='Edit')
ROLE_SET = {'active': False, 'user_id': '81befadf-ff5f-4246-808e-490739da472e', 'role_id': 'cb3cbeba-5240-4a2a-8d2f-28ba4e1c8d57', 'force': False}
ROLE_SET_FORCE = {'active': True, 'user_id': '81befadf-ff5f-4246-808e-490739da472e', 'role_id': 'cb3cbeba-5240-4a2a-8d2f-28ba4e1c8d57', 'force': True}
ROLE_DELETE = ['6e03c486-4942-4eed-af7b-74f385182880']

with open(
        os.path.join(RESOURCE_DIR, 'user1.expired.access.token')
) as f:
    user1_expired_access_token = f.read()

with open(
        os.path.join(RESOURCE_DIR, 'user1.expired.refresh.token')
) as f:
    user1_expired_refresh_token = f.read()

with open(
        os.path.join(RESOURCE_DIR, 'user1.access.token')
) as f:
    user1_access_token = f.read()

with open(
        os.path.join(RESOURCE_DIR, 'user1.refresh.token')
) as f:
    user1_refresh_token = f.read()
