from gevent import monkey

monkey.patch_all()

from main_app import app
