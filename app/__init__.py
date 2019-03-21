#-*- coding=utf-8 -*-
from flask import Flask
from werkzeug.contrib.fixers import ProxyFix
from config import config
from extend import *


def create_app():
    app = Flask(__name__)
    app.config.from_object(config)
    config.init_app(app)
    app.wsgi_app = ProxyFix(app.wsgi_app)
    cache.init_app(app)
    limiter.init_app(app)

    from .front import front as front_blueprint
    app.register_blueprint(front_blueprint)

    from .admin import admin as admin_blueprint
    app.register_blueprint(admin_blueprint,url_prefix='/admin')

    return app


