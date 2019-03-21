#-*- coding=utf-8 -*-
from self_config import *
import os
from datetime import timedelta
basedir = os.path.abspath(os.path.dirname(__file__))


class config:
    SECRET_KEY = os.path.join(config_dir,'PyOne'+password)
    CACHE_TYPE='redis'
    CACHE_REDIS_HOST=REDIS_HOST
    CACHE_REDIS_PORT=REDIS_PORT
    CACHE_REDIS_DB=REDIS_DB
    if REDIS_PASSWORD!='':
        CACHE_REDIS_PASSWORD=REDIS_PASSWORD
    SEND_FILE_MAX_AGE_DEFAULT=timedelta(seconds=1)
    version='4.190320'

    @staticmethod
    def init_app(app):
        pass



