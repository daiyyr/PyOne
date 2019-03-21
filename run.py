#-*- coding=utf-8 -*-
import eventlet
eventlet.monkey_patch()
import os
from flask_script import Manager, Shell
from app import create_app
from self_config import *
from config import *
from function import *
from redis import Redis,ConnectionPool

app = create_app()
manager = Manager(app)

@app.cli.command()
def test():
    """Run the unit tests."""
    import unittest
    tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)


######################系统日志
app.logger.addHandler(ErrorLogger().file_handler)
app.logger.setLevel(logging.DEBUG)

######################初始化变量
pool = ConnectionPool(host='localhost', port=6379, db=0)
tmp_rd=Redis(connection_pool=pool)
tmp_rd.set('title',title)
tmp_rd.set('tj_code',tj_code)
tmp_rd.set('downloadUrl_timeout',downloadUrl_timeout)
tmp_rd.set('testing_filed',testing_filed)
tmp_rd.set('allow_site',','.join(allow_site))
tmp_rd.set('ARIA2_HOST',ARIA2_HOST)
tmp_rd.set('ARIA2_PORT',ARIA2_PORT)
tmp_rd.set('ARIA2_SECRET',ARIA2_SECRET)
tmp_rd.set('ARIA2_SCHEME',ARIA2_SCHEME)
tmp_rd.set('password',password)
config_path=os.path.join(config_dir,'self_config.py')
with open(config_path,'r') as f:
    text=f.read()
tmp_rd.set('users',re.findall('od_users=([\w\W]*})',text)[0])
key='themelist'
tmp_rd.delete(key)
######################函数
app.jinja_env.globals['version']=config.version
app.jinja_env.globals['FetchData']=FetchData
app.jinja_env.globals['path_list']=path_list
app.jinja_env.globals['CanEdit']=CanEdit
app.jinja_env.globals['quote']=urllib.quote
app.jinja_env.globals['len']=len
app.jinja_env.globals['enumerate']=enumerate
app.jinja_env.globals['breadCrumb']=breadCrumb
app.jinja_env.globals['list']=list
app.jinja_env.globals['os']=os
app.jinja_env.globals['re']=re
app.jinja_env.globals['file_ico']=file_ico
app.jinja_env.globals['CutText']=CutText
app.jinja_env.globals['GetConfig']=GetConfig
app.jinja_env.globals['config_dir']=config_dir
app.jinja_env.globals['GetThemeList']=GetThemeList
app.jinja_env.globals['get_od_user']=get_od_user

################################################################################
#####################################启动#######################################
################################################################################
if __name__ == '__main__':
    manager.run()





