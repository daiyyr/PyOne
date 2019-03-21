#-*- coding=utf-8 -*-
import os
import logging
from logging import handlers
from self_config import config_dir

class Logger(object):
    level_relations = {
        'debug':logging.DEBUG,
        'info':logging.INFO,
        'warning':logging.WARNING,
        'error':logging.ERROR,
        'crit':logging.CRITICAL
    }#日志级别关系映射

    def __init__(self,filename=os.path.join(config_dir,'logs/PyOne.running.log'),level='debug',when='D',backCount=3,fmt='%(asctime)s - %(levelname)s: %(message)s'):
        self.filename=filename
        self.level=level
        self.logger = logging.getLogger(self.filename)
        format_str = logging.Formatter(fmt)#设置日志格式
        self.logger.setLevel(self.level_relations.get(self.level))#设置日志级别
        self.stream_handler = logging.StreamHandler()#往屏幕上输出
        self.stream_handler.setFormatter(format_str) #设置屏幕上显示的格式
        self.file_handler = handlers.TimedRotatingFileHandler(filename=filename,when=when,backupCount=backCount,encoding='utf-8')#往文件里写入#指定间隔时间自动生成文件的处理器
        #实例化TimedRotatingFileHandler
        #interval是时间间隔，backupCount是备份文件的个数，如果超过这个个数，就会自动删除，when是间隔的时间单位，单位有以下几种：
        # S 秒
        # M 分
        # H 小时、
        # D 天、
        # W 每星期（interval==0时代表星期一）
        # midnight 每天凌晨
        self.file_handler.setFormatter(format_str)#设置文件里写入的格式
        self.logger.addHandler(self.stream_handler) #把对象加到logger里
        self.logger.addHandler(self.file_handler)


    def __del__(self):
        self.logger.removeHandler(self.stream_handler)
        self.logger.removeHandler(self.file_handler)


class InfoLogger(Logger):

    def __init__(self):
        super(InfoLogger,self).__init__()

    def print_r(self,msg):
        self.logger.info(msg)

    def __del__(self):
        self.logger.removeHandler(self.stream_handler)
        self.logger.removeHandler(self.file_handler)


class ErrorLogger(Logger):
    """docstring for Log"""
    def __init__(self,filename=os.path.join(config_dir,'logs/PyOne.error.log')):
        super(ErrorLogger,self).__init__(filename)

    def print_r(self,msg):
        self.logger.info(msg)

    def __del__(self):
        self.logger.removeHandler(self.stream_handler)
        self.logger.removeHandler(self.file_handler)


if __name__ == '__main__':
    log = Logger(level='debug')
    log.logger.debug('debug')
    log.logger.info('info')
    log.logger.warning('警告')
    log.logger.error('报错')
    log.logger.critical('严重')
    Logger('error.log', level='error').logger.error('error')
