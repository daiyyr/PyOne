#-*- coding=utf-8 -*-
from header import *
from upload import *

def CutText(msg,indent=15):
    if len(msg)>indent*2:
        skip_len=len(msg)-indent*2
        new_msg=msg[:indent]+'...'+msg[skip_len:]
    else:
        new_msg=msg
    return new_msg

def get_upload_tasks(page,per_page=50):
    tasks=mon_db.upload_queue.find({})\
                .sort([('add_time',DESCENDING)])\
                .limit(per_page).skip((page-1)*per_page)
    ##根据gid获取列表
    result=[]
    for task in tasks:
        info={}
        info['localpath']=CutText(task['localpath'])
        info['remote']=CutText(task['remote'])
        info['user']=task['user']
        info['status']=task['status']
        info['speed']=task['speed']
        result.append(info)
    return result


def get_upload_tasks_no():
    taskno=mon_db.upload_queue.find({}).count()
    return taskno


def StartUploadQueue():
    waiting_tasks=mon_db.upload_queue.find({
            '$or':[
            {'status':{'$ne':'file exists!'}},
            {'status':{'$ne':'上传成功！'}}
            ]
        })
    queue=Queue()
    for t in waiting_tasks:
        print(t['localpath'])
        queue.put((t['localpath'],t['remote'],t['user'],t['id']))
    tasks=[]
    for i in range(min(5,queue.qsize())):
        t=MultiUploadQueue(queue)
        t.start()
        tasks.append(t)
    for t in tasks:
        t.join()
    #删除错误数据
    RemoveRepeatFile()


class MultiUploadQueue(Thread):
    def __init__(self,waiting_queue):
        super(MultiUploadQueue,self).__init__()
        self.queue=waiting_queue

    def run(self):
        while not self.queue.empty():
            localpath,remote_path,user,id=self.queue.get()
            if not os.path.exists(localpath):
                new_value={'status':'file exists!'}
                mon_db.upload_queue.update_many({'id':id},{'$set':new_value})
                break
            cp='{}:/{}'.format(user,remote_path)
            if mon_db.items.find_one({'path':cp}):
                InfoLogger().print_r(u'{} exists!'.format(cp))
                new_value={'status':'file exists!'}
                mon_db.upload_queue.update_many({'id':id},{'$set':new_value})
                break
            else:
                _upload_session=Upload_for_server(localpath,remote_path,user)
            while 1:
                try:
                    new_value={}
                    data=_upload_session.next()
                    msg=data['status']
                    InfoLogger().print_r('{} upload status:{}'.format(localpath,msg))
                    """
                    partition upload success
                    The request has been throttled!
                    partition upload fail! retry
                    partition upload fail!
                    file exists
                    create upload session fail
                    """
                    if 'partition upload success' in msg:
                        new_value['status']=msg
                        new_value['speed']=data.get('speed')
                    elif 'The request has been throttled' in msg:
                        new_value['status']='api受限！智能等待30分钟'
                    elif 'partition upload fail! retry' in msg:
                        new_value['status']='上传失败，等待重试'
                    elif 'partition upload fail' in msg:
                        new_value['status']='上传失败，已经超过重试次数'
                        mon_db.upload_queue.find_one_and_update({'id':id},{'$set':new_value})
                        break
                    elif 'file exists' in msg:
                        new_value['status']='远程文件已存在'
                        mon_db.upload_queue.find_one_and_update({'id':id},{'$set':new_value})
                        break
                    elif 'create upload session fail' in msg:
                        new_value['status']='创建实例失败！'
                        mon_db.upload_queue.find_one_and_update({'id':id},{'$set':new_value})
                        break
                    else:
                        new_value['status']='上传成功！'
                        new_value['speed']=data.get('speed')
                        mon_db.upload_queue.find_one_and_update({'id':id},{'$set':new_value})
                        time.sleep(2)
                        os.remove(localpath)
                        break
                    mon_db.upload_queue.find_one_and_update({'id':id},{'$set':new_value})
                except Exception as e:
                    exstr = traceback.format_exc()
                    ErrorLogger().print_r(exstr)
                    break
                time.sleep(2)
