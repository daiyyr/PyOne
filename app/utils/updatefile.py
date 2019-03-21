#-*- coding=utf-8 -*-
from header import *

def Dir(path=u'{}:/'.format(GetConfig('default_pan'))):
    app_url=GetAppUrl()
    user,n_path=path.split(':')
    InfoLogger().print_r('update {}\'s {} file'.format(user,n_path))
    if n_path=='/':
        BaseUrl=app_url+u'v1.0/me/drive/root/children?expand=thumbnails'
        mon_db.items.remove({'user':user})
        queue=Queue()
        g=GetItemThread(queue,user)
        g.GetItem(BaseUrl)
        queue=g.queue
    else:
        grandid=0
        parent=''
        if n_path.endswith('/'):
            n_path=n_path[:-1]
        if not n_path.startswith('/'):
            n_path='/'+n_path
        if mon_db.items.find_one({'grandid':0,'type':'folder','user':user}):
            parent_id=0
            for idx,p in enumerate(n_path[1:].split('/')):
                if parent_id==0:
                    parent_id=mon_db.items.find_one({'name':p,'grandid':idx,'user':user})['id']
                else:
                    parent_id=mon_db.items.find_one({'name':p,'grandid':idx,'parent':parent_id})['id']
                mon_db.items.delete_many({'parent':parent_id})
            grandid=idx+1
            parent=parent_id
        n_path=urllib.quote(n_path.encode('utf-8'))
        BaseUrl=app_url+u'v1.0/me/drive/root:{}:/children?expand=thumbnails'.format(n_path)
        queue=Queue()
        g=GetItemThread(queue,user)
        g.GetItem(BaseUrl,grandid,parent,1)
        queue=g.queue
    if queue.qsize()==0:
        return
    tasks=[]
    for i in range(min(10,queue.qsize())):
        t=GetItemThread(queue,user)
        t.setDaemon(True)
        t.start()
        tasks.append(t)
    # for t in tasks:
    #     t.join()
    error_status=0
    while 1:
        for t in tasks:
            InfoLogger().print_r('thread {}\'s status {},qsize {}'.format(t.getName(),t.isAlive(),t.queue.qsize()))
            if t.isAlive()==False and t.queue.qsize()==0:
                tasks.pop(tasks.index(t))
            if t.queue.qsize()==0 and t.isAlive()==True:
                error_status+=1
                InfoLogger().print_r('error status times:{}'.format(error_status))
            else:
                error_status=1
            if error_status>=20 and t in tasks:
                InfoLogger().print_r('force kill thread:{}'.format(t.getName()))
                tasks.pop(tasks.index(t))
        if len(tasks)==0:
            InfoLogger().print_r(u'{} all thread stop!'.format(path))
            break
        time.sleep(1)
    # RemoveRepeatFile()


def UpdateFile(renew='all'):
    tasks=[]
    if renew=='all':
        mon_db.items.delete_many({})
        clearRedis()
        for user,item in od_users.items():
            if item.get('client_id')!='':
                share_path='{}:{}'.format(user,item['share_path'])
                # Dir_all(share_path)
                t=Thread(target=Dir,args=(share_path,))
                t.start()
                tasks.append(t)
        for t in tasks:
            t.join()
    else:
        for user,item in od_users.items():
            if item.get('client_id')!='':
                share_path='{}:{}'.format(user,item['share_path'])
                # Dir(share_path)
                t=Thread(target=Dir,args=(share_path,))
                t.start()
                tasks.append(t)
    while 1:
        for t in tasks:
            if t.isAlive()==False:
                tasks.pop(tasks.index(t))
        if len(tasks)==0:
            InfoLogger().print_r('all users update status is complete')
            break
        time.sleep(1)
    InfoLogger().print_r('update file success!')
    os.kill(os.getpid(), signal.SIGKILL)


def GetRootid(user=GetConfig('default_pan')):
    key='{}:rootid'.format(user)
    if redis_client.exists(key):
        return redis_client.get(key)
    else:
        app_url=GetAppUrl()
        token=GetToken(user=user)
        url=app_url+u'v1.0/me/drive/root/'
        headers={'Authorization': 'Bearer {}'.format(token)}
        headers.update(default_headers)
        r=browser.get(url,headers=headers)
        data=json.loads(r.content)
        redis_client.set(key,data['id'],3600)
        return data['id']


def FileExists(filename,user=GetConfig('default_pan')):
    token=GetToken(user=user)
    headers={'Authorization':'bearer {}'.format(token),'Content-Type':'application/json'}
    headers.update(default_headers)
    search_url=app_url+"v1.0/me/drive/root/search(q='{}')".format(convert2unicode(filename))
    r=browser.get(search_url,headers=headers)
    jsondata=json.loads(r.text)
    if len(jsondata['value'])==0:
        return False
    else:
        return True

def FileInfo(fileid,user=GetConfig('default_pan')):
    token=GetToken(user=user)
    headers={'Authorization':'bearer {}'.format(token),'Content-Type':'application/json'}
    headers.update(default_headers)
    search_url=app_url+"v1.0/me/drive/items/{}".format(fileid)
    r=browser.get(search_url,headers=headers)
    jsondata=json.loads(r.text)
    return jsondata
