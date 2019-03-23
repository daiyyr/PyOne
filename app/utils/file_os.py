#-*- coding=utf-8 -*-
from header import *

########################删除文件
def DeleteLocalFile(fileid):
    mon_db.items.remove({'id':fileid})

def DeleteRemoteFile(fileid,user=GetConfig('default_pan')):
    app_url=GetAppUrl()
    token=GetToken(user=user)
    headers={'Authorization':'bearer {}'.format(token)}
    headers.update(default_headers)
    url=app_url+'v1.0/me/drive/items/'+fileid
    r=browser.delete(url,headers=headers)
    if r.status_code==204:
        DeleteLocalFile(fileid)
        return True
    else:
        DeleteLocalFile(fileid)
        return False

########################
def CreateFolder(folder_name,grand_path,user=GetConfig('default_pan')):
    app_url=GetAppUrl()
    token=GetToken(user=user)
    if grand_path=='' or grand_path is None or grand_path=='/':
        url=app_url+'v1.0/me/drive/root/children'
        parent_id=''
        grandid=0
    else:
        path='{}:/{}'.format(user,grand_path)
        parent=mon_db.items.find_one({'path':path})
        parent_id=parent['id']
        grandid=parent['grandid']+1
        url=app_url+'v1.0/me/drive/items/{}/children'.format(parent['id'])
    headers={'Authorization':'bearer {}'.format(token),'Content-Type':'application/json'}
    headers.update(default_headers)
    payload={
      "name": folder_name,
      "folder": {},
      "@microsoft.graph.conflictBehavior": "rename"
    }
    r=browser.post(url,headers=headers,data=json.dumps(payload))
    data=json.loads(r.content)
    if data.get('id'):
        #插入数据
        share_path=od_users.get(user).get('share_path')
        if share_path=='/':
            share_path=''
        item={}
        item['type']='folder'
        item['user']=user
        item['name']=data.get('name')
        item['id']=data.get('id')
        item['size']=humanize.naturalsize(data.get('size'), gnu=True)
        item['size_order']=data.get('size')
        item['lastModtime']=date_to_char(parse(data.get('lastModifiedDateTime')))
        item['grandid']=grandid
        item['parent']=parent_id
        if grand_path=='' or grand_path is None or grand_path=='/':
            path=convert2unicode(data['name'])
        else:
            path=grand_path.replace(share_path,'',1)+'/'+convert2unicode(data['name'])
        if not path.startswith('/'):
            path='/'+path
        path='{}:{}'.format(user,path)
        item['path']=path
        item['order']=0
        mon_db.items.insert_one(item)
        return True
    else:
        ErrorLogger().print_r(data.get('error').get('msg'))
        InfoLogger().print_r(data.get('error').get('msg'))
        return False

def CreateFile(filename,path,content,user=GetConfig('default_pan')):
    token=GetToken(user=user)
    app_url=GetAppUrl()
    if not path.startswith('/'):
        path='/'+path
    share_path=od_users.get(user).get('share_path')
    if share_path!='/':
        remote_file=os.path.join(os.path.join(share_path,path[1:]),filename)
    else:
        remote_file=os.path.join(path,filename)
    InfoLogger().print_r(u'remote path:{}'.format(remote_file))
    info={}
    headers={'Authorization':'bearer {}'.format(token)}
    headers.update(default_headers)
    url=app_url+'v1.0/me/drive/items/root:{}:/content'.format(remote_file)
    r=browser.put(url,headers=headers,data=content,timeout=10)
    data=json.loads(r.content)
    if data.get('id'):
        AddResource(data,user)
        info['status']=0
        info['msg']='succeed'
        key='has_item$#$#$#$#{}:{}$#$#$#$#{}'.format(user,path,filename)
        InfoLogger().print_r('set key:{}'.format(key))
        redis_client.delete(key)
    else:
        info['status']=0
        info['msg']=data.get('error').get('message')
    return info

def EditFile(fileid,content,user=GetConfig('default_pan')):
    token=GetToken(user=user)
    app_url=GetAppUrl()
    info={}
    headers={'Authorization':'bearer {}'.format(token)}
    headers.update(default_headers)
    url=app_url+'v1.0/me/drive/items/{}/content'.format(fileid)
    try:
        r=browser.put(url,headers=headers,data=content,timeout=10)
        data=json.loads(r.content)
        if data.get('id'):
            info['status']=0
            info['msg']='Succeed to change'
            redis_client.delete('{}:content'.format(fileid))
            file=mon_db.items.find_one({'id':fileid})
            name=file['name']
            path=file['path'].replace(name,'',1)
            if len(path.split('/'))>2 and path.split('/')[-1]=='':
                path=path[:-1]
            key='has_item$#$#$#$#{}$#$#$#$#{}'.format(path,name)
            InfoLogger().print_r('edit key:{}'.format(key))
            redis_client.delete(key)
        else:
            info['status']=0
            info['msg']=data.get('error').get('message')
    except Exception as e:
        exstr = traceback.format_exc()
        ErrorLogger().print_r(exstr)
        info['status']=0
        info['msg']='修改超时'
    return info


def MoveFile(fileid,new_folder_path,user=GetConfig('default_pan')):
    app_url=GetAppUrl()
    token=GetToken(user=user)
    #GetRootid
    if new_folder_path=='' or new_folder_path is None or new_folder_path=='/':
        folder_id=GetRootid(user)
        parent=''
        grandid=0
        path='{}:/{}'.format(user,GetName(fileid))
    else:
        path='{}:/{}'.format(user,new_folder_path)
        InfoLogger().print_r(path)
        parent_item=mon_db.items.find_one({'path':path})
        folder_id=parent_item['id']
        parent=parent_item['id']
        grandid=parent_item['grandid']+1
        path=parent_item['path']+'/'+GetName(fileid)
    url=app_url+'v1.0/me/drive/items/{}'.format(fileid)
    headers={'Authorization':'bearer {}'.format(token),'Content-Type':'application/json'}
    headers.update(default_headers)
    payload={
      "parentReference": {
        "id": folder_id
      },
      "name": GetName(fileid)
    }
    r=browser.patch(url,headers=headers,data=json.dumps(payload))
    data=json.loads(r.content)
    if data.get('id'):
        new_value={'parent':parent,'grandid':grandid,'path':path}
        mon_db.items.find_one_and_update({'id':fileid},{'$set':new_value})
        file=mon_db.items.find_one({'id':fileid})
        filename=file['name']
        if file['parent']=='':
            path='/'
        else:
            path=mon_db.items.find_one({'id':file['parent']})['path']
        key='has_item$#$#$#$#{}$#$#$#$#{}'.format(path,filename)
        redis_client.delete(key)
        return True
    else:
        InfoLogger().print_r(data.get('error').get('msg'))
        return False

def ReName(fileid,new_name,user=GetConfig('default_pan')):
    app_url=GetAppUrl()
    token=GetToken(user=user)
    url=app_url+'v1.0/me/drive/items/{}'.format(fileid)
    headers={'Authorization':'bearer {}'.format(token),'Content-Type':'application/json'}
    headers.update(default_headers)
    payload={
      "name": new_name
    }
    r=browser.patch(url,headers=headers,data=json.dumps(payload))
    data=json.loads(r.content)
    if data.get('id'):
        it=mon_db.items.find_one({'id':fileid})
        old_name=it['name']
        path=it['path'].replace(old_name,new_name,1)
        new_value={'path':path,'name':new_name}
        mon_db.items.find_one_and_update({'id':fileid},{'$set':new_value})
        key='path:{}'.format(fileid)
        redis_client.delete(key)
        key='name:{}'.format(fileid)
        redis_client.delete(key)
        if it['type']=='folder':
            files=mon_db.items.find({'parent':it['id']})
            for file in files:
                new_path=file['path'].replace(old_name,new_name,1)
                new_value={'path':new_path}
                mon_db.items.find_one_and_update({'id':file['id']},{'$set':new_value})
        return True
    else:
        InfoLogger().print_r(data.get('error').get('msg'))
        return False
