#-*- coding=utf-8 -*-
from flask import url_for,request
import hashlib
import markdown
from header import *

################################################################################
###################################功能函数#####################################
################################################################################
def md5(string):
    a=hashlib.md5()
    a.update(string.encode(encoding='utf-8'))
    return a.hexdigest()

def GetTotal(path='{}:/'.format(GetConfig('default_pan'))):
    key='total:{}'.format(path)
    if redis_client.exists(key):
        return int(redis_client.get(key))
    else:
        user,n_path=path.split(':')
        if n_path=='/':
            total=mon_db.items.find({'grandid':0}).count()
        else:
            f=mon_db.items.find_one({'path':path})
            pid=f['id']
            total=mon_db.items.find({'parent':pid}).count()
        redis_client.set(key,total,300)
        return total


# @cache.memoize(timeout=60*5)
def FetchData(path='{}:/'.format(GetConfig('default_pan')),page=1,per_page=50,sortby='lastModtime',order='desc',dismiss=False,search_mode=False):
    if search_mode:
        show_secret=GetConfig('show_secret')
        query=mon_db.items.find({'name':re.compile(path)})
        resp=[]
        data=query.limit(per_page).collation({"locale": "zh", 'numericOrdering':True})\
                .sort([('order',ASCENDING)])\
                .skip((page-1)*per_page)
        for d in data:
            if show_secret=='no':
                if d['type']=='folder':
                    folder_name=d['path']
                else:
                    folder_name=d['path'].replace('/'+d['name'],'')
                _,has_password,_=has_item(folder_name,'.password')
                if has_password!=False:
                    continue
            item={}
            item['name']=d['name']
            item['id']=d['id']
            item['lastModtime']=d['lastModtime']
            item['size']=d['size']
            item['type']=d['type']
            item['path']=d['path']
            if dismiss:
                if d['name'] not in ('README.md','README.txt','readme.md','readme.txt','.password','HEAD.md','HEAD.txt','head.md','head.txt'):
                    resp.append(item)
            else:
                resp.append(item)
        total=len(resp)
        return resp,total
    path=urllib.unquote(path)
    resp=[]
    if sortby not in ['lastModtime','type','size','name']:
        sortby='lastModtime'
    if sortby=='size':
        sortby='size_order'
    if order=='desc':
        order=DESCENDING
    else:
        order=ASCENDING
    try:
        user,n_path=path.split(':')
        if n_path=='/':
            data=mon_db.items.find({'grandid':0,'user':user}).collation({"locale": "zh", 'numericOrdering':True})\
                .sort([('order',ASCENDING),(sortby,order)])\
                .limit(per_page).skip((page-1)*per_page)
            for d in data:
                item={}
                item['name']=d['name']
                item['id']=d['id']
                item['lastModtime']=d['lastModtime']
                item['size']=d['size']
                item['type']=d['type']
                item['path']=d['path']
                if dismiss:
                    if d['name'] not in ('README.md','README.txt','readme.md','readme.txt','.password','HEAD.md','HEAD.txt','head.md','head.txt'):
                        resp.append(item)
                else:
                    resp.append(item)
            total=GetTotal(path)
        else:
            f=mon_db.items.find_one({'path':path})
            pid=f['id']
            if f['type']!='folder':
                return f,'files'
            data=mon_db.items.find({'parent':pid}).collation({"locale": "zh", 'numericOrdering':True})\
                .sort([('order',ASCENDING),(sortby,order)])\
                .limit(per_page).skip((page-1)*per_page)
            for d in data:
                item={}
                item['name']=d['name']
                item['id']=d['id']
                item['lastModtime']=d['lastModtime']
                item['size']=d['size']
                item['type']=d['type']
                item['path']=d['path']
                if dismiss:
                    if d['name'] not in ('README.md','README.txt','readme.md','readme.txt','.password','HEAD.md','HEAD.txt','head.md','head.txt'):
                        resp.append(item)
                else:
                    resp.append(item)
            total=GetTotal(path)
    except:
        resp=[]
        total=0
    return resp,total

@cache.memoize(timeout=60*5)
def _thunbnail(id,user):
    app_url=GetAppUrl()
    token=GetToken(user=user)
    headers={'Authorization':'bearer {}'.format(token),'Content-type':'application/json'}
    headers.update(default_headers)
    url=app_url+'v1.0/me/drive/items/{}/thumbnails/0?select=large'.format(id)
    r=browser.get(url,headers=headers)
    data=json.loads(r.content)
    if data.get('large').get('url'):
        # return data.get('large').get('url').replace('thumbnail','videotranscode').replace('&width=800&height=800','')+'&format=dash&track=audio&transcodeAhead=0&part=initsegment&quality=audhigh'
        return data.get('large').get('url')
        # return data.get('large').get('url').replace('thumbnail','videotranscode').replace('&width=800&height=800','')+'&format=dash&track=audio&transcodeAhead=0&part=initsegment&quality=audhigh'
    else:
        return False

@cache.memoize(timeout=60*5)
def _getdownloadurl(id,user):
    app_url=GetAppUrl()
    token=GetToken(user=user)
    filename=GetName(id)
    ext=filename.split('.')[-1].lower()
    headers={'Authorization':'bearer {}'.format(token),'Content-type':'application/json'}
    headers.update(default_headers)
    url=app_url+'v1.0/me/drive/items/'+id
    r=browser.get(url,headers=headers)
    data=json.loads(r.content)
    if data.get('@microsoft.graph.downloadUrl'):
        downloadUrl=data.get('@microsoft.graph.downloadUrl')
    else:
        ErrorLogger().print_r('Getting resource:{} {} error:{}'.format(id,filename,data.get('error').get('message')))
        downloadUrl=data.get('error').get('message')
    if ext in ['webm','avi','mpg', 'mpeg', 'rm', 'rmvb', 'mov', 'wmv', 'mkv', 'asf']:
        play_url=_thunbnail(id,user)
        play_url=play_url.replace('thumbnail','videomanifest').replace('&width=800&height=800','')+'&part=index&format=dash&useScf=True&pretranscode=0&transcodeahead=0'
        # play_url=re.sub('inputFormat=.*?&','inputFormat=mp4&',play_url)
        # downloadUrl=downloadUrl.replace('thumbnail','videomanifest').replace('&width=800&height=800','')+'&part=index&format=dash&useScf=True&pretranscode=0&transcodeahead=0'
    else:
        play_url=downloadUrl
    return downloadUrl,play_url

def GetDownloadUrl(id,user):
    key_='downloadUrl:{}'.format(id)
    if redis_client.exists(key_):
        downloadUrl,play_url,ftime=redis_client.get(key_).split('####')
        if time.time()-int(ftime)>=600:
            # InfoLogger().print_r('{} downloadUrl expired!'.format(id))
            downloadUrl,play_url=_getdownloadurl(id,user)
            ftime=int(time.time())
            k='####'.join([downloadUrl,play_url,str(ftime)])
            redis_client.set(key_,k)
        else:
            # InfoLogger().print_r('get {}\'s downloadUrl from cache'.format(id))
            downloadUrl=downloadUrl
            play_url=play_url
    else:
        # InfoLogger().print_r('first time get downloadUrl from {}'.format(id))
        downloadUrl,play_url=_getdownloadurl(id,user)
        ftime=int(time.time())
        if not downloadUrl.startswith('http'):
            return downloadUrl,downloadUrl
        k='####'.join([downloadUrl,play_url,str(ftime)])
        redis_client.set(key_,k)
    return downloadUrl,play_url



# @cache.memoize(timeout=60*5)
def GetReadMe(path):
    # README
    ext='Markdown'
    readme,_,i=has_item(path,'README.md')
    if readme==False:
        readme,_,i=has_item(path,'readme.md')
    if readme==False:
        ext='Text'
        readme,_,i=has_item(path,'readme.txt')
    if readme==False:
        ext='Text'
        readme,_,i=has_item(path,'README.txt')
    if readme!=False:
        readme=markdown.markdown(readme, extensions=['tables'])
    return readme,ext


# @cache.memoize(timeout=60*5)
def GetHead(path):
    # README
    ext='Markdown'
    head,_,i=has_item(path,'HEAD.md')
    if head==False:
        head,_,i=has_item(path,'head.md')
    if head==False:
        ext='Text'
        head,_,i=has_item(path,'head.txt')
    if head==False:
        ext='Text'
        head,_,i=has_item(path,'HEAD.txt')
    if head!=False:
        head=markdown.markdown(head, extensions=['tables'])
    return head,ext


def CanEdit(filename):
    ext=filename.split('.')[-1].lower()
    if ext in ["html","htm","php","css","go","java","js","json","txt","sh","md",".password"]:
        return True
    else:
        return False

def CodeType(ext):
    code_type={}
    code_type['html'] = 'html';
    code_type['htm'] = 'html';
    code_type['php'] = 'php';
    code_type['py'] = 'python';
    code_type['css'] = 'css';
    code_type['go'] = 'golang';
    code_type['java'] = 'java';
    code_type['js'] = 'javascript';
    code_type['json'] = 'json';
    code_type['txt'] = 'Text';
    code_type['sh'] = 'sh';
    code_type['md'] = 'Markdown';
    return code_type.get(ext.lower())

def file_ico(item):
    try:
        ext = item['name'].split('.')[-1].lower()
        if ext in ['bmp','jpg','jpeg','png','gif']:
            return "image"

        if ext in ['mp4','mkv','webm','avi','mpg', 'mpeg', 'rm', 'rmvb', 'mov', 'wmv', 'mkv', 'asf']:
            return "ondemand_video"

        if ext in ['ogg','mp3','wav']:
            return "audiotrack"

        return "insert_drive_file"
    except:
        return "insert_drive_file"

def _remote_content(fileid,user):
    kc='{}:content'.format(fileid)
    if redis_client.exists(kc):
        content=unicode(redis_client.get(kc), errors='ignore')
        return content
    else:
        downloadUrl,play_url=GetDownloadUrl(fileid,user)
        if downloadUrl:
            r=browser.get(downloadUrl)
            # r.encoding='utf-8'
            if r.encoding=='ISO-8859-1':
                content=r.content
            else:
                content=r.text
            InfoLogger().print_r(content)
            redis_client.set(kc,content)
            return content
        else:
            return False

# @cache.memoize(timeout=60)
def has_item(path,name):
    if mon_db.items.count()==0:
        return False,False,False
    if len(path.split('/'))==1:
        path=path+'/'
    key='has_item$#$#$#$#{}$#$#$#$#{}'.format(path,name)
    InfoLogger().print_r('get key {}'.format(key))
    # if False:
    if redis_client.exists(key):
        values=redis_client.get(key)
        item,fid,cur=values.split('########')
        if item=='False':
            item=False
        if cur=='False':
            cur=False
        else:
            cur=True
        if fid=='False':
            fid=False
        return item,fid,cur
    else:
        item=False
        fid=False
        dz=False
        cur=False
        if name=='.password':
            dz=True
        try:
            user,n_path=path.split(':')
            if n_path=='/':
                if mon_db.items.find_one({'grandid':0,'name':name,'user':user}):
                    fid=mon_db.items.find_one({'grandid':0,'name':name,'user':user})['id']
                    item=_remote_content(fid,user).strip()
            else:
                route=n_path.split('/')
                if name=='.password':
                    for idx,r in enumerate(route):
                        if r=='':
                            data=mon_db.items.find_one({'name':name,'user':user,'grandid':0})
                        else:
                            p=user+':'+'/'.join(route[:idx+1])
                            f=mon_db.items.find_one({'path':p})
                            pid=f['id']
                            data=mon_db.items.find_one({'name':name,'parent':pid})
                        if data:
                            fid=data['id']
                            item=_remote_content(fid,user).strip()
                            if idx==len(route)-1:
                                cur=True
                else:
                    f=mon_db.items.find_one({'path':path})
                    pid=f['id']
                    data=mon_db.items.find_one({'name':name,'parent':pid})
                    if data:
                        fid=data['id']
                        item=_remote_content(fid,user).strip()
        except Exception as e:
            exstr = traceback.format_exc()
            ErrorLogger().print_r(exstr)
            item=False
        redis_client.set(key,'{}########{}########{}'.format(item,fid,cur))
        return item,fid,cur

def has_verify(path):
    verify=False
    md5_p=md5(path)
    passwd,fid,cur=has_item(path,'.password') # plaintext
    if fid and cur:
        vp=request.cookies.get(md5_p) # ciphertext
        if md5(passwd)==vp:
            verify=True
    else:
        check_path=path
        while 1:
            passwd,fid,cur=has_item(check_path,'.password') # plaintext
            md5_p=md5(check_path)
            vp=request.cookies.get(md5_p) # ciphertext
            if md5(passwd)==vp:
                verify=True
            else:
                if cur:
                    # find a parent folder with password, and user has no cookies for it
                    return False
            if check_path.split('/')[-1]!='':
                tmp_path='/'.join(check_path.split('/')[:-1])
                if '/' not in tmp_path:
                    check_path=tmp_path+'/'
                else:
                    check_path=tmp_path
            else:
                break
    return verify

def path_list(path):
    try:
        path=urllib.unquote(path)
        if path.split(':',1)=='':
            plist=[path+'/']
        else:
            user,n_path=path.split(':',1)
            if n_path.startswith('/'):
                n_path=n_path[1:]
            if n_path.endswith('/'):
                n_path=n_path[:-1]
            plist=n_path.split('/')
            if len(plist)==1:
                plist=['',plist[0]]
            plist=list(set(['{}:/{}'.format(user,i) for i in plist]))
        return plist
    except:
        return []

def breadCrumb(path):
    if path.endswith('/'):
        path=path[:-1]
    plist=path.split('/')
    #name:显示名称；pt：路径；
    for idx,p in enumerate(plist):
        if idx==0:
            name=p.split(':')[0]
            pt='/'+plist[0]
            last=False
        elif idx==len(plist)-1:
            name=p
            pt='/'+'/'.join(plist[:idx+1])
            last=True
        else:
            name=p
            pt='/'+'/'.join(plist[:idx+1])
            last=False
        yield name,pt,last





def get_od_user():
    config_path=os.path.join(config_dir,'self_config.py')
    with open(config_path,'r') as f:
        text=f.read()
    key='users'
    if redis_client.exists(key):
        users=json.loads(redis_client.get(key))
    else:
        value=re.findall('od_users=([\w\W]*})',text)[0]
        users=json.loads(value)
        redis_client.set(key,value)
    ret=[]
    for user,value in users.items():
        if value.get('client_id')!='':
            #userid,username,endpoint,sharepath,order,
            ret.append(
                    (
                        user,
                        value.get('other_name'),
                        '/{}:'.format(user),
                        value.get('share_path'),
                        value.get('order')
                    )
                )
        else:
            ret.append(
                    (
                        user,
                        'Add drive',
                        url_for('admin.install',step=0,user=user),
                        value.get('share_path'),
                        value.get('order')
                    )
                )
    ret=sorted(ret,key=lambda x:x[-1],reverse=False)
    return ret


def GetCookie(key,default):
    value=request.args.get(key)
    if value is None:
        value=request.cookies.get(key)
        if value==None or value=='None':
            value=default
    if key=='image_mode':
        value=int(value)
    return value
