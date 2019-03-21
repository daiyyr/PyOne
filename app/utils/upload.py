#-*- coding=utf-8 -*-
from header import *
import header


def _upload(filepath,remote_path,user=GetConfig('default_pan')): #remote_path like 'share/share.mp4'
    token=GetToken(user=user)
    headers={'Authorization':'bearer {}'.format(token)}
    headers.update(default_headers)
    url=app_url+'v1.0/me/drive/root:{}:/content'.format(urllib.quote(convert2unicode(remote_path)))
    timeCalc=TimeCalculator()
    r=browser.put(url,headers=headers,data=open(filepath,'rb'))
    # r=CurlUpload(url,headers,open(filepath,'rb'))
    try:
        data=json.loads(r.content)
        trytime=1
        while 1:
            try:
                if data.get('error'):
                    InfoLogger().print_r('upload {} fail; reason: {}'.format(filepath,data.get('error').get('message')))
                    yield {'status':'upload fail!'}
                    break
                elif r.status_code==201 or r.status_code==200:
                    speed=CalcSpeed(header._filesize(filepath),timeCalc.PassNow())['kb']
                    InfoLogger().print_r('upload {} success! speed:{}'.format(filepath,speed))
                    AddResource(data,user)
                    yield {'status':'upload success!','speed':speed}
                    break
                else:
                    InfoLogger().print_r(data)
                    yield {'status':'upload fail!'}
                    break
            except Exception as e:
                exstr = traceback.format_exc()
                trytime+=1
                ErrorLogger().print_r('error to opreate _upload("{}","{}"), try times {},error:{}'.format(filepath,remote_path,trytime,exstr))
                yield {'status':'upload fail! retry!'}
            if trytime>3:
                yield {'status':'upload fail! touch max retry time(3)'}
                break
    except Exception as e:
        exstr = traceback.format_exc()
        ErrorLogger().print_r(u'upload fail!{}'.format(exstr))
        ErrorLogger().print_r(r.content)

def _upload_part(uploadUrl, filepath,filesize, offset, length,trytime=1):
    offset,length=map(int,(offset,length))
    if offset>filesize:
        InfoLogger().print_r('offset must smaller than file size')
        return {'status':'fail','msg':'params mistake','code':1}
    length=length if offset+length<filesize else filesize-offset
    endpos=offset+length-1 if offset+length<filesize else filesize-1
    # InfoLogger().print_r('upload file {} {}%'.format(filepath,round(float(endpos)/filesize*100,1)))
    filebin=header._file_content(filepath,offset,length)
    headers={}
    # headers['Authorization']='bearer {}'.format(token)
    headers['Content-Length']=str(length)
    headers['Content-Range']='bytes {}-{}/{}'.format(offset,endpos,filesize)
    headers.update(default_headers)
    try:
        timeCalc=TimeCalculator()
        r=browser.put(uploadUrl,headers=headers,data=filebin)
        # r=CurlUpload(uploadUrl,headers,filebin)
        data=json.loads(r.content)
        speed=CalcSpeed(length,timeCalc.PassNow())['kb']
        if r.status_code==201 or r.status_code==200:
            InfoLogger().print_r(u'{} upload success! real time speed:{}'.format(filepath,speed))
            return {'status':'success','msg':'all upload success','code':0,'info':data,'speed':speed}
        elif r.status_code==202:
            offset=data.get('nextExpectedRanges')[0].split('-')[0]
            InfoLogger().print_r(u'{} partition upload success! {}%! real time speed:{}'.format(filepath,round(float(endpos)/filesize*100,1),speed))
            return {'status':'success','msg':'partition upload success','code':1,'offset':offset,'speed':speed}
        else:
            trytime+=1
            if trytime<=3:
                return {'status':'fail'
                        ,'msg':'please retry'
                        ,'sys_msg':data.get('error').get('message')
                        ,'code':2,'trytime':trytime}
            else:
                return {'status':'fail'
                        ,'msg':'retry times limit'
                        ,'sys_msg':data.get('error').get('message')
                        ,'code':3}
    except Exception as e:
        exstr = traceback.format_exc()
        ErrorLogger().print_r('error to opreate _upload_part("{}","{}","{}","{}"), try times {},reason:{}'.format(uploadUrl, filepath, offset, length,trytime,exstr))
        trytime+=1
        if trytime<=3:
            return {'status':'fail','msg':'please retry','code':2,'trytime':trytime,'sys_msg':''}
        else:
            return {'status':'fail','msg':'retry times limit','code':3,'sys_msg':''}

def CreateUploadSession(path,user=GetConfig('default_pan')):
    token=GetToken(user=user)
    headers={'Authorization':'bearer {}'.format(token),'Content-Type':'application/json'}
    headers.update(default_headers)
    url=app_url+u'v1.0/me/drive/root:{}:/createUploadSession'.format(urllib.quote(convert2unicode(path)))
    data={
          "item": {
            "@microsoft.graph.conflictBehavior": "fail",
          }
        }
    InfoLogger().print_r('create upload session for :{}'.format(path))
    try:
        r=browser.post(url,headers=headers,data=json.dumps(data))
        retdata=json.loads(r.content)
        if r.status_code==409:
            InfoLogger().print_r('file exists')
            return False
        else:
            return retdata
    except Exception as e:
        ErrorLogger().print_r('error to opreate CreateUploadSession("{}"),reason {}'.format(path,e))
        return False

def UploadSession(uploadUrl,filesize, filepath,user):
    length=1024*1024*3.25
    offset=0
    trytime=1
    # filesize=header._filesize(filepath)
    while 1:
        result=_upload_part(uploadUrl, filepath,filesize, offset, length,trytime=trytime)
        code=result['code']
        #上传完成
        if code==0:
            AddResource(result['info'],user)
            yield {'status':'upload success!','uploadUrl':uploadUrl,'speed':result['speed']}
            break
        #分片上传成功
        elif code==1:
            trytime=1
            offset=result['offset']
            per=round((float(offset)/filesize)*100,1)
            # InfoLogger().print_r('upload file success {} {}%;real time speed:{}'.format(filepath,round(float(endpos)/size*100,1),speed))
            yield {'status':'partition upload success! {}%'.format(per),'uploadUrl':uploadUrl,'speed':result['speed']}
        #错误，重试
        elif code==2:
            if result['sys_msg']=='The request has been throttled':
                InfoLogger().print_r(result['sys_msg']+' ; wait for 1800s')
                yield {'status':'The request has been throttled! wait for 1800s','uploadUrl':uploadUrl}
                time.sleep(1800)
            offset=offset
            trytime=result['trytime']
            yield {'status':'partition upload fail! retry!','uploadUrl':uploadUrl}
        #重试超过3次，放弃
        elif code==3:
            yield {'status':'partition upload fail! touch max retry times!','uploadUrl':uploadUrl}
            break

def Upload_for_server(filepath,remote_path=None,user=GetConfig('default_pan')):
    token=GetToken(user=user)
    headers={'Authorization':'bearer {}'.format(token),'Content-Type':'application/json'}
    if remote_path is None:
        remote_path=os.path.basename(filepath)
    if remote_path.endswith('/'):
        remote_path=os.path.join(remote_path,os.path.basename(filepath))
    if not remote_path.startswith('/'):
        remote_path='/'+remote_path
    filepath=convert2unicode(filepath)
    remote_path=convert2unicode(remote_path.replace('//','/'))
    filesize=header._filesize(filepath)
    InfoLogger().print_r('local file path:{}, remote file path:{}'.format(filepath,remote_path))
    if filesize<1024*1024*3.25:
        for msg in _upload(filepath,remote_path,user):
            yield msg
    else:
        session_data=CreateUploadSession(remote_path,user)
        if session_data==False:
            yield {'status':'file exists!'}
        else:
            if session_data.get('uploadUrl'):
                InfoLogger().print_r('start upload {}'.format(filepath))
                uploadUrl=session_data.get('uploadUrl')
                for msg in UploadSession(uploadUrl,filesize,filepath,user):
                    yield msg
            else:
                # InfoLogger().print_r('user:{} create upload session fail! {},{}'.format(user,remote_path,session_data.get('error').get('message')))
                yield {'status':'user:{};create upload session fail!{}'.format(user,session_data.get('error').get('message'))}

def Upload(filepath,remote_path=None,user=GetConfig('default_pan')):
    token=GetToken(user=user)
    headers={'Authorization':'bearer {}'.format(token),'Content-Type':'application/json'}
    if remote_path is None:
        remote_path=os.path.basename(filepath)
    if remote_path.endswith('/'):
        remote_path=os.path.join(remote_path,os.path.basename(filepath))
    if not remote_path.startswith('/'):
        remote_path='/'+remote_path
    remote_path=remote_path.replace('//','/')
    filesize=header._filesize(filepath)
    InfoLogger().print_r('local file path:{}, remote file path:{}'.format(filepath,remote_path))
    if filesize<1024*1024*3.25:
        for msg in _upload(filepath,remote_path,user):
            1
    else:
        session_data=CreateUploadSession(remote_path,user)
        if session_data==False:
            return {'status':'file exists!'}
        else:
            if session_data.get('uploadUrl'):
                InfoLogger().print_r('start upload {}'.format(filepath))
                uploadUrl=session_data.get('uploadUrl')
                for msg in UploadSession(uploadUrl,filesize,filepath,user):
                    1
            else:
                InfoLogger().print_r(session_data.get('error').get('msg'))
                InfoLogger().print_r('create upload session fail! {}'.format(remote_path))
                return {'status':'create upload session fail!'}


def ContinueUpload(filepath,uploadUrl,user):
    headers={'Content-Type':'application/json'}
    headers.update(default_headers)
    r=browser.get(uploadUrl,headers=headers)
    data=json.loads(r.text)
    offset=data.get('nextExpectedRanges')[0].split('-')[0]
    expires_on=time.mktime(parse(data.get('expirationDateTime')).timetuple())
    if time.time()>expires_on:
        yield {'status':'alright expired!'}
    else:
        length=1024*1024*3.25
        trytime=1
        filesize=header._filesize(filepath)
        while 1:
            result=_upload_part(uploadUrl, filepath,filesize, offset, length,trytime=trytime)
            code=result['code']
            #上传完成
            if code==0:
                AddResource(result['info'],user)
                yield {'status':'upload success!','uploadUrl':uploadUrl,'speed':result['speed']}
                break
            #分片上传成功
            elif code==1:
                trytime=1
                offset=result['offset']
                per=round((float(offset)/filesize)*100,1)
                # InfoLogger().print_r('upload file success {} {}%;real time speed:{}'.format(filepath,round(float(endpos)/size*100,1),speed))
                yield {'status':'partition upload success! {}%'.format(per),'uploadUrl':uploadUrl,'speed':result['speed']}
            #错误，重试
            elif code==2:
                if result['sys_msg']=='The request has been throttled':
                    InfoLogger().print_r(result['sys_msg']+' ; wait for 1800s')
                    yield {'status':'The request has been throttled! wait for 1800s','uploadUrl':uploadUrl}
                    time.sleep(1800)
                offset=offset
                trytime=result['trytime']
                yield {'status':'partition upload fail! retry!','uploadUrl':uploadUrl}
            #重试超过3次，放弃
            elif code==3:
                yield {'status':'partition upload fail! touch max retry times!','uploadUrl':uploadUrl}
                break


class MultiUpload(Thread):
    def __init__(self,waiting_queue,user):
        super(MultiUpload,self).__init__()
        self.queue=waiting_queue
        self.user=user

    def run(self):
        while not self.queue.empty():
            localpath,remote_dir=self.queue.get()
            cp='{}:/{}'.format(self.user,remote_dir)
            if mon_db.items.find_one({'path':cp}):
                InfoLogger().print_r(u'{} exists!'.format(cp))
            else:
                Upload(localpath,remote_dir,self.user)


def UploadDir(local_dir,remote_dir,user,threads=5):
    InfoLogger().print_r(u'geting file from dir {}'.format(local_dir))
    localfiles=list_all_files(local_dir)
    InfoLogger().print_r(u'get {} files from dir {}'.format(len(localfiles),local_dir))
    InfoLogger().print_r(u'check filename')
    for f in localfiles:
        dir_,fname=os.path.dirname(f),os.path.basename(f)
        if len(re.findall('[:/#\|]+',fname))>0:
            newf=os.path.join(dir_,re.sub('[:/#\|]+','',fname))
            shutil.move(f,newf)
    localfiles=list_all_files(local_dir)
    check_file_list=[]
    if local_dir.endswith('/'):
        local_dir=local_dir[:-1]
    for file in localfiles:
        dir_,fname=os.path.dirname(file),os.path.basename(file)
        remote_path=remote_dir+'/'+dir_.replace(local_dir,'')+'/'+fname
        remote_path=remote_path.replace('//','/')
        check_file_list.append((remote_path,file))
    queue=Queue()
    tasks=[]
    for remote_path,file in check_file_list:
        queue.put((file,remote_path))
    print "start upload files 5s later"
    time.sleep(5)
    for i in range(min(threads,queue.qsize())):
        t=MultiUpload(queue,user)
        t.start()
        tasks.append(t)
    for t in tasks:
        t.join()
    #删除错误数据
    RemoveRepeatFile()
