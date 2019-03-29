#-*- coding=utf-8 -*-
from flask import render_template,redirect,abort,make_response,jsonify,request,url_for,Response,send_from_directory
from flask_sqlalchemy import Pagination
from ..utils import *
from ..extend import *
from . import front
import datetime

from tempfile import mkstemp
from shutil import move
from os import fdopen, remove


################################################################################
###################################前台函数#####################################
################################################################################
@front.before_request
def before_request():
    bad_ua=['Googlebot-Image','FeedDemon ','BOT/0.1 (BOT for JCE)','CrawlDaddy ','Java','Feedly','UniversalFeedParser','ApacheBench','Swiftbot','ZmEu','Indy Library','oBot','jaunty','YandexBot','AhrefsBot','MJ12bot','WinHttp','EasouSpider','HttpClient','Microsoft URL Control','YYSpider','jaunty','Python-urllib','lightDeckReports Bot','PHP','vxiaotou-spider','spider']
    global referrer
    try:
        ip = request.headers['X-Forwarded-For'].split(',')[0]
    except:
        ip = request.remote_addr
    try:
        ua = request.headers.get('User-Agent')
    except:
        ua="null"
    if sum([i.lower() in ua.lower() for i in bad_ua])>0:
        return redirect('http://www.baidu.com')
    # print '{}:{}:{}'.format(request.endpoint,ip,ua)
    referrer=request.referrer if request.referrer is not None else 'no-referrer'


@front.errorhandler(500)
def page_not_found(e):
    # note that we set the 500 status explicitly
    msg,status=CheckServer()
    return render_template('error.html',msg=msg,code=500), 500

@front.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    msg,status=CheckServer()
    return render_template('error.html',msg=msg,code=404), 404


@front.route('/favicon.ico')
def favicon():
    resp=MakeResponse(send_from_directory(os.path.join(config_dir, 'app/static/img'),'favicon.ico',mimetype='image/vnd.microsoft.icon'))
    return resp


def setRetry(key, value):
    retrykeyfile = ""
    retrykeyfile = os.path.join(config_dir,'logs/PyOne.password.retry.key')
    if not os.path.exists(retrykeyfile):
        os.mknod(retrykeyfile)
    #Create temp file
    fh, abs_path = mkstemp()
    with fdopen(fh,'w') as new_file:
        found = False
        with open(retrykeyfile) as old_file:
            for line in old_file:
                if key == line.split(':')[0]: 
                    new_file.write(key + ":" + str(value) + "\n")
                else:
                    new_file.write(line)
            if not found:
                new_file.write(key + ":" + str(value) + "\n")
    #Remove original file
    remove(retrykeyfile)
    #Move new file
    move(abs_path, retrykeyfile)


def getRetry(key):
    retrykeyfile = ""
    retrykeyfile = os.path.join(config_dir,'logs/PyOne.password.retry.key')
    if not os.path.exists(retrykeyfile):
        os.mknod(retrykeyfile)
    with open(retrykeyfile) as old_file:
        for line in old_file:
            if key == line.split(':')[0]: 
                return line.split(':')[1]
    return ""

def setRetryLog(log_line):
    retrylogfile = ""
    retrylogfile = os.path.join(config_dir,'logs/PyOne.password.retry.log')
    if not os.path.exists(retrylogfile):
        os.mknod(retrylogfile)
    with open(retrylogfile, 'a') as file:
        file.write(str(datetime.datetime.now()) + " " + log_line + '\n')


@front.route('/<path:path>',methods=['POST','GET'])
@front.route('/',methods=['POST','GET'])
@limiter.limit("200/minute;50/second")
def index(path=None):
    if path is None:
        path='{}:/'.format(GetConfig('default_pan'))
    path=urllib.unquote(path).replace('&action=play','')
    if not os.path.exists(os.path.join(config_dir,'.install')):
        resp=MakeResponse(redirect(url_for('admin.install',step=0,user=GetConfig('default_pan'))))
        return resp
    try:
        user,n_path=path.split(':')
    except:
        return MakeResponse(abort(404))
    if n_path=='':
        path=':'.join([user,'/'])
    page=request.args.get('page',1,type=int)
    image_mode=GetCookie(key='image_mode',default=0)
    sortby=GetCookie(key='sortby',default=GetConfig('default_sort'))
    order=GetCookie(key='order',default=GetConfig('order_m'))
    print('sortby:{}, order:{}'.format(sortby,order))
    action=request.args.get('action','download')
    data,total = FetchData(path=path,page=page,per_page=50,sortby=sortby,order=order,dismiss=True)
    
    #ddos protection
    try:
        retry_key = ''.join(e for e in ('retry' + path) if e.isalnum())
        retry = getRetry(retry_key)
        if retry == "":
            retry = 0
        retry = float(retry)
        if(retry == 5):
            retry = (datetime.datetime.now() - datetime.datetime(1900, 1, 1, 0, 0, 0, 0)).total_seconds()
            setRetry(retry_key, retry)
        if(retry > 5):
            last_try = datetime.datetime(1900, 1, 1, 0, 0, 0, 0) + datetime.timedelta(seconds=retry)
            if((datetime.datetime.now() - last_try).total_seconds() > 60):
                #unlock account
                setRetry(retry_key, 0)
            else:
                #lock account for 7 days
                retry = (datetime.datetime.now() - datetime.datetime(1900, 1, 1, 0, 0, 0, 0)).total_seconds()
                setRetry(retry_key, retry)
                return render_template('error.html',msg="Someone was trying your password. Your account has been locked for 7 days. Please contact admin.",code=500), 500
    except:
        exstr = traceback.format_exc()
        ErrorLogger().print_r(exstr)

    #是否有密码
    password,_,cur=has_item(path,'.password')
    ori_pass = password
    md5_p=md5(path)
    has_verify_=has_verify(path)
    if request.method=="POST":
        password1=request.form.get('password')
        #deal with root password
        if len(path.split(':')) == 1 or path.split(':')[1].strip()=='/':
            try:
                for line in password.splitlines():
                    if line != '' and password1 == line:
                        password = password1
                        has_verify_ = True
                        md5_urp=md5('user_root_pass')
                        resp=MakeResponse(redirect(url_for('.index',path=path)))
                        resp.delete_cookie(md5_urp)
                        resp.set_cookie(md5_urp,password1)
                        resp.delete_cookie(md5_p)
                        resp.set_cookie(md5_p,ori_pass)
                        return resp
            except Exception as e:
                exstr = traceback.format_exc()
                return render_template('error.html',msg=exstr,code=500), 500

        if password1==password:
            resp=MakeResponse(redirect(url_for('.index',path=path)))
            resp.delete_cookie(md5_p)
            resp.set_cookie(md5_p,ori_pass)
            return resp
    if password!=False:
        retry = getRetry(retry_key)
        if retry == "":
            retry = 0
        retry = float(retry)
        retry += 1
        setRetry(retry_key,retry)
        setRetryLog("path: " + path + ", password: " +  password1)

        if (not request.cookies.get(md5_p) or request.cookies.get(md5_p)!=password) and has_verify_==False:
            if total=='files' and GetConfig('encrypt_file')=="no":
                return show(data['id'],user,action)
            resp=MakeResponse(render_template('theme/{}/password.html'.format(GetConfig('theme')),path=path,cur_user=user))
            return resp
    if total=='files':
        return show(data['id'],user,action)
    readme,ext_r=GetReadMe(path)
    head,ext_d=GetHead(path)
    #参数
    all_image=False if sum([file_ico(i)!='image' for i in data])>0 else True
    pagination=Pagination(query=None,page=page, per_page=50, total=total, items=None)

    #hide root files, and other users' folders
    try:
        # testing = ''
        if len(path.split(':')) == 1 or path.split(':')[1].strip()=='/':
            md5_urp=md5('user_root_pass')
            user_root_pass = request.cookies.get(md5_urp)
            # testing += 'user_root_pass:' + user_root_pass
            for i in range(len(data) - 1, -1, -1):
                if data[i]['type']=='folder':
                    sub_password,_,_sub_cur=has_item(data[i]['path'],'.password')
                    # testing += '; sub_folder_pass_' + data[i]['path'] + ':' + sub_password + ',sub_cur:' + str(_sub_cur)
                    if sub_password!=False:
                        if sub_password != user_root_pass and _sub_cur:
                            del data[i]
                        #directly go into sub folder
                        if sub_password == user_root_pass:
                            resp=MakeResponse(redirect(url_for('.index',path=data[i]['path'])))
                            md5_sub_p=md5(data[i]['path'])
                            resp.delete_cookie(md5_sub_p)
                            resp.set_cookie(md5_sub_p,sub_password)
                            return resp
                else:
                    del data[i]
            # return render_template('error.html',msg=testing,code=500), 500
    except Exception as e:
        exstr = traceback.format_exc()
        return render_template('error.html',msg=exstr,code=500), 500

    if path.split(':',1)[-1]=='/':
        path=':'.join([path.split(':',1)[0],''])
    resp=MakeResponse(render_template('theme/{}/index.html'.format(GetConfig('theme'))
                    ,pagination=pagination
                    ,items=data
                    ,path=path
                    ,image_mode=image_mode
                    ,readme=readme
                    ,ext_r=ext_r
                    ,head=head
                    ,ext_d=ext_d
                    ,sortby=sortby
                    ,order=order
                    ,cur_user=user
                    ,all_image=all_image
                    ,endpoint='.index'))
    resp.set_cookie('image_mode',str(image_mode))
    resp.set_cookie('sortby',str(sortby))
    resp.set_cookie('order',str(order))
    return resp

@front.route('/file/<user>/<fileid>/<action>')
def show(fileid,user,action='download'):
    name=GetName(fileid)
    ext=name.split('.')[-1].lower()
    path=GetPath(fileid)
    url=request.url.replace(':80','').replace(':443','').encode('utf-8').split('?')[0]
    inner_url='/'+urllib.quote('/'.join(url.split('/')[3:]))
    if request.method=='POST' or action=='share':
        InfoLogger().print_r(u'share page:{}'.format(path))
        if ext in ['csv','doc','docx','odp','ods','odt','pot','potm','potx','pps','ppsx','ppsxm','ppt','pptm','pptx','rtf','xls','xlsx']:
            downloadUrl,play_url=GetDownloadUrl(fileid,user)
            url = 'https://view.officeapps.live.com/op/view.aspx?src='+urllib.quote(downloadUrl)
            resp=MakeResponse(redirect(url))
        elif ext in ['bmp','jpg','jpeg','png','gif']:
            resp=MakeResponse(render_template('theme/{}/show/image.html'.format(GetConfig('theme')),url=url,inner_url=inner_url,path=path,cur_user=user))
        elif ext in ['mp4','webm']:
            resp=MakeResponse(render_template('theme/{}/show/video.html'.format(GetConfig('theme')),url=url,inner_url=inner_url,path=path,cur_user=user))
        elif ext in ['avi','mpg', 'mpeg', 'rm', 'rmvb', 'mov', 'wmv', 'mkv', 'asf']:
            resp=MakeResponse(render_template('theme/{}/show/video2.html'.format(GetConfig('theme')),url=url,inner_url=inner_url,path=path,cur_user=user))
        elif ext in ['ogg','mp3','wav']:
            resp=MakeResponse(render_template('theme/{}/show/audio.html'.format(GetConfig('theme')),url=url,inner_url=inner_url,path=path,cur_user=user))
        elif CodeType(ext) is not None:
            content=common._remote_content(fileid,user)
            resp=MakeResponse(render_template('theme/{}/show/code.html'.format(GetConfig('theme')),content=content,url=url,inner_url=inner_url,language=CodeType(ext),path=path,cur_user=user))
        elif name=='.password':
            resp=MakeResponse(abort(404))
        else:
            downloadUrl,play_url=GetDownloadUrl(fileid,user)
            resp=MakeResponse(redirect(downloadUrl))
        return resp
    InfoLogger().print_r('action:{}'.format(action))
    if name=='.password':
        resp=MakeResponse(abort(404))
    if 'no-referrer' in GetConfig('allow_site').split(',') or sum([i in referrer for i in GetConfig('allow_site').split(',')])>0:
        downloadUrl,play_url=GetDownloadUrl(fileid,user)
        if not downloadUrl.startswith('http'):
            return MakeResponse(downloadUrl)
        if ext in ['webm','avi','mpg', 'mpeg', 'rm', 'rmvb', 'mov', 'wmv', 'mkv', 'asf']:
            if action=='play':
                resp=MakeResponse(redirect(play_url))
            else:
                resp=MakeResponse(redirect(downloadUrl))
        else:
            resp=MakeResponse(redirect(play_url))
    else:
        resp=MakeResponse(abort(404))
    return resp



@front.route('/py_find/<key_word>')
def find(key_word):
    page=request.args.get('page',1,type=int)
    ajax=request.args.get('ajax','no')
    image_mode=request.args.get('image_mode')
    sortby=request.args.get('sortby')
    order=request.args.get('order')
    action=request.args.get('action','download')
    data,total=FetchData(path=key_word,page=page,per_page=50,sortby=sortby,order=order,dismiss=True,search_mode=True)
    pagination=Pagination(query=None,page=page, per_page=50, total=total, items=None)
    if ajax=='yes':
        retdata={}
        retdata['code']=0
        retdata['msg']=""
        retdata['total']=total
        retdata['data']=[]
        for d in data:
            info={}
            if d['type']=='folder':
                info['name']='<a href="'+url_for('.index',path=d['path'])+'">'+d['name']+'</a>'
            else:
                info['name']='<a href="'+url_for('.index',path=d['path'],action='share')+'" target="_blank">'+d['name']+'</a>'
            info['type']=d['type']
            info['lastModtime']=d['lastModtime']
            info['size']=d['size']
            info['path']=d['path']
            info['id']=d['id']
            retdata['data'].append(info)
        return jsonify(retdata)
    resp=MakeResponse(render_template('theme/{}/find.html'.format(GetConfig('theme'))
                    ,pagination=pagination
                    ,items=data
                    ,path='/'
                    ,sortby=sortby
                    ,order=order
                    ,key_word=key_word
                    ,cur_user='搜索:"{}"'.format(key_word)
                    ,endpoint='.find'))
    resp.set_cookie('image_mode',str(image_mode))
    resp.set_cookie('sortby',str(sortby))
    resp.set_cookie('order',str(order))
    return resp

@front.route('/robots.txt')
def robot():
    resp="""
User-agent:  *
Disallow:  /
    """
    resp=MakeResponse(resp)
    resp.headers['Content-Type'] = 'text/javascript; charset=utf-8'
    return resp

@front.route('/add_folder',methods=['POST'])
def AddFolder():
    folder_name=request.form.get('folder_name')
    path=request.args.get('path')
    user,grand_path=path.split(':')
    if grand_path=='' or grand_path is None:
        grand_path='/'
    else:
        if grand_path.startswith('/'):
            grand_path=grand_path[1:]

    password,_,cur=has_item(path,'.password')
    md5_urp=md5('user_root_pass')
    password1 = request.cookies.get(md5_urp)
    if(password != "" and password != password1):
        result = False
        retdata={}
        retdata['result']=result
        # retdata['msg'] = str(password) + "   " + str(password1)
        return jsonify(retdata)
    result=CreateFolder(folder_name,grand_path,user)
    return jsonify({'result':result})


@front.route('/upload_local',methods=['POST','GET'])
def upload_local():
    path = request.args.get('path')
    password,_,cur=has_item(path,'.password')
    md5_urp=md5('user_root_pass')
    password1 = request.cookies.get(md5_urp)
    if(password != "" and password != password1):
        return render_template('error.html',msg="error",code=500), 500

    user,remote_folder=request.args.get('path').split(':')
    resp=MakeResponse(render_template('theme/{}/upload_local.html'.format(GetConfig('theme')),remote_folder=remote_folder,cur_user=user))
    # resp=MakeResponse(render_template('admin/manage/upload_local.html',remote_folder=remote_folder,cur_user=user))
    return resp


@front.route('/recv_upload', methods=['POST'])
def recv_upload():  # 接收前端上传的一个分片

    # pass 'path' failed
    # path=request.form.get('path')
    # password,_,cur=has_item(path,'.password')
    # md5_urp=md5('user_root_pass')
    # password1 = request.cookies.get(md5_urp)
    # if(password != "" and password != password1):
    #     return render_template('error.html',msg="error",code=500), 500

    md5=request.form.get('fileMd5')
    name=request.form.get('name').encode('utf-8')
    chunk_id=request.form.get('chunk',0,type=int)
    filename = '{}-{}'.format(name,chunk_id)
    upload_file = request.files['file']
    upload_file.save(u'./upload/{}'.format(filename))
    return jsonify({'upload_part':True})


@front.route('/to_one',methods=['GET'])
def server_to_one():
    user=request.args.get('user')
    filename=request.args.get('filename').encode('utf-8')
    remote_folder=request.args.get('remote_folder').encode('utf-8')

    path = user + ":" + remote_folder
    password,_,cur=has_item(path,'.password')
    md5_urp=md5('user_root_pass')
    password1 = request.cookies.get(md5_urp)
    if(password != "" and password != password1):
        return render_template('error.html',msg="error",code=500), 500

    try:
        # session['login']='true'
        if remote_folder!='/':
            remote_folder=remote_folder+'/'
        local_dir=os.path.join(config_dir,'upload')
        filepath=urllib.unquote(os.path.join(local_dir,filename))
        _upload_session=Upload_for_server(filepath,remote_folder,user)
        def read_status():
            while 1:
                try:
                    msg=_upload_session.next()['status']
                    yield "data:" + msg + "\n\n"
                except Exception as e:
                    exstr = traceback.format_exc()
                    ErrorLogger().print_r(exstr)
                    msg='end'
                    yield "data:" + msg + "\n\n"
                    os.remove(filepath)
                    break
        return Response(read_status(), mimetype= 'text/event-stream')
    except Exception as e:
        exstr = traceback.format_exc()
        ErrorLogger().print_r(exstr)
        return render_template('error.html',msg="error",code=500), 500
    # finally:
        # session.pop('login',None)

@front.route('/delete',methods=["POST"])
def delete():
    ids=request.form.get('id')
    user=request.form.get('user')
    if ids is None:
        return jsonify({'msg':u'Please select files you want to delete','status':0})
    ids=ids.split('##')
    infos={}
    infos['status']=1
    infos['delete']=0
    infos['fail']=0

    md5_urp=md5('user_root_pass')
    password1 = request.cookies.get(md5_urp)

    for id in ids:
        InfoLogger().print_r('delete {}'.format(id))
        file=mon_db.items.find_one({'id':id})
        name=file['name']
        path=file['path'].replace(name,'')
        if len(path.split('/'))>2 and path.split('/')[-1]=='':
            path=path[:-1]

        password,_,cur=has_item(path,'.password')
        if(password != "" and password != password1):
            infos['fail']+=1
            infos['status']=0
            infos['msg']="User authentication failed!"
            return jsonify(infos)
        
        key='has_item$#$#$#$#{}$#$#$#$#{}'.format(path,name)
        InfoLogger().print_r('delete key:{}'.format(key))
        redis_client.delete(key)
        kc='{}:content'.format(id)
        redis_client.delete(kc)
        status=DeleteRemoteFile(id,user)
        if status:
            infos['delete']+=1
        else:
            infos['fail']+=1
    return jsonify(infos)

@front.route('/rename',methods=['POST'])
def Rename():
    fileid=request.form.get('fileid')

    file=mon_db.items.find_one({'id':fileid})
    name=file['name']
    path=file['path'].replace(name,'')
    if len(path.split('/'))>2 and path.split('/')[-1]=='':
        path=path[:-1]
    password,_,cur=has_item(path,'.password')
    md5_urp=md5('user_root_pass')
    password1 = request.cookies.get(md5_urp)
    if(password != "" and password != password1):
        return jsonify({'result':False})

    user=request.form.get('user')
    new_name=request.form.get('new_name')
    if new_name=='' or new_name is None:
        return jsonify({'result':False})
    else:
        if new_name.startswith('/'):
            new_name=new_name[1:]
        if new_name.endswith('/'):
            new_name=new_name[:-1]
    result=ReName(fileid,new_name,user)
    return jsonify({'result':result})


