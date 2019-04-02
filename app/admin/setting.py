#-*- coding=utf-8 -*-
from base_view import *
import uuid
import os

########admin
@admin.route('/',methods=['GET','POST'])
@admin.route('/setting',methods=['GET','POST'])
def setting():
    if request.method=='POST':
        if request.files.keys()!=[]:
            favicon=request.files['favicon']
            favicon.save('./app/static/img/favicon.ico')
        title=request.form.get('title','PyOne')
        theme=request.form.get('theme','material')
        title_pre=request.form.get('title_pre','index of ')
        downloadUrl_timeout=request.form.get('downloadUrl_timeout',5*60)
        allow_site=request.form.get('allow_site','no-referrer')
        #Aria2
        ARIA2_HOST=request.form.get('ARIA2_HOST','localhost').replace('https://','').replace('http://','')
        ARIA2_PORT=request.form.get('ARIA2_PORT',6800)
        ARIA2_SECRET=request.form.get('ARIA2_SECRET','')
        ARIA2_SCHEME=request.form.get('ARIA2_SCHEME','http')

        #MongoDB
        MONGO_HOST=request.form.get('MONGO_HOST','localhost').replace('https://','').replace('http://','')
        MONGO_PORT=request.form.get('MONGO_PORT',27017)
        MONGO_DB=request.form.get('MONGO_DB','three')
        MONGO_USER=request.form.get('MONGO_USER','')
        MONGO_PASSWORD=request.form.get('MONGO_PASSWORD','')
        #Redis
        REDIS_HOST=request.form.get('REDIS_HOST','localhost').replace('https://','').replace('http://','')
        REDIS_PORT=request.form.get('REDIS_PORT',6379)
        REDIS_DB=request.form.get('REDIS_DB','0')
        REDIS_PASSWORD=request.form.get('REDIS_PASSWORD','')

        order_m=request.form.get('order_m','desc')
        default_sort=request.form.get('default_sort','lastModtime')
        show_secret=request.form.get('show_secret','no')
        encrypt_file=request.form.get('encrypt_file','no')
        set('title',title)
        set('title_pre',title_pre)
        set('theme',theme)
        set('downloadUrl_timeout',downloadUrl_timeout)
        set('allow_site',allow_site)
        #Aria2
        set('ARIA2_HOST',ARIA2_HOST)
        set('ARIA2_PORT',ARIA2_PORT)
        set('ARIA2_SECRET',ARIA2_SECRET)
        set('ARIA2_SCHEME',ARIA2_SCHEME)
        #MongoDB
        set('MONGO_HOST',MONGO_HOST)
        set('MONGO_PORT',MONGO_PORT)
        set('MONGO_DB',MONGO_DB)
        set('MONGO_USER',MONGO_USER)
        set('MONGO_PASSWORD',MONGO_PASSWORD)
        #Redis
        set('REDIS_HOST',REDIS_HOST)
        set('REDIS_PORT',REDIS_PORT)
        set('REDIS_DB',REDIS_DB)
        set('REDIS_PASSWORD',REDIS_PASSWORD)

        set('default_sort',default_sort)
        set('order_m',order_m)
        set('show_secret',show_secret)
        set('encrypt_file',encrypt_file)
        # reload()
        redis_client.set('title',title)
        redis_client.set('title_pre',title_pre)
        redis_client.set('theme',theme)
        redis_client.set('downloadUrl_timeout',downloadUrl_timeout)
        redis_client.set('allow_site',','.join(allow_site.split(',')))
        #Aria2
        redis_client.set('ARIA2_HOST',ARIA2_HOST)
        redis_client.set('ARIA2_PORT',ARIA2_PORT)
        redis_client.set('ARIA2_SECRET',ARIA2_SECRET)
        redis_client.set('ARIA2_SCHEME',ARIA2_SCHEME)

        #MongoDB
        redis_client.set('MONGO_HOST',MONGO_HOST)
        redis_client.set('MONGO_PORT',MONGO_PORT)
        redis_client.set('MONGO_DB',MONGO_DB)
        redis_client.set('MONGO_USER',MONGO_USER)
        redis_client.set('MONGO_PASSWORD',MONGO_PASSWORD)

        #Redis
        redis_client.set('REDIS_HOST',REDIS_HOST)
        redis_client.set('REDIS_PORT',REDIS_PORT)
        redis_client.set('REDIS_DB',REDIS_DB)
        redis_client.set('REDIS_PASSWORD',REDIS_PASSWORD)

        redis_client.set('default_sort',default_sort)
        redis_client.set('order_m',order_m)
        redis_client.set('show_secret',show_secret)
        redis_client.set('encrypt_file',encrypt_file)
        flash('Updating succeed')
        resp=MakeResponse(redirect(url_for('admin.setting')))
        return resp
    resp=MakeResponse(render_template('admin/setting/setting.html'))
    return resp


@admin.route('/setCode',methods=['GET','POST'])
def setCode():
    if request.method=='POST':
        tj_code=request.form.get('tj_code','')
        headCode=request.form.get('headCode','')
        footCode=request.form.get('footCode','')
        cssCode=request.form.get('cssCode','')
        #redis
        set('tj_code',tj_code)
        set('headCode',headCode)
        set('footCode',footCode)
        set('cssCode',cssCode)
        # reload()
        redis_client.set('tj_code',tj_code)
        redis_client.set('headCode',headCode)
        redis_client.set('footCode',footCode)
        redis_client.set('cssCode',cssCode)
        flash('Updating succeed')
        resp=MakeResponse(render_template('admin/setCode/setCode.html'))
        return resp
    resp=MakeResponse(render_template('admin/setCode/setCode.html'))
    return resp


@admin.route('/user',methods=['GET','POST'])
def user():
    drivelist=[]
    users=json.loads(redis_client.get("users"))
    for user,value in users.items():
        if value.get('client_id')!='':
            drivelist.append(user
                (
                    user,
                    value.get('other_name')
                )
            )
    if request.method=='POST':
        # Search the selected dirve, if user's folder exists, do nothing. If not:
        # Add folder with MS account name in the selected drive;
        # Add a new line in root .password as random password;
        # Add the same password in .password under user's folder.
        drive = request.form.get('drive','')
        account = request.form.get('email','')
        user_folder_exist = False
        users=json.loads(redis_client.get("users"))
        drive_root_password = ""
        drive_root_path = ""
        for user,value in users.items():
            if user == drive:
                drive_root_path = '{}:/'.format(user)
                drive_root_password,_,cur=has_item(drive_root_path,'.password')
                data,total = FetchData(path=drive_root_path,page=page,per_page=50,sortby=sortby,order=order,dismiss=True)
                for i in range(len(data) - 1, -1, -1):
                    if data[i]['type']=='folder':
                        if account == data[i]['name']:
                            user_folder_exist = True
                            break

                break
        if user_folder_exist:
            flash('Failed! User already exists.')
        else:
            folder_name=account
            path=drive_root_path
            user,grand_path=path.split(':')
            if grand_path=='' or grand_path is None:
                grand_path='/'
            else:
                if grand_path.startswith('/'):
                    grand_path=grand_path[1:]
            result=CreateFolder(folder_name,grand_path,user)
            if not result:
                flash('Creating failed!')
            else:
                new_password = str(uuid.uuid4()).replace("-","")[:16]
                if drive_root_password is None:
                    drive_root_password = new_password
                else:
                    drive_root_password = drive_root_password + '\n' + new_password
                rootpassfile = os.path.join(drive_root_path,'.password')
                with open(rootpassfile,'w') as new_file:
                    new_file.write(drive_root_password)
                
                folderpassfile = os.path.join(drive_root_path, folder_name, '.password')
                with open(folderpassfile,'w') as new_file:
                    new_file.write(new_password)

                flash('New user have been added!')
        resp=MakeResponse(
            render_template('admin/setting/user.html',
            drivelist = drivelist
            ))
        return resp
    resp=MakeResponse(render_template('admin/setting/user.html',
            drivelist = drivelist
            ))
    return resp
