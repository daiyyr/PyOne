#-*- coding=utf-8 -*-
from base_view import *
import uuid
import os
import time


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
    if request.method=='POST':
        # Search the selected dirve, if user's folder exists, do nothing. If not:
        # Add folder with MS account name in the selected drive;
        # Add a new line in root .password as random password;
        # Add the same password in .password under user's folder.
        drive = request.form.get('drive','')
        account = request.form.get('email','')
        user_folder_exist = False
        users=json.loads(redis_client.get("users"))
        drive_root_password = None
        drive_root_path = ""
        root_pass_file_exist = False
        root_pass_id = None
        if(account == ""):
            flash('Invalid account!')
            resp=MakeResponse(render_template('admin/setting/user.html'))
            return resp

        for user,value in users.items():
            if user == drive:
                drive_root_path = '{}:/'.format(user)
                drive_root_password,root_pass_id,cur=has_item(drive_root_path,'.password')

                if drive_root_password is not None and drive_root_password != False:
                    root_pass_file_exist = True
            data,total = FetchData(path='{}:/'.format(user),page=1,per_page=50000,dismiss=True)
            for i in range(len(data) - 1, -1, -1):
                if data[i]['type']=='folder':
                    if account == data[i]['name']:
                        user_folder_exist = True
                        break

        if user_folder_exist:
            flash('Failed! User '+account+' already exists.')
            return MakeResponse(render_template('admin/setting/user.html'))
        
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
            flash('Creating user folder failed!')
            return MakeResponse(render_template('admin/setting/user.html'))

        check_data=mon_db.items.find_one({'path': os.path.join(drive_root_path,folder_name)})
        wait_time = 0
        while not check_data:
            time.sleep(0.1)
            wait_time += 0.1
            check_data=mon_db.items.find_one({'path':os.path.join(drive_root_path, folder_name)})
            if wait_time >= 20:
                flash('Creating user folder failed!')
                return MakeResponse(render_template('admin/setting/user.html'))

        new_password = str(uuid.uuid4()).replace("-","")[:16]
        if drive_root_password is None or not drive_root_password:
            drive_root_password = new_password
        else:
            drive_root_password = drive_root_password + '\n' + new_password

        #edit or create root .password
        if root_pass_file_exist:
            EditFile(fileid=root_pass_id,content=drive_root_password,user=user)
            wait_time = 0
            check_data = False
            while not check_data:
                time.sleep(0.1)
                wait_time += 0.1
                check_data=mon_db.items.find_one({'id':root_pass_id})
                if wait_time >= 20:
                    flash('Editing root password failed!')
                    return MakeResponse(render_template('admin/setting/user.html'))

        else:
            if path.split(':')[-1]=='':
                path=path.split(':')[0]+':/'
            user,n_path=path.split(':')
            CreateFile(filename='.password',path=n_path,content=drive_root_password,user=user)
            wait_time = 0
            check_data = False
            while not check_data:
                time.sleep(0.1)
                wait_time += 0.1
                check_data=mon_db.items.find_one({'path':os.path.join(drive_root_path, '.password')})
                if wait_time >= 20:
                    flash('Creating root password failed!')
                    return MakeResponse(render_template('admin/setting/user.html'))
    
        #create sub folder's .password
        path = os.path.join(drive_root_path, folder_name)
        if path.split(':')[-1]=='':
            path=path.split(':')[0]+':/'
        user,n_path=path.split(':')
        CreateFile(filename='.password',path=n_path,content=new_password,user=user)
        wait_time = 0
        check_data = False
        while not check_data:
            time.sleep(0.1)
            wait_time += 0.1
            check_data=mon_db.items.find_one({'path':os.path.join(path, '.password')})
            if wait_time >= 20:
                flash('Creating user folder password failed!')
                return MakeResponse(render_template('admin/setting/user.html'))


        flash('Succeed! User '+account+' have been created!')

        resp=MakeResponse(render_template('admin/setting/user.html'))
        return resp

    resp=MakeResponse(render_template('admin/setting/user.html'))
    return resp
