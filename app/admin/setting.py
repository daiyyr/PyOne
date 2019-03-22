#-*- coding=utf-8 -*-
from base_view import *

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

        # testing_filed=request.form.get('testing_filed','testing testing')

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
        # set('title', testing_filed)
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
        # redis_client.set('title',testing_filed)
        
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
        flash('更新成功')
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
        flash('更新成功')
        resp=MakeResponse(render_template('admin/setCode/setCode.html'))
        return resp
    resp=MakeResponse(render_template('admin/setCode/setCode.html'))
    return resp
