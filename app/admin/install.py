#-*- coding=utf-8 -*-
from base_view import *


###########################################安装
@admin.route('/install',methods=['POST','GET'])
def install():
    if request.method=='POST':
        step=request.form.get('step',type=int)
        user=request.form.get('user')
        if step==1:
            client_id=request.form.get('client_id')
            client_secret=request.form.get('client_secret')
            set('client_id',client_id,user)
            set('client_secret',client_secret,user)
            login_url=LoginUrl.format(client_id=client_id,redirect_uri=redirect_uri)
            return render_template('admin/install/install_1.html',client_secret=client_secret,client_id=client_id,login_url=login_url,cur_user=user)
        else:
            client_secret=request.form.get('client_secret')
            client_id=request.form.get('client_id')
            code=request.form.get('code')
            #授权
            headers={'Content-Type':'application/x-www-form-urlencoded'}
            headers.update(default_headers)
            data=AuthData.format(client_id=client_id,redirect_uri=urllib.quote(redirect_uri),client_secret=client_secret,code=code)
            url=OAuthUrl
            r=requests.post(url,data=data,headers=headers)
            Atoken=json.loads(r.text)
            if Atoken.get('access_token'):
                with open(os.path.join(config_dir,'data/{}_Atoken.json'.format(user)),'w') as f:
                    json.dump(Atoken,f,ensure_ascii=False)
                refresh_token=Atoken.get('refresh_token')
                token=ReFreshToken(refresh_token,user)
                with open(os.path.join(config_dir,'data/{}_token.json'.format(user)),'w') as f:
                    json.dump(token,f,ensure_ascii=False)
                with open(os.path.join(config_dir,'.install'),'w') as f:
                    f.write('4.0')
                config_path=os.path.join(config_dir,'self_config.py')
                with open(config_path,'r') as f:
                    text=f.read()
                redis_client.set('users',re.findall('od_users=([\w\W]*})',text)[0])
                return make_response('<h1>授权成功!<br>请先在<B><a href="/admin/cache" target="_blank">后台-更新列表</a></B>，全量更新数据<br>然后<a href="/?t={}">点击进入首页</a></h1><br>'.format(time.time()))
            else:
                return jsonify(Atoken)
    step=request.args.get('step',type=int)
    user=request.args.get('user','A')
    resp=MakeResponse(render_template('admin/install/install_0.html',step=step,cur_user=user,redirectUrl=redirect_uri))
    return resp

###########################################卸载
@admin.route('/uninstall',methods=['POST'])
def uninstall():
    type_=request.form.get('type')
    if type_=='mongodb':
        mon_db.items.remove()
        mon_db.down_db.remove()
        msg='删除mongodb数据成功'
    elif type_=='redis':
        redis_client.flushdb()
        msg='删除redis数据成功'
    elif type_=='directory':
        subprocess.Popen('rm -rf {}/data/*.json'.format(config_dir),shell=True)
        subprocess.Popen('rm -rf {}/.install'.format(config_dir),shell=True)
        msg='删除网站数据成功'
    else:
        msg='数据已清除！如果需要删除目录请运行:rm -rf {}'.format(config_dir)
    ret={'msg':msg}
    return jsonify(ret)
