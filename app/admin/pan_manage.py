#-*- coding=utf-8 -*-
from base_view import *



###########################################Drive管理
@admin.route('/panage',methods=['GET','POST'])
def panage():
    if request.method=='POST':
        ####Drive信息处理
        for k,v in request.form.to_dict().items():
            if 'share_path' in k or 'other_name' in k:
                user=re.findall('\[(.*?)\]',k)[0]
                key=re.findall('(.*)\[',k)[0]
                InfoLogger().print_r('setting {}\'s {}\'s value {}'.format(user,key,v))
                set(key,v,user)
        config_path=os.path.join(config_dir,'self_config.py')
        with open(config_path,'r') as f:
            text=f.read()
        redis_client.set('users',re.findall('od_users=([\w\W]*})',text)[0])
        flash('Updating succeed')
        resp=MakeResponse(redirect(url_for('admin.panage')))
        return resp
    resp=MakeResponse(render_template('admin/pan_manage/pan_manage.html'))
    return resp


@admin.route('/add_pan',methods=["POST","GET"])
def add_pan():
    if request.method=='POST':
        title=request.form.get('title','PyOne')
        pan=request.form.get('pan',''.join(random.sample(string.ascii_letters,2)))
        if pan in od_users.keys():
            flash('盘位重复！')
            return redirect(url_for('admin.add_pan'))
        order=request.form.get('order',0,type=int)
        info={"client_id":"",
                "client_secret":"",
                "share_path":"/",
                "other_name":title,
                "order":order
            }
        od_users[pan]=info
        config_path=os.path.join(config_dir,'self_config.py')
        with open(config_path,'r') as f:
            old_text=f.read()
        with open(config_path,'w') as f:
            old_od=re.findall('od_users={[\w\W]*}',old_text)[0]
            new_od='od_users='+json.dumps(od_users,indent=4,ensure_ascii=False)
            print(new_od)
            new_text=old_text.replace(old_od,new_od,1)
            f.write(new_text)
        flash('添加盘符[{}]成功'.format(pan))
        key='users'
        redis_client.delete(key)
        return redirect(url_for('admin.add_pan'))
    return render_template('admin/pan_manage/add_pan.html')


@admin.route('/rm_pan',methods=["POST","GET"])
def rm_pan():
    if request.method=='POST':
        pan=request.form.get('user')
        od_users.pop(pan)
        config_path=os.path.join(config_dir,'self_config.py')
        with open(config_path,'r') as f:
            old_text=f.read()
        with open(config_path,'w') as f:
            old_od=re.findall('od_users={[\w\W]*}',old_text)[0]
            new_od='od_users='+json.dumps(od_users,indent=4,ensure_ascii=False)
            new_text=old_text.replace(old_od,new_od,1)
            f.write(new_text)
        key='users'
        redis_client.delete(key)
        mon_db.items.delete_many({'user':pan})
        data=dict(msg='Succeed to delete drive [{}]'.format(pan),status=1)
        return jsonify(data)
    return render_template('admin/pan_manage/rm_pan.html')



@admin.route('/setDefaultPan',methods=["POST"])
def setDefaultPan():
    pan=request.form.get('pan')
    set('default_pan',pan)
    redis_client.set('default_pan',pan)
    return jsonify({'msg':'Succeed to change'})


