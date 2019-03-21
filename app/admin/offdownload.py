#-*- coding=utf-8 -*-
from base_view import *




######离线下载---调用aria2
@admin.route('/off_download',methods=['POST','GET'])
def off_download():
    if request.method=='POST':
        p,status=get_aria2()
        if not status:
            return jsonify({'status':False,'msg':p})
        urls=request.form.get('urls').split('\n')
        grand_path=request.form.get('grand_path')
        user=request.form.get('user')
        for url in urls:
            if url.strip()!='':
                # cmd=u'python {} download_and_upload "{}" "{}" {}'.format(os.path.join(config_dir,'function.py'),url,grand_path,user)
                cmd=u'nohup python {} download_and_upload "{}" "{}" {} &'.format(os.path.join(config_dir,'function.py'),url,grand_path,user)
                subprocess.Popen(cmd,shell=True)
        return jsonify({'status':True,'msg':'ok'})
    path=request.args.get('path')
    user,grand_path=path.split(':')
    msg=None
    p,status=get_aria2()
    if not status:
        msg=p
    resp=MakeResponse(render_template('admin/offdownload.html',grand_path=grand_path,cur_user=user,msg=msg))
    return resp


@admin.route('/jsonrpc',methods=['POST'])
def RPCserver():
    action=request.form.get('action')
    allow_action=['tellActive','tellSuccess','tellFail','tellUnselected','pause','pauseAll','unpause','unpauseAll','remove','removeAll','restart','unselected','selected']
    action_dict=dict(tellActive=1,tellSuccess=0,tellFail=-1,tellUnselected=2)
    if action not in allow_action:
        return jsonify({'code':0,'msg':'not allow action'})
    if action in ['tellActive','tellSuccess','tellFail','tellUnselected']:
        status=action_dict[action]
        ret={'code':1,'msg':'get data success','result':get_tasks(status)}
    elif action in ['pause','pauseAll','unpause','unpauseAll','remove','removeAll','restart','unselected','selected']:
        ret=None
        gids=request.form.get('gid').split('####')
        ret1=Aria2Method(action=action,gids=gids)
        ret2=DBMethod(action=action,gids=gids)
        if ret1 is not None:
            ret=ret1
        else:
            ret=ret2
    return jsonify(ret)

@admin.route('/clearHist',methods=['POST'])
def clearHist():
    mon_db.down_db.delete_many({})
    ret={'msg':'清除成功！'}
    return jsonify(ret)
