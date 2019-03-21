#-*- coding=utf-8 -*-
from base_view import *

###upload
@admin.route('/upload',methods=["POST","GET"])
def upload():
    if request.method=='POST':
        user=request.form.get('user').encode('utf-8')
        local=request.form.get('local').encode('utf-8')
        remote=request.form.get('remote').encode('utf-8')
        if not os.path.exists(local):
            flash('本地目录/文件不存在')
            return redirect(url_for('admin.upload'))
        if os.path.isfile(local):
            filelists=[local]
        else:
            filelists=list_all_files(local)
        if local.endswith('/'):
            local=local[:-1]
        for file in filelists:
            print(file)
            info={}
            dir_,fname=os.path.dirname(file),os.path.basename(file)
            remote_path=remote+'/'+dir_.replace(local,'')+'/'+fname
            remote_path=remote_path.replace('//','/')
            info['user']=user
            info['localpath']=file
            info['remote']=remote_path
            info['status']=''
            info['speed']=''
            info['id']=base64.b64encode(str(int(round(time.time())))+file)
            info['add_time']=int(round(time.time()))
            mon_db.upload_queue.insert_one(info)
        cmd='python {}/function.py StartUploadQueue'.format(config_dir)
        subprocess.Popen(cmd,shell=True)
        resp=redirect(url_for('admin.upload'))
        return resp
    page=request.args.get('page',1,type=int)
    resp=MakeResponse(render_template('admin/upload.html',page=page))
    return resp

@admin.route('/upload/jsonrpc',methods=['POST'])
def UploadRPCserver():
    action=request.form.get('action')
    page=request.form.get('page',1,type=int)
    if action=='pagination':
        data={'code':1}
        total=get_upload_tasks_no()
        pagination=Pagination(query=None,page=page, per_page=50, total=total, items=None)
        data['page']=page
        data['pages']=pagination.pages
        page_lists=[]
        for p in pagination.iter_pages():
            page_lists.append(p)
        data['page_lists']=page_lists[::-1]
        data['has_prev']=pagination.has_prev
        data['has_next']=pagination.has_next
        return jsonify(data)
    elif action=='ClearHist':
        mon_db.upload_queue.delete_many({})
        ret={'msg':'清除成功！'}
        return jsonify(ret)
    elif action=='Restart':
        cmd='python {}/function.py StartUploadQueue'.format(config_dir)
        subprocess.Popen(cmd,shell=True)
        ret={'msg':'重启成功！'}
        return jsonify(ret)
    ret=get_upload_tasks(page)
    data={'code':1,'result':ret}
    return jsonify(data)



###upload end
