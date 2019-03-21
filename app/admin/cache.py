#-*- coding=utf-8 -*-
from base_view import *



@admin.route('/cache',methods=["POST","GET"])
def cache_control():
    if request.method=='POST':
        type=request.form.get('type')
        cmd="python -u {} UpdateFile {}".format(os.path.join(config_dir,'function.py'),type)
        subprocess.Popen(cmd,shell=True)
        msg='后台刷新数据中...请不要多次点击！否则服务器出问题别怪PyOne'
        return jsonify(dict(msg=msg))
    resp=MakeResponse(render_template('admin/cache.html'))
    return resp
