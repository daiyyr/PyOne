#-*- coding=utf-8 -*-
from base_view import *



@admin.route('/cache',methods=["POST","GET"])
def cache_control():
    if request.method=='POST':
        type=request.form.get('type')
        cmd="python -u {} UpdateFile {}".format(os.path.join(config_dir,'function.py'),type)
        subprocess.Popen(cmd,shell=True)
        msg='Backend data refreshing...Please do not multi-click'
        return jsonify(dict(msg=msg))
    resp=MakeResponse(render_template('admin/cache.html'))
    return resp
