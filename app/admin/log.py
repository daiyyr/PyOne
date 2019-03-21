#-*- coding=utf-8 -*-
from base_view import *



@admin.route('/logs',methods=["POST","GET"])
def logs():
    logname=request.args.get('logname','running')
    command='{}_log'.format(logname)
    resp=MakeResponse(render_template('admin/logs.html',command=command,logname=logname))
    return resp

