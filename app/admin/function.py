#-*- coding=utf-8 -*-
from base_view import *
import os


###
@admin.route('/login',methods=["POST","GET"])
def login():
    if request.method=='POST':
        password1=request.form.get('password')
        if password1==GetConfig('password'):
            session['login']='true'
            if not os.path.exists(os.path.join(config_dir,'.install')):
                resp=MakeResponse(redirect(url_for('admin.install',step=0,user='A')))
                return resp
            resp=MakeResponse(redirect(url_for('admin.setting')))
        else:
            resp=MakeResponse(render_template('admin/login.html'))
        return resp
    if session.get('login'):
        return redirect(url_for('admin.setting'))
    resp=MakeResponse(render_template('admin/login.html'))
    return resp

@admin.route('/logout',methods=['GET','POST'])
def logout():
    session.pop('login',None)
    return redirect('/')    

@admin.route('/reload',methods=['GET','POST'])
def reload():
    cmd='supervisorctl -c {} restart pyone'.format(os.path.join(config_dir,'supervisoredis_client.conf'))
    subprocess.Popen(cmd,shell=True)
    flash('rebooting...if shared directory is changed, please clean your browser cache')
    return redirect(url_for('admin.setting'))

@admin.route('/setPass',methods=['POST'])
def setPass():
    new_password=request.form.get('new_password')
    old_password=request.form.get('old_password')
    if old_password==GetConfig('password'):
        set('password',new_password)
        redis_client.set('password',new_password)
        data={'msg':'changing password succeed!'}
    else:
        data={'msg':'Original password is incorrect!'}
    return jsonify(data)


@admin.route('/unlock',methods=['POST'])
def unlock():
    try:
        retrykeyfile = os.path.join(config_dir,'logs/PyOne.password.retry.key')
        open(retrykeyfile, 'w').close()
        data={'msg':'All accounts have been unlocked!'}
    except:
        data={'msg':'Failed to unlock accounts!'}
    return jsonify(data)


@admin.route('/UpdatePyOne')
def UpdatePyOne():
    html="""
    <style type="text/css">
    #output {
        background-color: #000000;
        color: #fff;
        font-family: monospace, fixed;
        font-size: 15px;
        line-height: 18px;
    }
    </style>
    <textarea rows="20" placeholder="" id="output" style="width:100%;max-heigth:100%;"></textarea>
    <script type="text/javascript">
        var source = new EventSource("/admin/stream?command=##request_url##");
        source.onmessage = function(event) {
            if(event.data=='end'){
                source.close();
            }
            else{
                document.getElementById("output").innerHTML += event.data + "\\n";
                document.getElementById("output").scrollTop = document.getElementById('output').scrollHeight;
            }
          }
          source.addEventListener('error',function(e){
              source.close();
          })
    </script>
    """
    html=html.replace('##request_url##','upgrade')
    return MakeResponse(html)


