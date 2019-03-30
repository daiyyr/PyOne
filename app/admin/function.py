#-*- coding=utf-8 -*-
from base_view import *
import datetime
import os
import shutil


###
@admin.route('/login',methods=["POST","GET"])
def login():
    retry_key = ''.join(e for e in ('retryAdmin') if e.isalnum())
    retry = getRetry(retry_key)
    if retry == "":
        retry = 0
    retry = float(retry)
    if(retry == 5):
        retry = (datetime.datetime.now() - datetime.datetime(1900, 1, 1, 0, 0, 0, 0)).total_seconds()
        setRetry(retry_key, retry)
    if(retry > 5):
        last_try = datetime.datetime(1900, 1, 1, 0, 0, 0, 0) + datetime.timedelta(seconds=retry)
        if((datetime.datetime.now() - last_try).total_seconds() > 60 * 60 * 24 * 7 ):
            #unlock account
            setRetry(retry_key, 0)
        else:
            #lock account for 7 days
            retry = (datetime.datetime.now() - datetime.datetime(1900, 1, 1, 0, 0, 0, 0)).total_seconds()
            setRetry(retry_key, retry)
            return render_template('error.html',msg="Someone was trying Admin password. Admin has been locked for 7 days. Please contact the IT team.",code=403), 403

    if request.method=='POST':
        password1=request.form.get('password')
        if password1==GetConfig('password'):
            setRetry(retry_key,0)
            session['login']='true'
            session['access_control_panel']='true'
            if not os.path.exists(os.path.join(config_dir,'.install')):
                resp=MakeResponse(redirect(url_for('admin.install',step=0,user='A')))
                return resp
            resp=MakeResponse(redirect(url_for('admin.setting')))
        else:
            retry = getRetry(retry_key)
            if retry == "":
                retry = 0
            retry = float(retry)
            retry += 1
            setRetry(retry_key,retry)
            try:
                ip = request.headers['X-Forwarded-For'].split(',')[0]
            except:
                ip = request.remote_addr
            setRetryLog("path: " + "Admin!!!!!!" + ", password: " +  password1 + ", IP: " + ip)
            resp=MakeResponse(render_template('admin/login.html'))
        return resp
    if session.get('login') and session.get('access_control_panel'):
        return redirect(url_for('admin.setting'))
    resp=MakeResponse(render_template('admin/login.html'))
    return resp

@admin.route('/logout',methods=['GET','POST'])
def logout():
    session.pop('login',None)
    session.pop('access_control_panel',None)
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

def setRetry(key, value):
    retrykeyfile = os.path.join(config_dir,'logs/PyOne.password.retry.key')
    if not os.path.exists(retrykeyfile):
        open(retrykeyfile, 'a').close()
    #Create temp file
    tempFile = os.path.join(config_dir,'logs/PyOne.password.retry.key.temp')
    open(tempFile, 'a').close()
    with open(tempFile,'w') as new_file:
        found = False
        with open(retrykeyfile) as old_file:
            for line in old_file:
                if key == line.split(':')[0]: 
                    new_file.write(key + ":" + str(value) + "\n")
                    found = True
                else:
                    new_file.write(line)
            if not found:
                new_file.write(key + ":" + str(value) + "\n")
    #Remove original file
    os.remove(retrykeyfile)
    #Move new file
    retrykeyfile = os.path.join(config_dir,'logs/PyOne.password.retry.key')
    shutil.move(tempFile, retrykeyfile)


def getRetry(key):
    retrykeyfile = os.path.join(config_dir,'logs/PyOne.password.retry.key')
    if not os.path.exists(retrykeyfile):
        open(retrykeyfile, 'a').close()
    with open(retrykeyfile) as old_file:
        for line in old_file:
            if key == line.split(':')[0]: 
                return line.split(':')[1]
    return ""

def setRetryLog(log_line):
    retrylogfile = os.path.join(config_dir,'logs/PyOne.password.retry.log')
    with open(retrylogfile, 'a') as file:
        file.write(str(datetime.datetime.now()) + " " + log_line + '\n')
