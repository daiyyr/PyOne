#!/etc/bash
function wget_exists(){
    echo "1. 安装wget";
    which wget > /dev/null 2>&1
    if [ $? == 0 ]; then
        echo "wget exist"
    else
        echo "wget dose not exist"
        yum install wget
    fi
}

function git_exists(){
    echo "2. 安装git";
    which git > /dev/null 2>&1
    if [ $? == 0 ]; then
        echo "git exist"
    else
        echo "git dose not exist"
        yum install git
    fi
}
#安装pip
function pip_exists(){
    echo "3. 安装pip";
    which pip > /dev/null 2>&1
    if [ $? == 0 ]; then
        echo "pip exist"
    else
        echo "pip dose not exist"
        wget https://bootstrap.pypa.io/get-pip.py
        python get-pip.py
        rm -rf get-pip.py
    fi
}

#安装python依赖包
function install_(){
    echo "4. 安装python依赖包";
    pip install -r requirements.txt -U
}

#配置文件
function config_file(){
    echo "5. 配置文件";
    cur_dir=`pwd`
    cp self_config.py.sample self_config.py
    cp supervisord.conf.sample supervisord.conf
    mkdir /var/run/supervisor
    chmod +x /var/run/supervisor
    sed -i "s|/root/PyOne|$cur_dir|" self_config.py
    sed -i "s|/root/PyOne|$cur_dir|" supervisord.conf
}

#添加开机任务
function auto_boot(){
    echo "6. 配置开机启动";
    cur_dir=`pwd`
    echo "supervisord -c $cur_dir/supervisord.conf" >> /etc/rc.d/rc.local
    echo "sh /data/aria2/aria2.sh start" >> /etc/rc.d/rc.local
    chmod +x /etc/rc.d/rc.local
    # sh /data/arai2/aria2.sh start
}


#安装aria2
function install_aria2(){
    echo "7. 安装aria2";
    which aria2c > /dev/null 2>&1
    if [ $? == 0 ]; then
        echo "检测到已安装aria2"
        echo "请到后台配置aria2信息"
        echo "如果您配置了aria2授权信息，请确保是rpc-secret模式！如果不是，则不能正常工作。"
        echo "开启rpc-secret模式方法："
        echo "  >1. 编辑aria2的配置文件，将rpc-secret这一行反注释，然后'rpc-secret='后面填写密码"
        echo "  >2. 将rpc-user和rpc-passwd注释掉"
        echo "  >3. 重启aria2"
    else
        git clone https://github.com/abbeyokgo/aria2_installer.git
        cd aria2_installer
        sh install_aria2.sh
        echo "安装aria2完成"
        echo "如果已经成功安装，请到后台配置aria2信息"
        cd ..
        rm -rf aria2_installer
    fi
}

#开放端口
function open_port(){
    if [ -e "/etc/sysconfig/iptables" ]
        then
            iptables -I INPUT -p tcp --dport 34567 -j ACCEPT
            service iptables save
            service iptables restart
        else
            firewall-cmd --zone=public --add-port=34567/tcp --permanent
            firewall-cmd --reload
        fi
}





#执行
wget_exists
git_exists
pip_exists
install_
config_file
auto_boot
install_aria2
open_port
yum install lsof
mkdir logs
echo "---------------------------------------------------------------"
echo "一键脚本运行完成！请检查以下文件："
echo "  > 1. self_config.py、supervisord.conf是否存在！"
echo "  > 2. 检查self_config.py、supervisord.conf脚本里面的目录是否正确！"
echo "  > 3. 请确保已经安装Nginx、Redis、MongoDB，并已经运行！"
echo "  > 4. 检查/data/aria2是否存在。"
echo "  > 5. 检查aria2是否运行：pgrep 'aria2c'"
echo "    如果aria2没有运行，运行：sh /data/aria2/aria2.sh start"
echo
echo "如果检查没有问题！在网站目录可运行以下脚本运行网站"
echo "supervisord -c supervisord.conf"
echo "---------------------------------------------------------------"
echo
echo "PyOne交流群：864996565"

