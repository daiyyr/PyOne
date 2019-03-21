#!/etc/bash

#11.20
del_rubbish(){
    python -c "from function import *;mon_db.down_db.delete_many({});"
}

#2019.01.10
update_sp(){
    ps -aux | grep supervisord | awk '{print "kill -9 " $2}'|sh
    rm -rf supervisord.conf
    cp supervisord.conf.sample supervisord.conf
    supervisord -c supervisord.conf
}

#2019.01.18
update_config(){
    num=`cat self_config.py | grep "MONGO_HOST" | wc -l`
    if [ $num == 0 ]; then
        echo '' >> self_config.py
        echo 'MONGO_HOST="localhost"' >> self_config.py
    fi
    num=`cat self_config.py | grep "MONGO_PORT" | wc -l`
    if [ $num == 0 ]; then
        echo '' >> self_config.py
        echo 'MONGO_PORT="27017"' >> self_config.py
    fi
    num=`cat self_config.py | grep "MONGO_USER" | wc -l`
    if [ $num == 0 ]; then
        echo '' >> self_config.py
        echo 'MONGO_USER=""' >> self_config.py
    fi
    num=`cat self_config.py | grep "MONGO_PASSWORD" | wc -l`
    if [ $num == 0 ]; then
        echo '' >> self_config.py
        echo 'MONGO_PASSWORD=""' >> self_config.py
    fi
    num=`cat self_config.py | grep "MONGO_DB" | wc -l`
    if [ $num == 0 ]; then
        echo '' >> self_config.py
        echo 'MONGO_DB="three"' >> self_config.py
    fi
    num=`cat self_config.py | grep "REDIS_HOST" | wc -l`
    if [ $num == 0 ]; then
        echo '' >> self_config.py
        echo 'REDIS_HOST="localhost"' >> self_config.py
    fi

    num=`cat self_config.py | grep "REDIS_PORT" | wc -l`
    if [ $num == 0 ]; then
        echo '' >> self_config.py
        echo 'REDIS_PORT="6379"' >> self_config.py
    fi

    num=`cat self_config.py | grep "REDIS_PASSWORD" | wc -l`
    if [ $num == 0 ]; then
        echo '' >> self_config.py
        echo 'REDIS_PASSWORD=""' >> self_config.py
    fi

    num=`cat self_config.py | grep "REDIS_DB" | wc -l`
    if [ $num == 0 ]; then
        echo '' >> self_config.py
        echo 'REDIS_DB="0"' >> self_config.py
    fi

    num=`cat self_config.py | grep "default_sort" | wc -l`
    if [ $num == 0 ]; then
        echo '' >> self_config.py
        echo 'default_sort="lastModtime"' >> self_config.py
    fi

    num=`cat self_config.py | grep "order_m" | wc -l`
    if [ $num == 0 ]; then
        echo '' >> self_config.py
        echo 'order_m="desc"' >> self_config.py
    fi

    num=`cat self_config.py | grep "default_pan" | wc -l`
    if [ $num == 0 ]; then
        echo '' >> self_config.py
        echo 'default_pan="A"' >> self_config.py
    fi

}



#2019.02.15
upgrade_to4(){
    echo '-------------------------------'
    echo '2019.02.15，PyOne升级为4.0版本！！'
    echo '2019.02.15之前安装的PyOne需重新安装！'
    echo '-------------------------------'
}

#2019.02.16
upgrade(){
    num=`ls | grep .install | wc -l`
    if [ $num == 0 ]; then
        touch .install
    fi
    update_config
    pip install -r requirements.txt
    which lsof > /dev/null 2>&1
    if [ $? == 0 ]; then
        echo "lsof exist"
    else
        echo "lsof dose not exist"
        yum install lsof
    fi
}


restart(){
    supervisorctl -c supervisord.conf restart pyone
}

#执行
upgrade_to4
upgrade
del_rubbish

echo "2018.11.20更新版本，修复了磁力链接下载的bug&上传、展示有特殊字符的文件出问题的bug。"
echo "2018.11.21更新版本，优化磁力下载功能-可选下载文件。"
echo "2018.12.04更新版本，优化磁力下载界面"
echo "2018.12.10更新版本，修复特定分享目录后，二级目录设置密码出错的bug"
echo "2018.12.20更新版本，基础设置之后无需重启网站啦！如果你一直有保存之后不生效的问题，那么本次直接重启服务器吧！"
echo "2019.01.10更新版本，1. 修复防盗链失效的bug；2. 优化开机启动脚本。"
echo "2019.01.13更新版本，修复后台修改密码不生效的bug"
echo "2019.01.14更新版本，修复bug"
echo "2019.01.18更新版本，修复bug；添加搜索功能"
echo "2019.01.21更新版本，添加功能：后台直接添加盘符...避免小白添加配置出现各种问题"
echo "2019.01.23更新版本：修复设置了共享目录后设置README/HEAD/密码出错的bug;优化更新文件列表假死的bug"
echo "2019.01.24更新版本：支持设置加密文件夹下的文件；优化UI"
echo "2019.01.28更新版本：支持自定义代码！"
echo "2019.01.29更新版本：支持设置网站标题前缀；支持自定义主题（待更新设计标准）"
echo "2019.01.30更新版本：提交新主题"
echo "2019.02.15更新版本：新增一键卸载PyOne功能！"
echo "2019.02.16更新版本：优化PyOne4.0安装流程！"
echo "2019.02.19更新版本：优化细节"
echo "2019.02.20更新版本：1. 填坑！2. 后台可配置mongo和redis信息；3. 优化离线下载体验；4. 输出日志"
echo "2019.02.21更新版本：修复自定义代码bug"
echo "2019.02.22更新版本：优化离线下载功能（重启网站后任务不中断）"
echo "2019.02.23更新版本：1. 修复上传bug；2. 优化检测机制"
echo "2019.02.26更新版本：优化上传速度！"
echo "2019.02.27更新版本：修复创建文件夹bug"
echo "2019.02.28更新版本：美化500&404页面"
echo "2019.03.05更新版本：重构&优化上传界面"
echo "2019.03.08更新版本：优化逻辑&修复文件夹连级加密失效的bug&添加新主题"
echo "2019.03.14更新版本：后台输出实时日志&&一键升级PyOne"
echo "2019.03.15更新版本：修复bug&优化layui主题&可设置默认排序字段"
echo "2019.03.19更新版本：可自定义默认盘&可设置默认排序方法"
echo "---------------------------------------------------------------"
echo "更新完成！"
echo "如果网站无法访问，请检查config.py!"
echo "如果一直提示mongodb或者redis未运行，请自行安装lsof"
echo "---------------------------------------------------------------"
echo
echo "PyOne交流群：864996565"
echo "end"
restart

