# PyOne - 基于Python的onedrive文件本地化浏览系统,使用MongoDB缓存文件

Demo地址：[https://pyone.me](https://pyone.me)

Wiki地址：[https://wiki.pyone.me/](https://wiki.pyone.me/)

QQ交流群：[https://jq.qq.com/?_wv=1027&k=5ypfek0](https://jq.qq.com/?_wv=1027&k=5ypfek0)

PyOne论坛：[https://bbs.pyone.me/](https://bbs.pyone.me/)

**有任何问题，先看wiki！wiki找不到解决办法的，再到论坛里提问！**


```
2019.02.15：PyOne代码组织大变更！更新版本号为4.0！

如果是2019.02.15之前安装的PyOne，升级到4.0需要重新安装！

升级4.0教程：

1. 备份config.py，并改名为self_config.py；备份supervisord.conf

2. 备份data目录

3. 删除原来的PyOne目录

4. 重新git clone https://www.github.com/abbeyokgo/PyOne.git

5. 将self_config.py、supervisord.conf和data目录复制回去

6. 创建一个锁定文件：touch .install

6. 安装新的依赖包：pip install flask_script

7. 重启网站：supervisorctl -c supervisord.conf reload
```
