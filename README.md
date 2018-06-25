# ocserv-centos
ocserv-centos 自用
白名单修改
```
yum update

yum install wget net-tools

wget https://github.com/Adagior/ocserv/raw/master/all.sh

带规则版：
wget https://raw.githubusercontent.com/Adagior/ocserv/master/ip.sh

sh ip.sh
```
自行修改：vi /etc/ocserv/ocserv.conf

不转发：no-route  转发: route

重启服务： systemctl restart ocserv.service

添加用户： ocpasswd -c /usr/local/etc/ocserv/ocpasswd 用户名


all：全部代理  ip：国内不代理 auto：国外代理

路由表：
https://github.com/CNMan/ocserv-cn-no-route

详细说明：
https://www.logcg.com/archives/1343.html
