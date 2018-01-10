# ocserv-centos
ocserv-centos 自用
白名单修改
```
yum update

yum install wget net-tools

wget https://github.com/Adagior/ocserv/raw/master/all.sh

带规则版：https://raw.githubusercontent.com/Adagior/ocserv-centos/master/ocserv-auto.sh 

sh ocserv-auto.sh
```
自行修改：vi /etc/ocserv/ocserv.conf

不转发：no-route  转发: route

重启服务： systemctl restart ocserv.service

添加用户： ocpasswd -c /usr/local/etc/ocserv/ocpasswd 用户名
