# ocserv-centos
ocserv-centos 自用
白名单修改

由于版本更新 需要先安装 yum install -y ocserv

yum update

yum install wget net-tools

wget https://raw.githubusercontent.com/Adagior/ocserv-centos/master/ocserv-auto.sh 

sh ocserv-auto.sh

自行修改：vi /etc/ocserv/ocserv.conf

不转发：no-route  转发: route

重启服务： systemctl restart ocserv.service

添加用户： ocpasswd -c /usr/local/etc/ocserv/ocpasswd 用户名
