# ocserv-centos
ocserv-centos 自用
白名单修改

yum update

yum install wget net-tools

wget https://raw.githubusercontent.com/Adagior/ocserv-centos/master/ocserv-auto.sh ocserv-auto.sh

sh ocserv-auto.sh

自行修改：vi /usr/local/etc/ocserv/ocserv.conf

不转发：no-route  转发:route
