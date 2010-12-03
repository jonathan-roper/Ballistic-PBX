#/bin/sh
#Install Vtiger on Ubuntu LTS 10
#Copyright (C) 2010 Star2Billing S.L. jonathan@star2billing.com

#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; either version 2
#of the License, or (at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

#Variables
#Change to suit installation
WEBGROUP=www-data
WEBUSER=www-data
WEBROOT=/var/www
#WEBGROUP=asterisk
#WEBUSER=asterisk


apt-get update
apt-get -y upgrade
apt-get -y remove sendmail fetchmail procmail
apt-get -y install binutils cpp flex gcc libarchive-zip-perl libc6-dev libcompress-zlib-perl libpcre3 libpopt-dev lynx m4 make ncftp nmap openssl perl perl-modules unzip zip zlib1g-dev autoconf automake1.9 libtool bison autotools-dev gcc libpng12-dev libjpeg62-dev libfreetype6-dev libssl-dev libxml2-dev libxml2 g++ gawk postfix libsasl2-modules
apt-get -y install apache2 php5 libapache2-mod-php5
apt-get -y install mysql-server mysql-client php5-mysql php5-gd php5-imap

cd $WEBROOT

wget https://sourceforge.net/projects/vtigercrm/files/vtiger%20CRM%205.2.1/Core%20Product/vtigercrm-5.2.1.tar.gz/download
mv download vtigercrm-5.2.1.tar.gz
tar zxfv vtigercrm-5.2.1.tar.gz 
rm vtigercrm-5.2.1.tar.gz
chown -R $WEBGROUP:$WEBUSER vtigercrm/
mv vtigercrm crm

sed -i 's/display_errors = Off/display_errors = on/g'  /etc/php5/apache2/php.ini
sed -i 's/max_execution_time = 30/max_execution_time = 600/g'  /etc/php5/apache2/php.ini
sed -i 's/error_reporting = E_ALL & ~E_DEPRECATED/error_reporting = E_WARNING & ~E_NOTICE & ~E_DEPRECATED/g'  /etc/php5/apache2/php.ini
sed -i 's/allow_call_time_pass_reference = Off/allow_call_time_pass_reference = on/g'  /etc/php5/apache2/php.ini
sed -i 's/log_errors = On/log_errors = off/g'  /etc/php5/apache2/php.ini

 mv $WEBROOT/crm/htaccess.txt $WEBROOT/crm/.htaccess

/etc/init.d/apache2 restart
/etc/init.d/mysql restart

#done Vtiger

#!/bin/bash
#firewall script for VoIP
echo '

#!/bin/bash
#Goes in /etc/init.d/firewall
#sudo /etc/init.d/firewall start 
#sudo /etc/init.d/firewall stop 
#sudo /etc/init.d/firewall restart 
#sudo /etc/init.d/firewall status
#To make it run, sudo update-rc.d firewall defaults



RETVAL=0

# To start the firewall
start() {
  echo -n "Iptables rules creation: "
  /etc/firewall.sh
  RETVAL=0
}

# To stop the firewall
stop() {
  echo -n "Removing all iptables rules: "
  /etc/flush_iptables.sh
  RETVAL=0
}

case $1 in
  start)
    start
    ;;
  stop)
    stop
    ;;
  restart)
    stop
    start
    ;;
  status)
    /sbin/iptables -L
    /sbin/iptables -t nat -L
    RETVAL=0
    ;;
  *)
    echo "Usage: firewall {start|stop|restart|status}"
    RETVAL=1
esac

exit
' > /etc/init.d/firewall

echo '

#!/bin/bash
#Starts the default IP tables for A2Billing / FreePBX, edit this script to change behaviour
#File location /etc/firewall.sh


iptables -F
iptables -X


iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -p all -j ACCEPT  
iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 10000 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 123 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 69 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 53 -j ACCEPT
iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
iptables -A INPUT -p all -s localhost  -i eth0 -j DROP	
iptables -A INPUT -j REJECT
iptables -A FORWARD -j REJECT

iptables-save

# End message
echo " [End iptables rules setting]"

' > /etc/firewall.sh

echo '

#!/bin/sh
#Flush iptable rules, and open everything
#File location - /etc/flush_iptables.bash


#
# Set the default policy
#
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

#
# Set the default policy for the NAT table
#
iptables -t nat -P PREROUTING ACCEPT
iptables -t nat -P POSTROUTING ACCEPT
iptables -t nat -P OUTPUT ACCEPT

#
# Delete all rules
#
iptables -F
iptables -t nat -F

#
# Delete all chains
#

iptables -X
iptables -t nat -X

# End message
echo " [End of flush]"

' > /etc/flush_iptables.sh

chmod +x /etc/flush_iptables.sh
chmod +x /etc/firewall.sh
chmod +x /etc/init.d/firewall
update-rc.d firewall defaults

/etc/init.d/firewall restart

#Install OSSEC
cd /usr/src
rm -rf ossec*
wget http://www.ossec.net/files/ossec-hids-2.5.1.tar.gz
tar zxfv ossec-hids-*.tar.gz
rm -rf ossec-hids*.tar.gz
mv ossec-hids-* ossec-hids
cd ossec-hids
./install.sh
clear

# Add some local rules

/var/ossec/bin/ossec-control start

#quieten down the logs
echo 'unset SSHD_OOM_ADJUST' >>  /etc/default/ssh

if [ $INSTALLWEBMIN = 0 ]; then
	rm -rf webmin-1*.deb
	cd /usr/src
	wget http://sunet.dl.sourceforge.net/project/webadmin/webmin/1.520/webmin_1.520_all.deb
	dpkg --install webmin*
	apt-get -y -f install
	rm -rf webmin*.deb
fi








echo -e "Installation complete\n\n"

IP=`/sbin/ifconfig eth0 | grep "inet addr" | awk -F' ' '{print $2}' | awk -F':' '{print $2}'`

echo -e "Log into the Administrative interface at: http://$IP/crm/"
echo -e "and complete the installation"
# DONE

