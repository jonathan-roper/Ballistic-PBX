#/bin/sh
#Install Asterisk and FreePBX on Ubuntu LTS 10
#Copyright (C) 2010-11 Star2Billing S.L. jonathan@star2billing.com

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




# -------- preparation ------------


# ---------------------- Asterisk ------------------------
function funcasterisk() 
{

#Asterisk Versions.
ASTERISK18VER=asterisk-1.8-current.tar.gz
ASTERISK10VER=asterisk-10-current.tar.gz


#Add Asterisk group and user
grep -c "^asterisk:" /etc/group &> /dev/null
if [ $? = 1 ]; then
       /usr/sbin/groupadd -r -f asterisk
else
       echo "group asterisk already present"
fi

grep -c "^asterisk:" /etc/passwd &> /dev/null
if [ $? = 1 ]; then
       echo "adding user asterisk..."
       /usr/sbin/useradd -c "Asterisk" -g asterisk \
       -r -s /bin/bash -m -d /var/lib/asterisk \
       asterisk
else
       echo "user asterisk already present"
fi

#Select Asterisk version

cd /usr/src


ASTVER=4
until [ $ASTVER -lt 4 ] ; do
	clear
	echo "Select Asterisk Version to install"
	echo "Press 1 for Asterisk 1.6 or Asterisk 1.4, 2 for 1.8, 3. for 10"
	read ASTVER < /dev/tty
	echo $ASTVER
done

rm -rf asterisk*.tar.gz

case $ASTVER in
	1)
		echo "Enter Asterisk Version, e.g. 1.6.2.20 or 1.4.42)"
		read ASTVERSION
		if [ -z "$ASTVERSION" ]; then
    		ASTVERSION="1.4.42"
		fi
		echo "Enter Asterisk Addons Version, e.g. 1.6.2.4 or 1.4.13)"
		read ASTADDONSVERSION
		if [ -z "$ASTADDONSVERSION" ]; then
    		ASTADDONSVERSION="1.4.13"
		fi
		wget http://downloads.asterisk.org/pub/telephony/asterisk/releases/asterisk-$ASTVERSION.tar.gz
		wget http://downloads.asterisk.org/pub/telephony/asterisk/releases/asterisk-addons-$ASTADDONSVERSION.tar.gz
		tar zxf asterisk-$ASTVERSION.tar.gz
		tar zxf asterisk-addons-$ASTADDONSVERSION.tar.gz
	;;
	2)
		wget http://downloads.asterisk.org/pub/telephony/asterisk/$ASTERISK18VER
		tar zxf $ASTERISK18VER
	;;
	3)
		wget http://downloads.asterisk.org/pub/telephony/asterisk/$ASTERISK10VER
		tar zxf $ASTERISK10VER
	;;
esac


rm -rf libpri*.tar.gz
rm -rf dahdi*.tar.gz
wget http://downloads.asterisk.org/pub/telephony/libpri/libpri-1.4-current.tar.gz
wget http://downloads.digium.com/pub/telephony/dahdi-linux-complete/dahdi-linux-complete-current.tar.gz

tar zxf libpri-1.4-current.tar.gz
tar zxf dahdi-linux-complete-current.tar.gz


rm -rf *.tar.gz

mv libpri* libpri
mv asterisk-1* asterisk
mv asterisk-addons* asterisk-addons
mv dahdi-linux-complete* dahdi-linux-complete


#Install Asterisk


cd /usr/src/libpri
make clean
make 
make install
cd /usr/src


#Create directory and file to get meetme working
mkdir /usr/include/dahdi/
cp /usr/src/dahdi-linux-complete/linux/include/dahdi/user.h /usr/include/dahdi/user.h

cd /usr/src/dahdi-linux-complete
make all
make install
make config
cd /usr/src

/etc/init.d/dahdi start


#install Asterisk
cd /usr/src/asterisk
make clean
./configure
make menuselect
if [ $ASTVER -ge 2 ]
then
	/usr/src/asterisk/contrib/scripts/get_mp3_source.sh
fi
make
make install
make samples
#make progdocs



#create /var/run/asterisk for asterisk to run in and set permissions
mkdir /var/run/asterisk/





#Set directory for MOH
mkdir /var/lib/asterisk/mohmp3/


touch /etc/asterisk/chan_dahdi.conf

#Set permissions to run asterisk as asterisk user
chown -R asterisk:asterisk /var/log/asterisk/ /etc/asterisk/ /var/lib/asterisk/ /var/run/asterisk

#Add include for Dahdi channels
echo "#include dahdi-channels.conf" >> /etc/asterisk/chan_dahdi.conf
dahdi_genconf -F

#bit of a bodge here, just incase this script gets run twice
sed -i 's/\/var\/run\/asterisk/\/var\/run/g'  /etc/asterisk/asterisk.conf
sed -i 's/\/var\/run/\/var\/run\/asterisk/g'  /etc/asterisk/asterisk.conf

#The others should be OK not duplicate
sed -i 's/;runuser/runuser/g'  /etc/asterisk/asterisk.conf
sed -i 's/;rungroup/rungroup/g'  /etc/asterisk/asterisk.conf
sed -i 's/;dahdichanname/dahdichanname/g'  /etc/asterisk/asterisk.conf
sed -i 's/;dahdichanname/dahdichanname/g'  /etc/asterisk/asterisk.conf
sed -i 's/(!)/ /g'  /etc/asterisk/asterisk.conf
sed -i 's/ASTARGS=""/ASTARGS="-U asterisk"/g'  /usr/sbin/safe_asterisk

make config

#Install Asterisk Addons
if [ $ASTVER -lt 2 ]
then
	cd /usr/src/asterisk-addons
	make clean
	./configure
	make menuselect
	make
	make install
	make samples
fi



#Setup log rotation

touch /etc/logrotate.d/asterisk
echo '

/var/log/asterisk/*log {
   missingok
   rotate 5
   weekly
   create 0640 asterisk asterisk
   postrotate
       /usr/sbin/asterisk -rx 'logger reload' > /dev/null 2> /dev/null
   endscript
}

/var/log/asterisk/full {
   missingok
   rotate 5
   daily
   create 0640 asterisk asterisk
   postrotate
       /usr/sbin/asterisk -rx 'logger reload' > /dev/null 2> /dev/null
   endscript
}

/var/log/asterisk/messages {
   missingok
   rotate 5
   daily
   create 0640 asterisk asterisk
   postrotate
       /usr/sbin/asterisk -rx 'logger reload' > /dev/null 2> /dev/null
   endscript
}

/var/log/asterisk/cdr-csv/*csv {
  missingok
  rotate 5
  monthly
  create 0640 asterisk asterisk
}

'  > /etc/logrotate.d/asterisk


chown -R asterisk:asterisk /var/log/asterisk/ /etc/asterisk/ /var/lib/asterisk/ /var/run/asterisk /var/spool/asterisk

if [ -d /tftpboot ]; then
 chown -R asterisk:asterisk /tftpboot
fi

#Now Asterisk should start
#Disable TTY9 for OpenVZ
sed -i 's/TTY=9/#TTY=9/g'  /usr/sbin/safe_asterisk
/etc/init.d/asterisk restart

sleep 15


echo "fxotune -s" >> /etc/rc.local
touch /etc/fxotune.conf

#funcasterisk
}


# ---------------------- Freepbx ------------------------
function funcfreepbx () 
{

#check asterisk is running, before FreePBX is installed.


if test -f /var/run/asterisk/asterisk.pid; then
   
   #Set Apache to run as asterisk
	sed -i 's/www-data/asterisk/g'  /etc/apache2/envvars
	/etc/init.d/apache2 restart
	mysqladmin -u root password 'passw0rd'


   
	# Get FreePBX - Unzip and modify
	cd /usr/src
	rm -rf freepbx*.tar.gz
	wget http://mirror.freepbx.org/freepbx-2.8.0.tar.gz
	tar zxfv freepbx*.tar.gz
	rm -rf freepbx*.tar.gz
	mv freepbx-2* freepbx
	mkdir /usr/share/freepbx /var/lib/asterisk/bin

	cd /usr/src/freepbx

	#make some changes to FreePBX
	sed -i 's/AUTHTYPE=none/AUTHTYPE=database/g'  amportal.conf
	sed -i 's/SERVERINTITLE=false/SERVERINTITLE=true/g'  amportal.conf
	sed -i 's/\/var\/www\/html/\/usr\/share\/freepbx/g'  amportal.conf
	sed -i 's/# ZAP2DAHDICOMPAT=true|false/ZAP2DAHDICOMPAT=true/g'  amportal.conf
	#sed -i 's/FOPRUN=true/FOPRUN=false/g'  amportal.conf

	#create the MySQL databases
	mysqladmin -uroot -ppassw0rd create asterisk
	mysqladmin -uroot -ppassw0rd create asteriskcdrdb
	mysql -uroot -ppassw0rd  asterisk < SQL/newinstall.sql
	mysql -uroot -ppassw0rd asteriskcdrdb < SQL/cdr_mysql_table.sql
	mysql -uroot -ppassw0rd -e "GRANT ALL PRIVILEGES ON asterisk.* TO asteriskuser@localhost IDENTIFIED BY 'amp109'"
	mysql -uroot -ppassw0rd -e "GRANT ALL PRIVILEGES ON asteriskcdrdb.* TO asteriskuser@localhost IDENTIFIED BY 'amp109'"

	cp amportal.conf /etc/amportal.conf
	chown -R asterisk:asterisk /etc/amportal.conf
	./install_amp --username=asteriskuser --password=amp109



	chown -R asterisk:asterisk /etc/asterisk
	chown -R asterisk:asterisk /usr/share/freepbx
	chown -R asterisk:asterisk /var/lib/asterisk



	#Bring modules upto date and get useful modules
	/var/lib/asterisk/bin/module_admin upgradeall
	
	/var/lib/asterisk/bin/module_admin download asterisk-cli
	/var/lib/asterisk/bin/module_admin download asteriskinfo 
	/var/lib/asterisk/bin/module_admin download backup 
	/var/lib/asterisk/bin/module_admin download fw_ari
	/var/lib/asterisk/bin/module_admin download fw_fop
	/var/lib/asterisk/bin/module_admin download iaxsettings 
	/var/lib/asterisk/bin/module_admin download javassh 
	/var/lib/asterisk/bin/module_admin download languages 
	/var/lib/asterisk/bin/module_admin download logfiles 
	/var/lib/asterisk/bin/module_admin download phpinfo 
	/var/lib/asterisk/bin/module_admin download sipsettings 
	/var/lib/asterisk/bin/module_admin download weakpasswords 
	/var/lib/asterisk/bin/module_admin download fw_langpacks

	/var/lib/asterisk/bin/module_admin install asterisk-cli
	/var/lib/asterisk/bin/module_admin install asteriskinfo 
	/var/lib/asterisk/bin/module_admin install backup 
	/var/lib/asterisk/bin/module_admin install fw_ari
	/var/lib/asterisk/bin/module_admin install fw_fop
	/var/lib/asterisk/bin/module_admin install iaxsettings 
	/var/lib/asterisk/bin/module_admin install javassh 
	/var/lib/asterisk/bin/module_admin install languages 
	/var/lib/asterisk/bin/module_admin install logfiles 
	/var/lib/asterisk/bin/module_admin install phpinfo 
	/var/lib/asterisk/bin/module_admin install sipsettings 
	/var/lib/asterisk/bin/module_admin install weakpasswords 
	/var/lib/asterisk/bin/module_admin install fw_langpacks

	/var/lib/asterisk/bin/module_admin reload

	#Setup FreePBX web pages.
	touch /etc/apache2/sites-available/freepbx.conf
echo '

Alias /pbx /usr/share/freepbx/

DocumentRoot /usr/share/freepbx

<directory /usr/share/freepbx>
	AllowOverride all
	Options Indexes FollowSymLinks
	order allow,deny
	allow from all
	AuthName "PBX Administrator"
	AuthType Basic
	AuthUserFile /dev/null 
	AuthBasicAuthoritative off
	Auth_MySQL on
	Auth_MySQL_Authoritative on
	Auth_MySQL_Username asteriskuser
	Auth_MySQL_Password amp109
	Auth_MySQL_DB asterisk
	Auth_MySQL_Password_Table ampusers
	Auth_MySQL_Username_Field username
	Auth_MySQL_Password_Field password_sha1
	Auth_MySQL_Empty_Passwords off
	Auth_MySQL_Encryption_Types SHA1Sum
	Require valid-user
</directory>

<directory /usr/share/panel>
	AllowOverride all
	Options Indexes FollowSymLinks
	order allow,deny
	allow from all
	AuthName "Operator Panel"
	AuthType Basic
	AuthUserFile /dev/null 
	AuthBasicAuthoritative off
	Auth_MySQL on
	Auth_MySQL_Authoritative on
	Auth_MySQL_Username asteriskuser
	Auth_MySQL_Password amp109
	Auth_MySQL_DB asterisk
	Auth_MySQL_Password_Table ampusers
	Auth_MySQL_Username_Field username
	Auth_MySQL_Password_Field password_sha1
	Auth_MySQL_Empty_Passwords off
	Auth_MySQL_Encryption_Types SHA1Sum
	Require valid-user
</directory>

<IfModule mod_php5.c>
php_flag magic_quotes_gpc Off
php_flag track_vars On
php_flag register_globals Off
php_value upload_max_filesize 100M
php_value memory_limit 100M
php_value magic_quotes_gpc off
</IfModule>

<IfModule mod_auth_mysql.c>

' > /etc/apache2/sites-available/freepbx.conf

ln -s  /etc/apache2/sites-available/freepbx.conf /etc/apache2/sites-enabled/freepbx.conf


	echo "
	Options -Indexes
	<Files .htaccess>
	deny from all
	</Files> 
	" > /usr/share/freepbx/admin/modules/.htaccess
	
	
	#Set the AMI to only listen on 127.0.0.1
	sed -i 's/bindaddr = 0.0.0.0/bindaddr = 127.0.0.1/g' /etc/asterisk/manager.conf


#Get FreePBX to start automatically on boot.

	echo '#!/bin/bash' > /etc/init.d/amportal-start
	echo '/usr/local/sbin/amportal start' >> /etc/init.d/amportal-start
	chmod +x /etc/init.d/amportal-start
	update-rc.d amportal-start start 99 2 3 4 5 .
	

	echo '#!/bin/bash' > /etc/init.d/amportal-stop
	echo '/usr/local/sbin/amportal stop' >> /etc/init.d/amportal-stop
	chmod +x /etc/init.d/amportal-stop
	update-rc.d amportal-stop stop 10 0 1 6 .

	/etc/init.d/asterisk stop
	update-rc.d -f asterisk remove

	/etc/init.d/apache2 restart
	amportal kill
	dahdi_genconf -F
	/etc/init.d/dahdi restart
	amportal start

else
	clear
	echo "asterisk is not running"
	echo "please correct this before installing FreePBX"
	echo "Press enter to return to the install menu."
	read temp
fi

	
#funcfreepbx
}




# ----------------------IP Tables ------------------------
function funciptables () 
{
#firewall script for VoIP
#To add a range of IP Addresses - use the following syntax
#iptables -A INPUT -p tcp --destination-port 22 -m iprange --src-range 192.168.1.100-192.168.1.200 -j ACCEPT 
#Or single IP Address - for VoIP
#iptables -A INPUT -p udp -s 10.10.10.10 --dport 5060 -j ACCEPT
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
iptables -A INPUT -p udp -m udp --dport 69 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 4445 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 9000 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 10000 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 4520 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 4569 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 5060 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 10000:20000 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 4000:4999 -j ACCEPT
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

#funciptables
}


# ---------------------- Ossec ------------------------
function funcossec () 
{

cd /usr/src
rm -rf ossec*
wget http://www.ossec.net/files/ossec-hids-2.6.tar.gz
tar zxfv ossec-hids-*.tar.gz
rm -rf ossec-hids*.tar.gz
mv ossec-hids-* ossec-hids
cd ossec-hids
clear

echo "=================="
echo "OSSEC INSTALLATION"
echo "=================="
echo "When prompted, please chose local as the installation type"
echo "Unless you have previously set up an OSSEC server for"
echo "receiving Ossec notifications."
echo ""
echo "Answer no to the following question"
echo ""
echo "- We found your SMTP server as: smtp.somemailserver.com."
echo "- Do you want to use it? y/n y: n"
echo "When prompted type localhost as your mail server."
echo ""
echo ""
echo "Press any key to continue"
read any
./install.sh
clear

# Add some local rules

echo '<!-- @(#) $Id: local_rules.xml,v 1.5 2008/06/17 17:03:55 dcid Exp $
  -  Example of local rules for OSSEC.
  -
  -  Copyright (C) 2008 Third Brigade, Inc.
  -  All rights reserved.
  -
  -  This program is a free software; you can redistribute it
  -  and/or modify it under the terms of the GNU General Public
  -  License (version 3) as published by the FSF - Free Software
  -  Foundation.
  -
  -  License details: http://www.ossec.net/en/licensing.html
  -->


<!-- Modify it at your will. -->

<group name="local,syslog,">

  <!-- Note that rule id 5711 is defined at the ssh_rules file
    -  as a ssh failed login. This is just an example
    -  since ip 1.1.1.1 shouldnt be used anywhere.
    -  Level 0 means ignore.
    -->
  <rule id="100001" level="0">
    <if_sid>5711</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>Example of rule that will ignore sshd </description>
    <description>failed logins from IP 1.1.1.1.</description>
  </rule>
  
  
  <!-- This example will ignore ssh failed logins for the user name XYZABC.
    -->
  <!--  
  <rule id="100020" level="0">
    <if_sid>5711</if_sid>
    <user>XYZABC</user>
    <description>Example of rule that will ignore sshd </description>
    <description>failed logins for user XYZABC.</description>
  </rule>
  -->
  
  
  <!-- Specify here a list of rules to ignore. -->
  <!--
  <rule id="100030" level="0">
    <if_sid>12345, 23456, xyz, abc</if_sid>
    <description>List of rules to be ignored.</description>
  </rule>
  -->
   
</group> <!-- SYSLOG,LOCAL -->

 <!-- Rules below added by jroper -->


<group name="apache,">
 <rule id="100300" level="5">
   <if_sid>30109</if_sid>
   <description>Attempt to login using a non-existent user.</description>
  <group>invalid_login,</group>
 </rule>

 <rule id="100301" level="9" frequency="5" timeframe="120">
   <if_matched_sid>100300</if_matched_sid>
   <regex>user \S+ not found</regex>
   <description>Attempt to login using a non-existent user.</description>
  <group>invalid_login,</group>
 </rule>

<rule id="100013" level="0">
    <if_sid>31106</if_sid>
    <url>phpmyadmin</url>
    <description>Ignoring phpMyAdmin events.</description>
</rule>

<rule id="100016" level="0">
    <if_sid>31103</if_sid>
    <url>phpmyadmin</url>
    <description>Ignoring phpMyAdmin events.</description>
</rule>


<rule id="100017" level="0">
    <if_sid>31151</if_sid>
    <url>phpmyadmin</url>
    <description>Ignoring phpMyAdmin events.</description>
</rule>

<rule id="100018" level="0">
    <if_sid>31151</if_sid>
    <url>logout</url>
    <description>Ignoring FreePBX logout events.</description>
</rule>

logout


</group> <!-- ERROR_LOG,APACHE -->

<!-- EOF -->

' > /var/ossec/rules/local_rules.xml


#add some asterisk rules
sed -i '/ossec_rules/ i\    <include>asterisk_rules.xml</include>' /var/ossec/etc/ossec.conf 

#Get asterisk to write to syslog
echo 'messages => notice,warning,error' >> /etc/asterisk/logger.conf
asterisk -rx 'module reload'
sed -i 's/ossec:x:500:asterisk/ossec:x:500:/g' /etc/group
sed -i 's/ossec:x:500:/ossec:x:500:asterisk/g' /etc/group

sed -i '/<\/ossec_config>/d' /var/ossec/etc/ossec.conf
echo '
 <localfile>
   <log_format>syslog</log_format>
   <location>/var/log/asterisk/messages</location>
 </localfile>
 </ossec_config> 
' >> /var/ossec/etc/ossec.conf 




/var/ossec/bin/ossec-control start

#quieten down the logs
echo 'unset SSHD_OOM_ADJUST' >>  /etc/default/ssh

#funcossec
}

# ---------------------- Splash page ------------------------
function funcsplash () 
{
#install Gui


cd /var/www/
rm index.html
cp -R /var/a2b-payload/webrootindex/* /var/www/
chown -R asterisk:asterisk /var/www/


#funcsplash
}

# ---------------------- Reboot ------------------------
function funcreboot () 
{
# reboot

reboot

#funcreboot
}
# ---------------------- Pause ------------------------

function pause(){
   read -p �$*�
#pause
#usage pause "some test, press any key to continue"
#pause
}

# ---------------------- Install Dependencies ------------------------

function funcdependencies(){
#Install Dependencies

KERNELARCH=$(uname -p)

apt-get -y autoremove
apt-get -f install


apt-get -y update



apt-get -y remove sendmail

apt-get -y upgrade

echo ""
echo ""
echo ""
echo "If the Kernel has been updated, we advise you to reboot your server and run again the install script!"
echo "If you are not sure whether the kernel has been updated, reboot and start again (once only!)"
echo ""
echo "Press CTRL C to exit and reboot, or enter to continue"
read TEMP

apt-get install openssh-server

#check timezone
dpkg-reconfigure tzdata

#install dependencies

#for asterisk 10
apt-get -y install libsqlite3-dev sqlite3

apt-get -y install mysql-server
apt-get -y install mysql-client libmysqlclient-dev build-essential sysvinit-utils libxml2 libxml2-dev libncurses5-dev libcurl4-openssl-dev libvorbis-dev libspeex-dev unixodbc unixodbc-dev libiksemel-dev wget iptables php5 php5-cli php-pear php5-mysql php-db libapache2-mod-php5 php5-gd php5-curl sqlite libnewt-dev libusb-dev zlib1g-dev  libsqlite0-dev  libapache2-mod-auth-mysql sox mpg123 postfix flite php5-mcrypt python-setuptools python-mysqldb python-psycopg2 python-sqlalchemy ntp

#extras 
apt-get -y install wget iptables vim subversion flex bison libtiff-tools ghostscript autoconf gcc g++ automake libtool patch



apt-get -y install linux-headers-$(uname -r)

#remove the following packages for security.
apt-get -y remove nfs-common portmap

mkfifo /var/spool/postfix/public/pickup

#Enable Mod_Auth_MySQL
ln -s /etc/apache2/mods-available/auth_mysql.load /etc/apache2/mods-enabled/auth_mysql.load

#Set MySQL to start automatically
update-rc.d mysql remove
update-rc.d mysql defaults




INSTALLWEBMIN=2
until [ $INSTALLWEBMIN -lt 2 ] ; do
	clear
	echo "Do you want to install Webmin Y/n"
	echo "Press 0 for Yes or 1 for No"
	read INSTALLWEBMIN < /dev/tty
	echo $INSTALLWEBMIN
done

if [ $INSTALLWEBMIN = 0 ]; then
    rm -rf webmin*.deb
    cd /usr/src
    wget http://www.webmin.com/download/deb/webmin-current.deb
    dpkg --install webmin*
    apt-get -y -f install
    rm -rf webmin*.deb
fi


INSTALLTFTP=2
until [ $INSTALLTFTP -lt 2 ] ; do
    clear
    echo "Do you want to install a TFTP server Y/n"
    echo "Press 0 for Yes or 1 for No"
    read INSTALLTFTP < /dev/tty
    echo $INSTALLTFTP
done

#Install a TFTP server
if [ $INSTALLTFTP = 0 ]; then
    apt-get install xinetd tftpd tftp -y
    echo '
    service tftp
    {
    protocol        = udp
    port            = 69
    socket_type     = dgram
    wait            = yes
    user            = nobody
    server          = /usr/sbin/in.tftpd
    server_args     = /tftpboot
    disable         = no
    }
    ' > /etc/xinetd.d/tftp
    mkdir /tftpboot
    chmod -R 777 /tftpboot
    echo 'includedir /etc/xinetd.d' >> /etc/xinetd.conf
    /etc/init.d/xinetd start
fi



#funcdependencies
}

# ---------------------- Set Clock ------------------------


function funcsetclock(){
#Set the time and date
	apt-get -y install ntp ntpdate
	/usr/sbin/ntpdate -su pool.ntp.org
	hwclock --systohc
 #funcsetclock}
}

# ---------------------- Start Services ------------------------

function funcsetservices(){
	#Set some services to start automatically and open them up

	#chkconfig httpd on
	#chkconfig mysqld on


	# Start  MySQL & APACHE
	#service mysqld start
	#service httpd start

	#Set password to passw0rd
	mysqladmin -u root password 'passw0rd'

	mkdir /etc/pbx
	echo "" > /etc/pbx/runonce.sh
	echo "" > /etc/motd

#funcsetservices
}

# ---------------------- Install Public Keys ------------------------

function funcpublickey(){
#add public key to root user.
mkdir /root/.ssh
touch /root/.ssh/authorized_keys
echo '

' >> /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
#funcpublickey
}

# ---------------------- Menu ------------------------


show_menu_pabx() {
	clear
	echo " > Asterisk/FreePBX Installation Menu (Ubuntu)"
	echo "================================"
	echo "	1)  Install all"
	echo "	2)  Install dependencies"
	echo "	3)  Asterisk"
	echo "	4)  FreePBX"
	echo "	5)  IP-Tables"
	echo "	6)  Ossec Security"
	echo "	7)  Splash page"
	echo "	8)  Reboot"
	echo "	9) Add public key"
	echo "	0)  Quit"
	echo -n "(0-9) : "
	read OPTION < /dev/tty
}


ExitFinish=0

while [ $ExitFinish -eq 0 ]; do

	# Show menu with Installation items
	show_menu_pabx

	case $OPTION in
		1) 
			funcdependencies
			funcsetclock
			funcsetservices
			funcasterisk
			funcfreepbx
			funciptables
			funcossec
			funcsplash
			echo "done"
		;;
		2) 
			funcdependencies
			funcsetclock
			funcsetservices
		;;
		3) 
			funcasterisk
		;;
		4) 
			funcfreepbx
		;;
		5) 
			funciptables
					;;
		6) 
			funcossec
		;;
		7) 
			funcsplash
		;;
		8) 
			funcreboot
		;;
		9) 
			funcpublickey
		;;
		0)
		ExitFinish=1
		;;
		*)
	esac
	
done

