#!/bin/bash
#Install Asterisk and FreePBX on Ubuntu LTS 12.04
#Copyright (C) 2010-13 Star2Billing S.L. jonathan@star2billing.com

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

#Purpose
########
# To install asterisk 1.8, 10 or 11 on Ubuntu with FreePBX. 
# Includes OSSEC iptables and extra apache security on FreePBX, in addition to it's own security.


#Notes
#------
# The admin password in FreePBX is set on the first login, however we add apache authentication
# Therefore enter vm / vmadmin as the first login, which allows restricted access past apache auth.
# This can be changed later in FreePBX administrators screen.
# You need a password such as this with limited access for users to access the ARI, which
# is also protected by Apache authentication.



# ---------------------- Asterisk ------------------------
function funcasterisk() 
{

#Asterisk Versions.
ASTERISK18VER=asterisk-1.8-current.tar.gz
ASTERISK10VER=asterisk-10-current.tar.gz
ASTERISK11VER=asterisk-11-current.tar.gz

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


MAXASTVER=4
ASTVER=4
until [ $ASTVER -lt $MAXASTVER ] ; do
    clear
    echo "Select Asterisk Version to install"
    echo "1 for 1.8"
    echo "2 for Asterisk 10"
    echo "3 for Asterisk 11"
    read ASTVER < /dev/tty
    echo $ASTVER
done

rm -rf asterisk*.tar.gz

case $ASTVER in
    1)
        wget http://downloads.asterisk.org/pub/telephony/asterisk/$ASTERISK18VER
        tar zxf $ASTERISK18VER
    ;;
    2)
        wget http://downloads.asterisk.org/pub/telephony/asterisk/$ASTERISK10VER
        tar zxf $ASTERISK10VER
    ;;
    3)
        wget http://downloads.asterisk.org/pub/telephony/asterisk/$ASTERISK11VER
        tar zxf $ASTERISK11VER
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


#Install Dahdi
cd /usr/src/dahdi-linux-complete
make all
make install
make config
cd /usr/src

/etc/init.d/dahdi start

#Install Libpri
cd /usr/src/libpri
make clean
make 
make install
cd /usr/src

#install Asterisk
cd /usr/src/asterisk
make clean
./configure
make menuselect
/usr/src/asterisk/contrib/scripts/get_mp3_source.sh
make
make install
make samples
make config

#create /var/run/asterisk for asterisk to run in and set permissions
mkdir /var/run/asterisk/

#Set directory for MOH
mkdir /var/lib/asterisk/mohmp3/ 
ln -s /var/lib/asterisk/moh/* /var/lib/asterisk/mohmp3/


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

asterisk -x "core show version" >> /etc/ballistic/info.txt
echo "fxotune -s" >> /etc/rc.local
touch /etc/fxotune.conf

#funcasterisk
}



# ---------------------- Freepbx11 ------------------------
function funcfreepbx () 
{

#check asterisk is running, before FreePBX is installed.
if test -f /var/run/asterisk/asterisk.pid; 
then
    clear
    #Don't allow progress until access confirmed to database
    #Check root password set, if not, ask for it
    if [ -z "${MYSQLROOTPASSWD+xxx}" ]; then read -p "Enter MySQL root password " MYSQLROOTPASSWD; fi
	if [ -z "$MYSQLROOTPASSWD" ] && [ "${MYSQLROOTPASSWD+xxx}" = "xxx" ]; then read -p "Enter MySQL root password " MYSQLROOTPASSWD; fi 
    echo "Please enter the MySQL root password"
    until mysql -uroot -p$MYSQLROOTPASSWD -e ";" ; do 
    	clear
    	echo "Please enter the MySQL root password"
		read MYSQLROOTPASSWD
		echo "password incorrect"		
	done
    
    #Write FreePBX info
	echo "MySQL Root Password = $MYSQLROOTPASS" >> /etc/ballistic/info.txt
  
    #Set Apache to run as asterisk
    sed -i 's/www-data/asterisk/g'  /etc/apache2/envvars
    chown -R asterisk:asterisk /var/lock/apache2
    /etc/init.d/apache2 restart
    
	# Get FreePBX - Unzip and modify
    cd /usr/src
    rm -rf freepbx*.tar.gz
    rm -rf freepbx
    wget http://mirror.freepbx.org/freepbx-2.11.0rc1.tar.gz
    tar zxfv freepbx*.tar.gz
    rm -rf freepbx*.tar.gz
    mv freepbx-2* freepbx
    mkdir /var/www/html /var/lib/asterisk/bin

    cd /usr/src/freepbx

   if [ ! -f /etc/amportal.conf ]; 
   then
   		#Prepare Amportal and copy it into location.

    	#Generate random password for FreePBX database user
    	funcrandpass 10 0
    	FREEPBXPASSW=$RANDOMPASSW
    
    	#Generate random password for the AMI
    	funcrandpass 10 0
    	AMIPASSW=$RANDOMPASSW

    	#make some changes to Amportal
    	sed -i 's/AUTHTYPE=none/AUTHTYPE=database/g'  amportal.conf
    
    	#write out the new database user and password
    	echo "
AMPDBUSER=asteriskuser
AMPDBPASS=$FREEPBXPASSW
    	" >> amportal.conf
    	sed -i "s/AMPMGRPASS=amp111/AMPMGRPASS=$AMIPASSW/g"  amportal.conf

    	#Set the ARI password
    	funcrandpass 10 0
    	ARIPASSW=$RANDOMPASSW
    	sed -i "s/ARI_ADMIN_PASSWORD=ari_password/ARI_ADMIN_PASSWORD=$ARIPASSW/g"  amportal.conf
        
    	cp amportal.conf /etc/amportal.conf
   
	else	
		#Amportal already prepared, just go on to installation.
		echo "Amportal already setup, go straight to installation"
	fi
	source /etc/amportal.conf
	#create the MySQL databases
    mysqladmin -uroot -p$MYSQLROOTPASSWD create asterisk
    mysqladmin -uroot -p$MYSQLROOTPASSWD create asteriskcdrdb
    mysql -uroot -p$MYSQLROOTPASSWD  asterisk < SQL/newinstall.sql
    mysql -uroot -p$MYSQLROOTPASSWD asteriskcdrdb < SQL/cdr_mysql_table.sql
    mysql -uroot -p$MYSQLROOTPASSWD -e "GRANT ALL PRIVILEGES ON asterisk.* TO asteriskuser@localhost IDENTIFIED BY '$AMPDBPASS'"
    mysql -uroot -p$MYSQLROOTPASSWD -e "GRANT ALL PRIVILEGES ON asteriskcdrdb.* TO asteriskuser@localhost IDENTIFIED BY '$AMPDBPASS'"
    ./install_amp --username=$AMPDBUSER --password=$AMPDBPASS

    chown -R asterisk:asterisk /etc/asterisk
    chown -R asterisk:asterisk /var/www/html/
    chown -R asterisk:asterisk /var/lib/asterisk

    #Remove files, and re - symlink 
    rm /etc/asterisk/cel.conf
    rm /etc/asterisk/cel_odbc.conf
    rm /etc/asterisk/logger.conf
    rm /etc/asterisk/extensions.conf
    rm /etc/asterisk/iax.conf
    rm /etc/asterisk/sip_notify.conf
    rm /etc/asterisk/features.conf
    rm /etc/asterisk/sip.conf
	rm /etc/asterisk/confbridge.conf
	rm /etc/asterisk/ccss.conf 
    /var/lib/asterisk/bin/retrieve_conf 

    #Bring modules upto date and get useful modules
    /var/lib/asterisk/bin/module_admin upgradeall
    
    /var/lib/asterisk/bin/module_admin download asterisk-cli
    /var/lib/asterisk/bin/module_admin download asteriskinfo 
    /var/lib/asterisk/bin/module_admin download backup 
    /var/lib/asterisk/bin/module_admin download fw_ari
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
    /var/lib/asterisk/bin/module_admin install iaxsettings 
    /var/lib/asterisk/bin/module_admin install javassh 
    /var/lib/asterisk/bin/module_admin install languages 
    /var/lib/asterisk/bin/module_admin install logfiles 
    /var/lib/asterisk/bin/module_admin install phpinfo 
    /var/lib/asterisk/bin/module_admin install sipsettings 
    /var/lib/asterisk/bin/module_admin install weakpasswords 
    /var/lib/asterisk/bin/module_admin install fw_langpacks

    /var/lib/asterisk/bin/module_admin reload

    #Protect the Admin pages with Apache authentication.
    funcunifiedlogin admin /var/www/html/admin

    #Protect the ARI with Apache authentication.
    funcunifiedlogin recordings /var/www/html/recordings

    # Stop the ability to type the URL of the module and bypass security
    echo "
    Options -Indexes
    <Files .htaccess>
    deny from all
    </Files> 
    " > /var/www/html/admin/modules/.htaccess
    
    
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
    
    #Insert admin / admin user into FreePBX
    mysql -uroot -p$MYSQLROOTPASSWD asterisk -e "INSERT INTO ampusers (username,password_sha1,extension_low,extension_high,deptname,sections) VALUES ('vm', '3559095f228e3d157f2e10971a9283b28d86395c', '', '', '', '');"

    clear
    echo "Log into the FreePBX interface for the first time with:"
    echo "username = vm"
    echo "password = vmadmin"
    echo "This can be changed via the FreePBX administrator interface later."
    echo "Press Enter to continue"
    read TEMP
    
    
else
    clear
    echo "asterisk is not running"
    echo "please correct this before installing FreePBX"
    echo "Press enter to return to the install menu."
    read temp
fi

#Write FreePBX info
echo "MySQL Root Password = $MYSQLROOTPASS" >> /etc/ballistic/info.txt
    
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
wget http://www.ossec.net/files/ossec-hids-2.7.tar.gz
tar zxfv ossec-hids-*.tar.gz
rm -rf ossec-hids*.tar.gz
mv ossec-hids-* ossec-hids
cd ossec-hids
clear

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

<rule id="100019" level="0">
    <if_sid>31151</if_sid>
    <url>admin/config.php?</url>
    <description>Ignoring FreePBX 400 events.</description>
</rule>

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

# ---------------------- Ossec UI ------------------------
function funcossecui () 
{
clear
while true; do
    read -p "Do you wish to install The Ossec UI?  " yn
    case $yn in
        [Yy]* ) 
			cd /usr/share
			wget http://www.ossec.net/files/ossec-wui-0.3.tar.gz
			tar zxfv ossec-wui-0.3.tar.gz
			rm -rf ossec-wui-0.3.tar.gz
			mv ossec-wui* ossecui
			cd ossecui

			#Set up .htaccess
			echo '
			<Files *.sh>
  				deny from all
			</Files>

			<Files ossec_conf.php>
  				deny from all
			</Files>

			<Files .*>
  				deny from all
			</Files>
			' > /usr/share/ossecui/.htaccess

			echo '
				deny from all
			' > /usr/share/ossecui/site/.htaccess

			echo '
				deny from all
			' > /usr/share/ossecui/lib/.htaccess

			usermod -a -G ossec asterisk
	
			#Fix OSSEC UI 
			sed -i "s/\"SEEK_SET\"/SEEK_SET/g" /usr/share/ossecui/lib/os_lib_alerts.php 
	
			funcunifiedlogin ossecui /usr/share/ossecui
        	break;;
        
        
		[Nn]* ) break;;
    	* ) echo "Please answer yes or no.";;
    esac
done
#funcossecui
}

# ---------------------- Reboot ------------------------
function funcreboot () 
{
# reboot

reboot

#funcreboot
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
echo "If the Kernel has been updated, we advise you to reboot your server and re-run the install script!"
echo "If you are not sure whether the kernel has been updated, reboot and start again"
echo ""
echo "Press CTRL C to exit and reboot, or enter to continue"
[ -f /var/run/reboot-required ] && echo "*** System restart required ***" || echo "*** System restart NOT required ***"
read TEMP

apt-get install openssh-server

#check timezone
dpkg-reconfigure tzdata

#install dependencies

#for asterisk 10 & 11
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


# ---------------------- Unified Login ------------------------
#Script called with funcunifiedlogin <<directory name>> <<directory path>> e.g. funcunifiedlogin phpsysinfo . $1 will be replaced with phpsysinfo. $2 replaced with usr/share/phpsysinfo

funcunifiedlogin () {

    #Check we have the credentials stored in memory if not, prompt.
    until mysql -uasteriskuser -p$AMPDBPASS -e ";" ; do 
    	clear
		echo "MySQL FreePBX password?"
		read AMPDBPASS
		echo "Credentials incorrect"		
	done
	echo "
	Alias /$1 $2
	DocumentRoot $2/
	<directory $2>
		AllowOverride all
		Options Indexes FollowSymLinks
		order allow,deny
		allow from all
		AuthName \"PBX Access\"
		AuthType Basic
		AuthUserFile /dev/null
		AuthBasicAuthoritative off
		Auth_MySQL on
		Auth_MySQL_Authoritative on
		Auth_MySQL_Username asteriskuser
		Auth_MySQL_Password $AMPDBPASS
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
	</IfModule>

	<IfModule mod_auth_mysql.c>

	" > /etc/apache2/sites-available/$1.conf

    ln -s  /etc/apache2/sites-available/$1.conf /etc/apache2/sites-enabled/$1.conf
    service apache2 restart
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
    
    clear
    #Don't allow progress until access confirmed to database
    #Check root password set, if not, ask for it
    if [ -z "${MYSQLROOTPASSWD+xxx}" ]; then read -p "Enter MySQL root password " MYSQLROOTPASSWD; fi
	if [ -z "$MYSQLROOTPASSWD" ] && [ "${MYSQLROOTPASSWD+xxx}" = "xxx" ]; then read -p "Enter MySQL root password " MYSQLROOTPASSWD; fi 
    echo "Please enter the MySQL root password"
    until mysql -uroot -p$MYSQLROOTPASSWD -e ";" ; do 
    	clear
    	echo "Please enter the MySQL root password"
		read MYSQLROOTPASSWD
		echo "password incorrect"		
	done

#funcsetservices
}

# ---------------------- Install Public Keys ------------------------

function funcpublickey(){
#add public key to root user.
mkdir /root/.ssh
touch /root/.ssh/authorized_keys
echo '
#Delete this line, and replace with your public keys.
' >> /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
#funcpublickey
}


# ---------------------- Generate Random Password -------------------
#  $2 = include special characters; 1 = yes, 0 = no; defaults to 1
function funcrandpass() {
  [ "$2" == "0" ] && CHAR="[:alnum:]" || CHAR="[:graph:]"
   RANDOMPASSW=`cat /dev/urandom | tr -cd "$CHAR" | head -c ${1:-32}`
 }

# ---------------------- Configure HTTPS / SSL Security ------------
function funcssl() {
	#enable SSL on the server
	a2enmod ssl

	#enable rewrite on the server
	a2enmod rewrite

	#Enable SSL
	ln -s /etc/apache2/sites-available/default-ssl /etc/apache2/sites-enabled/000-default-ssl


	# SSL for Web pages 

	echo '

<Directory /var/www/>
    # Redirect administration interface to https
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}/admin
</Directory>
' > /etc/apache2/sites-available/freepbx_ssl.conf

	ln -s /etc/apache2/sites-available/freepbx_ssl.conf /etc/apache2/sites-enabled/freepbx_ssl.conf


	service apache2 restart
	
#End funcssl
 }


# ---------------------- Add installation info ------------
function funcinfo ()
{

	mkdir /etc/ballistic/
	touch /etc/ballistic/info.txt
	echo "installation date $(date)" >> /etc/ballistic/info.txt
	ifconfig | awk '/eth/ { print "MAC Address = " $5 }' >> /etc/ballistic/info.txt 
	ifconfig | awk '/inet addr/ { print "IPV4 = " $2 }'>> /etc/ballistic/info.txt
	ifconfig | awk '/inet6 addr/ { print "IPV6 = " $3 }' >> /etc/ballistic/info.txt

#funcinfo	
}


# ---------------------- Menu ------------------------


show_menu_pabx() {
    clear
    echo " > Asterisk/FreePBX Installation Menu (Ubuntu)"
    echo "================================"
    echo "  1)  Install all"
    echo "  2)  Install dependencies"
    echo "  3)  Asterisk"
    echo "  4)  FreePBX"
    echo "  5)  IP-Tables"
    echo "  6)  Ossec Security"
    echo "  7)  HTTPS / SSL Security"
    echo "  8)  Reboot"
    echo "  9)  Add public key"
    echo "  0)  Quit"
    echo -n "(0-8) : "
    read OPTION < /dev/tty
}


ExitFinish=0

while [ $ExitFinish -eq 0 ]; do

    # Show menu with Installation items
    show_menu_pabx

    case $OPTION in
        1) 
            funcdependencies
            funcinfo
            funcsetclock
            funcsetservices
            funcasterisk
            funcfreepbx
            funcssl
            funciptables
            funcossec
            funcossecui
            echo "done"
        ;;
        2) 
            funcdependencies
            funcsetclock
            funcsetservices
            funcinfo

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
            funcossecui
        ;;
        7) 
            funcssl
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

