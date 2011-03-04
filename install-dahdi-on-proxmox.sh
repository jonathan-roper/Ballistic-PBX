#/bin/sh
#Install Dahdi on Proxmox version 1.3
#Copyright (C) 2009-2011 Jonathan Roper joe.roper@gmail.com

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


apt-get -y update
apt-get -y upgrade


#install asterisk dependencies
apt-get -y --fix-missing install build-essential make libncurses5-dev libcurl4-openssl-dev  pve-headers-`uname -r`



echo "Please reboot and re-run this script"
echo "CTRL-C to exit or Enter to continue"
read TEMP


cd /usr/src/

wget http://downloads.digium.com/pub/telephony/dahdi-linux-complete/dahdi-linux-complete-current.tar.gz

tar zxfv dahdi-linux-complete-current.tar.gz


rm -rf *.tar.gz
rm -rf dahdi-linux-complete

mv dahdi-linux-complete* dahdi-linux-complete


#Install Dahdi

cd dahdi-linux-complete
make all
make install
make config

#fix startup problems
sed -i 's/modprobe dahdi/modprobe -f dahdi/g'  /etc/init.d/dahdi
/etc/init.d/dahdi restart


touch /usr/local/sbin/pabx-enable-conference
echo '
#/bin/sh
#Enable conference on Proxmox version 1.3 - Dahdi Version
#Copyright (C) 2009 Jonathan Roper joe.roper@gmail.com

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

clear
echo "This script enables call conferencing in the VE"
echo  "please enter the VE number"
read VENUMBER
vzctl set $VENUMBER --devnodes dahdi/pseudo:rw --save
vzctl exec $VENUMBER chown -R asterisk /dev/dahdi /lib/udev/devices/dahdi
vzctl exec $VENUMBER chgrp -R asterisk /dev/dahdi /lib/udev/devices/dahdi

echo "Job Done - Now reload asterisk in VE-"$VENUMBER
' > /usr/local/sbin/pabx-enable-conference
chmod +x /usr/local/sbin/pabx-enable-conference


#Create Template script
touch /usr/local/sbin/pabx-create-template
echo '
#/bin/sh
#Creates template.
#Copyright (C) 2009-2011 Jonathan Roper joe.roper@gmail.com

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

#!/bin/bash
#Create Template script - Joe Roper 2009-2011
clear
echo "Creates a template"
echo  "please enter the VE number"
read VENUMBER
vzctl stop $VENUMBER
vzctl set $VENUMBER --ipdel all --save 
echo "Create a name for your template"
echo "This must be in form OS-version-ASINGLEWORD_Vers_arch"
echo "eg centos-5-pabx-1_x86 or centos-5-pabx-1_amd64"
read TEMPLATENAME
cd /var/lib/vz/private/$VENUMBER
echo > "" /etc/resolv.conf
echo > "" /root/.bash-history
tar czfv /var/lib/vz/template/cache/$TEMPLATENAME.tar.gz *
echo "Job Done - Now install from the GUI"
' > /usr/local/sbin/pabx-create-template
chmod +x /usr/local/sbin/pabx-create-template

/etc/init.d/dahdi restart


#Add Eth0 for G729 and asterisk registrations.



touch /usr/local/sbin/pabx-create-eth0
echo '
#/bin/sh
#Creates Eth0 for Digium registration.
#Copyright (C) 2009-2011 Jonathan Roper joe.roper@gmail.com

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

#!/bin/bash
#Create Eth0 script - Joe Roper 2009
clear
echo "Creates an eth0 on the container - Do not run this more than once"
echo  "please enter the VE number"
read VENUMBER
set - `/sbin/ifconfig eth0 | head -1`
echo "Mac Address = ""$MAC$5"
echo "Please restart container $VENUMBER"
' > /usr/local/sbin/pabx-create-eth0
echo 'echo NETIF="ifname=eth0,mac=$MAC$5,host_mac=96:F0:7C:4F:5E:DA" >> /etc/vz/conf/$VENUMBER.conf' >> /usr/local/sbin/pabx-create-eth0
chmod +x /usr/local/sbin/pabx-create-eth0


#Allow IPtables to work on the VE
sed -i 's|ipt_REJECT ipt_tos ipt_limit ipt_multiport iptable_filter iptable_mangle ipt_TCPMSS ipt_tcpmss ipt_ttl ipt_length|ipt_REJECT ipt_tos ipt_TOS ipt_LOG ip_conntrack ipt_limit ipt_multiport iptable_filter iptable_mangle ipt_TCPMSS ipt_tcpmss ipt_ttl ipt_length ipt_state iptable_nat ip_nat_ftp|' /etc/vz/vz.conf 

/etc/init.d/vz restart 
echo "Now correct /usr/local/sbin/pabx-create-eth0" 
echo " There may be other problems to correct
If you get this error:
FATAL: Error inserting dahdi (/lib/modules/2.6.18.8-linode19/dahdi/dahdi.ko): Invalid module format
FATAL: Error inserting dahdi (/ lib/modules/2.6.18.8-linode19/dahdi/dahdi.ko): Invalid module format
Tenemos que modificar el script del arranque de DAHDI
We have to modify the startup script DAHDI
nano /etc/init.d/dahdi
nano / etc / init.d / dahdi
modificar estas dos l�neas:
modify these two lines:
modprobe dahdi
modprobe dahdi
modprobe dahdi_dummy 2> /dev/null
dahdi_dummy modprobe 2> / dev / null
para que queden
to make them
modprobe �f dahdi
modprobe-f dahdi
modprobe �f dahdi_dummy 2> /dev/null
dahdi_dummy modprobe-f 2> / dev / null
Volvemos a arrancar DAHDI
Restart DAHDI
/etc/init.d/dahdi start
/ etc / init.d / dahdi start"

INSTALLWEBMIN=2
until [ $INSTALLWEBMIN -lt 2 ] ; do
	clear
	echo "Do you want to install Webmin Y/n"
	echo "Press 0 for Yes or 1 for No"
	read INSTALLWEBMIN < /dev/tty
	echo $INSTALLWEBMIN
done

if [ $INSTALLWEBMIN = 0 ]; then
	rm -rf webmin-1*.deb
	cd /usr/src
	apt-get -y install libio-pty-perl libmd5-perl libnet-ssleay-perl  libauthen-pam-perl
	wget http://downloads.sourceforge.net/project/webadmin/webmin/1.500/webmin_1.500_all.deb?use_mirror=ignum
	dpkg --install webmin*
	rm -rf webmin-1*.rpm
fi