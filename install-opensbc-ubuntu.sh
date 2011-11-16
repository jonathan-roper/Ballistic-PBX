#!/bin/bash
#OpenSBC Debian

#/bin/sh
#Install OpenSBC - CentOS edition
#Copyright (C) 2010 Star2Billing S.L.
#Author Jonathan Roper jonathan@star2billing.com

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

#==================================================================================================
#This script will install OpenSBC on an existing asterisk server, and will be available on port 5061
#It will provide upwards registration, and RTP proxy services.
#No configuration in Asterisk is required.
#Simply point your phone at <<IPADDR>>:5061
#If this is installed behind NAT, forward UDP 5061 and 10,000 > 20,000
#==================================================================================================

apt-get update

apt-get install -y mc autoconf automake cvs flex expat libexpat1-dev libtool build-essential libxml2 libxml2-dev libtiff4 libtiff4-dev libssl-dev libncurses5-dev bison libaudiofile-dev subversion libnewt-dev libcurl3-dev libnet-ssleay-perl openssl ssl-cert libauthen-pam-perl libio-pty-perl libcrypt-passwdmd5-perl libdigest-md5-perl libpg-perl libdbd-pg-perl openssl ssl-cert flex bison build-essential libxml2 libxml2-dev expat libexpat1-dev libspeex-dev speex


cd /usr/src

echo "================================================================================"
echo "When prompted for a CVS password, just press enter"
echo "================================================================================"


cvs -d:pserver:anonymous@opensipstack.cvs.sourceforge.net:/cvsroot/opensipstack login
cvs -z3 -d:pserver:anonymous@opensipstack.cvs.sourceforge.net:/cvsroot/opensipstack co -P opensipstack
cvs -z3 -d:pserver:anonymous@opensipstack.cvs.sourceforge.net:/cvsroot/opensipstack co -P opensbc

cd /usr/src/opensipstack/
chmod +x ./configure
./configure --enable-localspeex --enable-gpllibs
make bothnoshared
cd ../opensbc
chmod +x ./configure
./configure --enable-gpllibs
make bothnoshared
make distrib


cp /usr/src/opensbc/distrib/* /usr/local/bin/
echo "/usr/local/bin/opensbc -d -p /var/run/opensbc.pid -H 65536 -C 1024000" > /usr/local/bin/startup.sh
echo "/usr/local/bin/opensbc -u root -k -p /var/run/opensbc.pid" > /usr/local/bin/shutdown.sh

echo "/usr/local/bin/startup.sh"  >> /etc/rc.local

mkdir /root/OpenSIPStack
mkdir /root/OpenSIPStack/OpenSBC_data


echo "
[OpenSBC-General-Parameters]
SIP-Log-Level=1
PTRACE-Log-Level=1
Log-File-Prefix=b2bua
SBC-Application-Mode=B2BUpperReg Mode
Enable-Trunk-Port=True
Enable-Calea-Port=True
RTP-Min-Port=10000
RTP-Max-Port=20000
NAT-Keep-Alive-Interval=15
Send-OPTIONS-NAT-Keep-Alive=True
Send-Responses-Using-New-Socket=False
Enable-Local-Refer=False
Disable-Refer-Optimization=True
Max-Forwards=70
Encryption-Mode=XOR
Encryption-Key=GS
Alerting-Timeout=30000
Seize-Timeout=60000
SIP-Timer-B=Default
SIP-Timer-H=Default
Session-Keep-Alive=1800
Session-Max-Life-Span=10800
Max-Concurrent-Session=100
Max-Call-Rate-Per-Second=10

[SIP-Transports]
Main-Interface-Address Array Size=1
Main-Interface-Address 1=sip:*:5061
Backdoor-Interface-Address=sip:*:5062
Trunk-Interface-Address=sip:*:5064
Media-Server-Interface-Address=sip:*:5066
CALEA-Interface-Address=sip:*:5068
Auxiliary-Interface-Address=sip:*:5070
Interface-Route-List Array Size=0

[RTP-Proxy]
Proxy-On-Private-Contact=True
Proxy-On-via-received-vs-signaling-address=True
Proxy-On-Private-Via=True
Proxy-On-Different-RPORT=True
Proxy-All-Media=False

[Trusted-Domains]
Accept-All-Calls=True
Trusted-Domain-List Array Size=0
X-Remote-Info-List Array Size=0

[Host-Access-List]
Trust-All-Hosts=True
Trusted-Host-List Array Size=0
Enable-Selective-Banning=True
Banned-Host-List Array Size=0

[Upper-Registration]
All-Reg-As-Upper-Reg=True
Enable-Stateful-Reg=False
Rewrite-TO-Domain=True
Rewrite-FROM-Domain=True
Route-List Array Size=1
Route-List 1=[sip:*] sip:127.0.0.1:5060

[B2BUA-Routes]
Route-List Array Size=1
Route-List 1=[sip:*] sip:127.0.0.1:5060
Insert-Route-Header=True
Rewrite-TO-URI=True
Prepend-ISUP-OLI=False
Route-By-Request-URI=False
Route-By-To-URI=False
Drop-Routes-On-Ping-Timeout=False
Use-External-XML=False
External-XML-File=b2bua-route.xml

" > /root/OpenSIPStack/OpenSBC_data/OpenSBC.ini


echo "================================================================================"
echo "The web interface for this is on <<ipaddress>:9999"
echo "By default it has no password on it"
echo "After reboot, please go to the website and configure a username and password"
echo "================================================================================"
echo "Please reboot"
echo "================================================================================"


echo 
'1. http://11.22.33.44:9999/Internal-DNS-Mapping

This is where we create the DNS entries for the internal IP addresses, this not compulsory, but it does make admin easier.

So assuming you have pbx.yourdomain.com on 192.168.1.101, 

Create a DNS entry on your DNS server for pbx.yourdomain.com = 11.22.33.44
Now add the internal DNS mapping with [sip:pbx.yourdomain.com] sip:192.168.1.101:5060
Click the update button.
Repeat as necessary for all PBX systems.

2. http://11.22.33.44:9999/Upper-Registration

Next we need to deal with the registration aspect, so that when you create an extension on a PBX, OpenSBC checks to see that it is valid.

Edit Route list, and add entries for each of your PBX systems.
[sip:*@pbx.yourdomain.com:*] sip:pbx.yourdomain.com:5060

or if you have not bothered with Step one - [sip:*@pbx.yourdomain.com:*] sip:192.168.1.101:5060 

Then click the update button

So registrations that are sent to pbx.yourdomain.com will be forwarded to the internal PBX, and if the username and password is correct, OpenSBC will allow the endpoint to register. Note that the endpoint must be configured with the hostname, e.g. pbx.yourdomain.com, NOT 11.22.33.44

Repeat as necessary for all PBX systems.

3. http://11.22.33.44:9999/B2BUA-Routes

This is how the call is actually routed when someone picks up the phone and makes a call.

The syntax here is the same as in step 2 for upper registration, e.g.Edit Route list, and add entries for each of your PBX systems.

[sip:*@pbx.yourdomain.com:*] sip:pbx.yourdomain.com:5060

or if you have not bothered with Step one - [sip:*@pbx.yourdomain.com:*] sip:192.168.1.101:5060

Then click the update button.


4. Register your endpoint 

Now attempt to register a phone to your extension@pbx.yourdomain.com and make a call.

5. DID forwarding

To forward DID to your systems from your DID provider or A2Billing system, simply forward the DID to sip/DID-Number@pbx.yourdomain.com


Please test and test again, particularly in respect of MWI lights, extension to extension calls and check that it does what you need it do.
' > /root/OpenSIPStack/README