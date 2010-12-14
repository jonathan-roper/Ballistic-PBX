#/bin/sh
#Install PIAF on existing copy of CentOS Version 1.02 32 or 64 bit Operating system only
#Copyright (C) 2010 Star2Billing S.L, sales@star2billing.com 

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

#CHANGELOG
#6th Septempber 2010 v1.01
#Change php-pear-DB from php-pear-db
#16th November 2010 v1.02
#Rewrite to support PiaF 1.7.5.5.3 and 64 bit
#This script was sponsored by Sheldon Steele of the ITS Group, http://www.itsgroup.org/
#recreate yum install list for 32bit install to include dialog
#Change php-pear-DB from php-pear-db v1.04


#Variables
KERNELARCH=$(uname -p)
PIAFLOC64=http://ignum2.dl.sourceforge.net/project/pbxinaflash/PIAF-1.7.5.5.3-CentOS-5.5-64bit/pbxinaflash-x86_64-17553.iso
PIAFLOC32=http://mesh.dl.sourceforge.net/project/pbxinaflash/PIAF-1.7.5.5.3-CentOS-5.5-32bit/pbxinaflash-17553.iso
PIAFVERS=1.7.5.5.3


clear
echo "Install PBX in a Flash on existing installation of CentOS bit"
echo ""
echo "Author, Joe Roper, sales@star2billing.com"
echo ""
echo "Released under the GPL."
echo ""
echo ""
echo "This is for CentOS 64 bit and 32 bit installs"
echo "Press CTRL C to exit or enter to continue"
read TEMP
clear

#Set up the time and date so we don't get any issues with Zap / dahdi compiling.
yum -y install ntp
service ntpd start
/usr/sbin/ntpdate -su pool.ntp.org
service ntpd stop
ntpdate pool.ntp.org
service ntpd start
hwclock --systohc
chkconfig ntpd on

#Disable SELINUX
sed -i 's/=enforcing/=disabled/g'  /etc/sysconfig/selinux

#The list of packages to install is created by doing a PiaF install as far as the ISO, but not
#going on to install PBX in a Flash. You can then install 
#yum-utils (yum install yum-utils) then type yum list installed > yumlist.txt
#Then import this file into Excel, and copy column A. Paste it into a new sheet,
#with Paste special, transpose.
#Save it as an MSDOS CSV file, then open in Notepad, then find and replace all commas with spaces.
#Copy this line below, and the script is updated.

if [ $KERNELARCH = "x86_64" ]; then
	# Install the 64 bit PIAF Dependencies.
	yum -y install GConf2.x86_64 MAKEDEV.x86_64 NetworkManager.x86_64 NetworkManager-glib.x86_64 ORBit2.x86_64 SDL.x86_64 SysVinit.x86_64 acpid.x86_64 alsa-lib.x86_64 alsa-lib-devel.x86_64 alsa-utils.x86_64 amtu.x86_64 anacron.x86_64 apr.x86_64 apr-util.x86_64 arts.x86_64 arts-devel.x86_64 aspell.x86_64 aspell-en.x86_64 at.x86_64 atk.x86_64 atk-devel.x86_64 attr.x86_64 audiofile.x86_64 audiofile-devel.x86_64 audit.x86_64 audit-libs.x86_64 audit-libs-python.x86_64 authconfig.x86_64 authconfig-gtk.x86_64 autoconf.noarch autofs.x86_64 automake.noarch automake14.noarch automake15.noarch automake16.noarch automake17.noarch avahi.x86_64 avahi-compat-libdns_sd.x86_64 avahi-glib.x86_64 basesystem.noarch bash.x86_64 bc.x86_64 bind.x86_64 bind-libs.x86_64 bind-utils.x86_64 binutils.x86_64 bison.x86_64 bitstream-vera-fonts.noarch bluez-gnome.x86_64 bluez-libs.x86_64 bluez-utils.x86_64 bzip2.x86_64 bzip2-libs.x86_64 cairo.x86_64 ccid.x86_64 centos-release.x86_64 centos-release-notes.x86_64 chkconfig.x86_64 chkfontpath.x86_64 comps-extras.noarch conman.x86_64 coolkey.x86_64 coreutils.x86_64 cpio.x86_64 cpp.x86_64 cpuspeed.x86_64 cracklib.x86_64 cracklib-dicts.x86_64 crash.x86_64 crontabs.noarch cryptsetup-luks.x86_64 cups.x86_64 cups-libs.x86_64 curl.x86_64 curl-devel.x86_64 cvs.x86_64 cyrus-sasl.x86_64 cyrus-sasl-lib.x86_64 cyrus-sasl-plain.x86_64 db4.x86_64 dbus.x86_64 dbus-glib.x86_64 dbus-libs.x86_64 dbus-python.x86_64 dejavu-lgc-fonts.noarch desktop-backgrounds-basic.noarch desktop-file-utils.x86_64 device-mapper.x86_64 device-mapper-event.x86_64 device-mapper-multipath.x86_64 dhclient.x86_64 dhcp.x86_64 dhcpv6-client.x86_64 dialog.x86_64 diffutils.x86_64 dmidecode.x86_64 dmraid.x86_64 docbook-dtds.noarch dos2unix.x86_64 dosfstools.x86_64 dump.x86_64 e2fsprogs.x86_64 e2fsprogs-devel.x86_64 e2fsprogs-libs.x86_64 ed.x86_64 eject.x86_64 elfutils.x86_64 elfutils-libelf.x86_64 elfutils-libs.x86_64 esound.x86_64 esound-devel.x86_64 ethtool.x86_64 expat.x86_64 fbset.x86_64 file.x86_64 filesystem.x86_64 findutils.x86_64 finger.x86_64 fipscheck.x86_64 fipscheck-lib.x86_64 firstboot.x86_64 firstboot-tui.x86_64 flex.x86_64 flite.x86_64 flite-devel.x86_64 fontconfig.x86_64 freetype.x86_64 freetype-devel.x86_64 ftp.x86_64 gamin.x86_64 gamin-python.x86_64 gawk.x86_64 gcc.x86_64 gcc-c++.x86_64 gd.x86_64 gdbm.x86_64 gettext.x86_64 glib2.x86_64 glib2-devel.x86_64 glibc.i686 glibc.x86_64 glibc-common.x86_64 glibc-devel.x86_64 glibc-headers.x86_64 gmp.x86_64 gnome-doc-utils.noarch gnome-keyring.x86_64 gnome-mime-data.x86_64 gnome-mount.x86_64 gnome-python2.x86_64 gnome-python2-bonobo.x86_64 gnome-python2-canvas.x86_64 gnome-python2-gconf.x86_64 gnome-python2-gnomevfs.x86_64 gnome-vfs2.x86_64 gnupg.x86_64 gnutls.x86_64 gpm.x86_64 grep.x86_64 groff.x86_64 grub.x86_64 gtk2.x86_64 gtk2-devel.x86_64 gtk2-engines.x86_64 gzip.x86_64 hal.x86_64 hesiod.x86_64 hicolor-icon-theme.noarch htmlview.noarch httpd.x86_64 hwdata.noarch ifd-egate.x86_64 imake.x86_64 info.x86_64 initscripts.x86_64 iproute.x86_64 ipsec-tools.x86_64 iptables.x86_64 iptables-ipv6.x86_64 iptstate.x86_64 iputils.x86_64 irda-utils.x86_64 irqbalance.x86_64 jack-audio-connection-kit.x86_64 joe.x86_64 jwhois.x86_64 kbd.x86_64 kernel.x86_64 kernel-devel.x86_64 kernel-headers.x86_64 keyutils-libs.x86_64 keyutils-libs-devel.x86_64 kpartx.x86_64 krb5-devel.x86_64 krb5-libs.x86_64 krb5-workstation.x86_64 ksh.x86_64 kudzu.x86_64 lcms.x86_64 less.x86_64 lftp.x86_64 libFS.x86_64 libICE.x86_64 libIDL.x86_64 libSM.x86_64 libX11.x86_64 libX11-devel.x86_64 libXTrap.x86_64 libXau.x86_64 libXaw.x86_64 libXcursor.x86_64 libXdmcp.x86_64 libXext.x86_64 libXfixes.x86_64 libXfont.x86_64 libXfontcache.x86_64 libXft.x86_64 libXi.x86_64 libXinerama.x86_64 libXmu.x86_64 libXpm.x86_64 libXrandr.x86_64 libXrender.x86_64 libXres.x86_64 libXt.x86_64 libXtst.x86_64 libXv.x86_64 libXxf86dga.x86_64 libXxf86misc.x86_64 libXxf86vm.x86_64 libacl.x86_64 libaio.x86_64 libart_lgpl.x86_64 libart_lgpl-devel.x86_64 libattr.x86_64 libbonobo.x86_64 libbonoboui.x86_64 libcap.x86_64 libdaemon.x86_64 libdmx.x86_64 libdrm.x86_64 libevent.x86_64 libfontenc.x86_64 libgcc.x86_64 libgcrypt.x86_64 libglade2.x86_64 libgnome.x86_64 libgnomecanvas.x86_64 libgnomeui.x86_64 libgomp.x86_64 libgpg-error.x86_64 libgssapi.x86_64 libhugetlbfs.x86_64 libidn.x86_64 libidn-devel.x86_64 libjpeg.x86_64 libmng.x86_64 libnotify.x86_64 libogg.x86_64 libogg-devel.x86_64 libpcap.x86_64 libpng.x86_64 libselinux.x86_64 libselinux-devel.x86_64 libselinux-python.x86_64 libsemanage.x86_64 libsepol.x86_64 libsepol-devel.x86_64 libstdc++.x86_64 libstdc++-devel.x86_64 libsysfs.x86_64 libtermcap.x86_64 libtermcap-devel.x86_64 libtiff.x86_64 libtiff-devel.x86_64 libtool-ltdl.x86_64 libtool-ltdl-devel.x86_64 libusb.x86_64 libusb-devel.x86_64 libuser.x86_64 libutempter.x86_64 libvolume_id.x86_64 libvorbis.x86_64 libvorbis-devel.x86_64 libwnck.x86_64 libxkbfile.x86_64 libxml2.x86_64 libxml2-devel.x86_64 libxml2-python.x86_64 libxslt.x86_64 lm_sensors.x86_64 lockdev.x86_64 lockdev-devel.x86_64 logrotate.x86_64 logwatch.noarch lsof.x86_64 lvm2.x86_64 m2crypto.x86_64 m4.x86_64 mailcap.noarch mailx.x86_64 make.x86_64 man.x86_64 man-pages.noarch mc.x86_64 mcelog.x86_64 mcstrans.x86_64 mdadm.x86_64 mesa-libGL.x86_64 mesa-libGL-devel.x86_64 metacity.x86_64 mgetty.x86_64 microcode_ctl.x86_64 mingetty.x86_64 mkbootdisk.x86_64 mkinitrd.x86_64 mkisofs.x86_64 mktemp.x86_64 mlocate.x86_64 module-init-tools.x86_64 mtools.x86_64 mtr.x86_64 mysql.x86_64 mysql-devel.x86_64 mysql-server.x86_64 nano.x86_64 nas.x86_64 nash.x86_64 nc.x86_64 ncurses.x86_64 ncurses-devel.x86_64 neon.x86_64 net-tools.x86_64 newt.x86_64 newt-devel.x86_64 nfs-utils.x86_64 nfs-utils-lib.x86_64 notification-daemon.x86_64 notify-python.x86_64 nscd.x86_64 nspr.x86_64 nss.x86_64 nss-tools.x86_64 nss_db.x86_64 nss_ldap.x86_64 ntp.x86_64 ntsysv.x86_64 numactl.x86_64 oddjob.x86_64 oddjob-libs.x86_64 openjade.x86_64 openldap.x86_64 openldap-devel.x86_64 opensp.x86_64 openssh.x86_64 openssh-clients.x86_64 openssh-server.x86_64 openssl.x86_64 openssl-devel.x86_64 pam.x86_64 pam_ccreds.x86_64 pam_krb5.x86_64 pam_passwdqc.x86_64 pam_pkcs11.x86_64 pam_smb.x86_64 pango.x86_64 paps.x86_64 parted.x86_64 passwd.x86_64 patch.x86_64 pax.x86_64 pciutils.x86_64 pcmciautils.x86_64 pcre.x86_64 pcsc-lite.x86_64 pcsc-lite-libs.x86_64 perl.x86_64 perl-Compress-Zlib.x86_64 perl-DBD-MySQL.x86_64 perl-DBI.x86_64 perl-DateManip.noarch perl-Digest-HMAC.noarch perl-Digest-SHA1.x86_64 perl-HTML-Parser.x86_64 perl-HTML-Tagset.noarch perl-Net-DNS.x86_64 perl-Net-IP.noarch perl-String-CRC32.x86_64 perl-URI.noarch perl-XML-Parser.x86_64 perl-libwww-perl.noarch perl-suidperl.x86_64 pfmon.x86_64 php.x86_64 php-cli.x86_64 php-common.x86_64 php-devel.x86_64 php-gd.x86_64 php-ldap.x86_64 php-mbstring.x86_64 php-mysql.x86_64 php-pdo.x86_64 php-pear.noarch php-pear-DB.noarch piafdl.noarch piafxtras.noarch pinfo.x86_64 pirut.noarch pkgconfig.x86_64 pkinit-nss.x86_64 pm-utils.x86_64 policycoreutils.x86_64 popt.x86_64 portmap.x86_64 postgresql-libs.x86_64 ppp.x86_64 procmail.x86_64 procps.x86_64 psacct.x86_64 psmisc.x86_64 pulseaudio-libs.x86_64 pycairo.x86_64 pygobject2.x86_64 pygtk2.x86_64 pygtk2-libglade.x86_64 pyorbit.x86_64 python.x86_64 python-elementtree.x86_64 python-iniparse.noarch python-numeric.x86_64 python-sqlite.x86_64 python-urlgrabber.noarch pyxf86config.x86_64 qt.x86_64 quota.x86_64 rdate.x86_64 rdist.x86_64 readahead.x86_64 readline.x86_64 readline-devel.x86_64 redhat-artwork.x86_64 redhat-logos.noarch redhat-lsb.x86_64 redhat-menus.noarch rhpl.x86_64 rhpxl.x86_64 rmt.x86_64 rng-utils.x86_64 rootfiles.noarch rp-pppoe.x86_64 rpm.x86_64 rpm-build.x86_64 rpm-libs.x86_64 rpm-python.x86_64 rsh.x86_64 rsync.x86_64 scrollkeeper.x86_64 sed.x86_64 selinux-policy.noarch sendmail.x86_64 setarch.x86_64 setup.noarch setuptool.x86_64 sgml-common.noarch shadow-utils.x86_64 shared-mime-info.x86_64 slang.x86_64 slang-devel.x86_64 smartmontools.x86_64 sos.noarch sox.x86_64 specspo.noarch sqlite.x86_64 startup-notification.x86_64 stunnel.x86_64 subversion.x86_64 sudo.x86_64 symlinks.x86_64 sysfsutils.x86_64 sysklogd.x86_64 syslinux.x86_64 system-config-date.noarch system-config-network.noarch system-config-network-tui.noarch system-config-securitylevel-tui.x86_64 talk.x86_64 tar.x86_64 tcp_wrappers.x86_64 tcpdump.x86_64 tcsh.x86_64 telnet.x86_64 termcap.noarch tftp-server.x86_64 time.x86_64 tmpwatch.x86_64 traceroute.x86_64 tree.x86_64 ttmkfdir.x86_64 tzdata.x86_64 udev.x86_64 unix2dos.x86_64 unixODBC.x86_64 unzip.x86_64 usbutils.x86_64 usermode.x86_64 usermode-gtk.x86_64 util-linux.x86_64 vconfig.x86_64 vim-minimal.x86_64 vixie-cron.x86_64 webmin.noarch wget.x86_64 which.x86_64 wireless-tools.x86_64 words.noarch wpa_supplicant.x86_64 xinetd.x86_64 xml-common.noarch xorg-x11-drv-evdev.x86_64 xorg-x11-drv-keyboard.x86_64 xorg-x11-drv-mouse.x86_64 xorg-x11-drv-vesa.x86_64 xorg-x11-drv-void.x86_64 xorg-x11-filesystem.noarch xorg-x11-font-utils.x86_64 xorg-x11-fonts-base.noarch xorg-x11-server-Xorg.x86_64 xorg-x11-server-utils.x86_64 xorg-x11-twm.x86_64 xorg-x11-utils.x86_64 xorg-x11-xauth.x86_64 xorg-x11-xfs.x86_64 xorg-x11-xinit.x86_64 xorg-x11-xkb-utils.x86_64 xulrunner.x86_64 yelp.x86_64 yp-tools.x86_64 ypbind.x86_64 yum.noarch yum-metadata-parser.x86_64 yum-updatesd.noarch yum-utils.noarch zip.x86_64 zlib.x86_64 zlib-devel.x86_64
else
	# Install the 32 bit PIAF Dependencies.
	yum -y install GConf2.i386 MAKEDEV.i386 NetworkManager.i386 NetworkManager-glib.i386 ORBit2.i386 OpenIPMI.i386 OpenIPMI-libs.i386 SDL.i386 SysVinit.i386 acpid.i386 alsa-lib.i386 alsa-lib-devel.i386 alsa-utils.i386 amtu.i386 anacron.i386 apmd.i386 apr.i386 apr-util.i386 arts.i386 arts-devel.i386 aspell.i386 aspell-en.i386 at.i386 atk.i386 atk-devel.i386 attr.i386 audiofile.i386 audiofile-devel.i386 audit.i386 audit-libs.i386 audit-libs-python.i386 authconfig.i386 authconfig-gtk.i386 autoconf.noarch autofs.i386 automake.noarch avahi.i386 avahi-compat-libdns_sd.i386 avahi-glib.i386 basesystem.noarch bash.i386 bc.i386 bind.i386 bind-libs.i386 bind-utils.i386 binutils.i386 bison.i386 bitstream-vera-fonts.noarch bluez-gnome.i386 bluez-libs.i386 bluez-utils.i386 bzip2.i386 bzip2-libs.i386 cairo.i386 cairo-devel.i386 ccid.i386 centos-release.i386 centos-release-notes.i386 chkconfig.i386 chkfontpath.i386 comps-extras.noarch conman.i386 coolkey.i386 coreutils.i386 cpio.i386 cpp.i386 cpuspeed.i386 cracklib.i386 cracklib-dicts.i386 crash.i386 crontabs.noarch cryptsetup-luks.i386 cups.i386 cups-libs.i386 curl.i386 curl-devel.i386 cvs.i386 cyrus-sasl.i386 cyrus-sasl-lib.i386 cyrus-sasl-plain.i386 db4.i386 dbus.i386 dbus-glib.i386 dbus-libs.i386 dbus-python.i386 dejavu-lgc-fonts.noarch desktop-backgrounds-basic.noarch desktop-file-utils.i386 device-mapper.i386 device-mapper-event.i386 device-mapper-multipath.i386 dhclient.i386 dhcp.i386 dhcpv6-client.i386 dialog.i386 diffutils.i386 dmidecode.i386 dmraid.i386 dmraid-events.i386 dnsmasq.i386 docbook-dtds.noarch dos2unix.i386 dosfstools.i386 dump.i386 e2fsprogs.i386 e2fsprogs-devel.i386 e2fsprogs-libs.i386 ed.i386 eject.i386 elfutils.i386 elfutils-libelf.i386 elfutils-libs.i386 esound.i386 esound-devel.i386 ethtool.i386 expat.i386 fbset.i386 file.i386 filesystem.i386 findutils.i386 finger.i386 fipscheck.i386 fipscheck-lib.i386 firstboot.i386 firstboot-tui.i386 flex.i386 flite.i386 flite-devel.i386 fontconfig.i386 fontconfig-devel.i386 freetype.i386 freetype-devel.i386 ftp.i386 gamin.i386 gamin-python.i386 gawk.i386 gcc.i386 gcc-c++.i386 gd.i386 gdbm.i386 gettext.i386 glib2.i386 glib2-devel.i386 glibc.i686 glibc-common.i386 glibc-devel.i386 glibc-headers.i386 gmp.i386 gnome-doc-utils.noarch gnome-keyring.i386 gnome-mime-data.i386 gnome-mount.i386 gnome-python2.i386 gnome-python2-bonobo.i386 gnome-python2-canvas.i386 gnome-python2-gconf.i386 gnome-python2-gnomevfs.i386 gnome-vfs2.i386 gnupg.i386 gnutls.i386 gpm.i386 grep.i386 groff.i386 grub.i386 gtk2.i386 gtk2-devel.i386 gtk2-engines.i386 gzip.i386 hal.i386 hesiod.i386 hicolor-icon-theme.noarch hmaccalc.i386 htmlview.noarch httpd.i386 hwdata.noarch ibmasm.i386 ifd-egate.i386 imake.i386 info.i386 initscripts.i386 iproute.i386 ipsec-tools.i386 iptables.i386 iptables-ipv6.i386 iptstate.i386 iputils.i386 irda-utils.i386 irqbalance.i386 jack-audio-connection-kit.i386 joe.i386 jwhois.i386 kbd.i386 kernel.i686 kernel-devel.i686 kernel-headers.i386 keyutils-libs.i386 keyutils-libs-devel.i386 kpartx.i386 krb5-devel.i386 krb5-libs.i386 krb5-workstation.i386 ksh.i386 kudzu.i386 lcms.i386 less.i386 lftp.i386 libFS.i386 libICE.i386 libIDL.i386 libSM.i386 libX11.i386 libX11-devel.i386 libXTrap.i386 libXau.i386 libXau-devel.i386 libXaw.i386 libXcursor.i386 libXcursor-devel.i386 libXdmcp.i386 libXdmcp-devel.i386 libXext.i386 libXext-devel.i386 libXfixes.i386 libXfixes-devel.i386 libXfont.i386 libXfontcache.i386 libXft.i386 libXft-devel.i386 libXi.i386 libXi-devel.i386 libXinerama.i386 libXinerama-devel.i386 libXmu.i386 libXpm.i386 libXrandr.i386 libXrandr-devel.i386 libXrender.i386 libXrender-devel.i386 libXres.i386 libXt.i386 libXtst.i386 libXv.i386 libXxf86dga.i386 libXxf86misc.i386 libXxf86vm.i386 libacl.i386 libaio.i386 libart_lgpl.i386 libart_lgpl-devel.i386 libattr.i386 libbonobo.i386 libbonoboui.i386 libcap.i386 libdaemon.i386 libdmx.i386 libdrm.i386 libfontenc.i386 libgcc.i386 libgcrypt.i386 libglade2.i386 libgnome.i386 libgnomecanvas.i386 libgnomeui.i386 libgomp.i386 libgpg-error.i386 libidn.i386 libidn-devel.i386 libjpeg.i386 libmng.i386 libnotify.i386 libogg.i386 libogg-devel.i386 libpcap.i386 libpng.i386 libpng-devel.i386 libselinux.i386 libselinux-devel.i386 libselinux-python.i386 libselinux-utils.i386 libsemanage.i386 libsepol.i386 libsepol-devel.i386 libstdc++.i386 libstdc++-devel.i386 libsysfs.i386 libtermcap.i386 libtermcap-devel.i386 libtiff.i386 libtiff-devel.i386 libtool-ltdl.i386 libtool-ltdl-devel.i386 libusb.i386 libusb-devel.i386 libuser.i386 libutempter.i386 libvolume_id.i386 libvorbis.i386 libvorbis-devel.i386 libwnck.i386 libxkbfile.i386 libxml2.i386 libxml2-devel.i386 libxml2-python.i386 libxslt.i386 lm_sensors.i386 logrotate.i386 logwatch.noarch lsof.i386 lvm2.i386 m2crypto.i386 m4.i386 mailcap.noarch mailx.i386 make.i386 man.i386 man-pages.noarch mc.i386 mcstrans.i386 mdadm.i386 mesa-libGL.i386 mesa-libGL-devel.i386 metacity.i386 mgetty.i386 microcode_ctl.i386 mingetty.i386 mkbootdisk.i386 mkinitrd.i386 mkisofs.i386 mktemp.i386 mlocate.i386 mod_perl.i386 module-init-tools.i386 mtools.i386 mtr.i386 mysql.i386 mysql-devel.i386 mysql-server.i386 nano.i386 nas.i386 nash.i386 nc.i386 ncurses.i386 ncurses-devel.i386 neon.i386 net-snmp-libs.i386 net-tools.i386 newt.i386 newt-devel.i386 nmap.i386 notification-daemon.i386 notify-python.i386 nscd.i386 nspr.i386 nss.i386 nss-tools.i386 nss_db.i386 nss_ldap.i386 ntp.i386 ntsysv.i386 numactl.i386 oddjob.i386 oddjob-libs.i386 openjade.i386 openldap.i386 opensp.i386 openssh.i386 openssh-clients.i386 openssh-server.i386 openssl.i686 openssl-devel.i386 pam.i386 pam_ccreds.i386 pam_krb5.i386 pam_passwdqc.i386 pam_pkcs11.i386 pam_smb.i386 pango.i386 pango-devel.i386 paps.i386 parted.i386 passwd.i386 patch.i386 pax.i386 pciutils.i386 pcmciautils.i386 pcre.i386 pcsc-lite.i386 pcsc-lite-libs.i386 perl.i386 perl-BSD-Resource.i386 perl-Compress-Zlib.i386 perl-Convert-ASN1.noarch perl-DBD-mysql.i386 perl-DBI.i386 perl-DateManip.noarch perl-Digest-HMAC.noarch perl-Digest-SHA1.i386 perl-HTML-Parser.i386 perl-HTML-Tagset.noarch perl-Net-DNS.i386 perl-String-CRC32.i386 perl-URI.noarch perl-XML-Parser.i386 perl-libwww-perl.noarch perl-suidperl.i386 php.i386 php-cli.i386 php-common.i386 php-devel.i386 php-gd.i386 php-mbstring.i386 php-mysql.i386 php-pdo.i386 php-pear.noarch php-pear-DB.noarch piafdl.noarch piafxtras.noarch pinfo.i386 pirut.noarch pkgconfig.i386 pkinit-nss.i386 pm-utils.i386 policycoreutils.i386 popt.i386 portmap.i386 postgresql-libs.i386 ppp.i386 prelink.i386 procmail.i386 procps.i386 psacct.i386 psmisc.i386 pulseaudio-libs.i386 pycairo.i386 pygobject2.i386 pygtk2.i386 pygtk2-libglade.i386 pyorbit.i386 python.i386 python-elementtree.i386 python-iniparse.noarch python-numeric.i386 python-sqlite.i386 python-urlgrabber.noarch pyxf86config.i386 qt.i386 quota.i386 rdate.i386 rdist.i386 readahead.i386 readline.i386 redhat-artwork.i386 redhat-logos.noarch redhat-lsb.i386 redhat-menus.noarch redhat-rpm-config.noarch rhpl.i386 rhpxl.i386 rmt.i386 rng-utils.i386 rp-pppoe.i386 rpm.i386 rpm-build.i386 rpm-libs.i386 rpm-python.i386 rsh.i386 rsync.i386 samba.i386 screen.i386 scrollkeeper.i386 sed.i386 selinux-policy.noarch selinux-policy-targeted.noarch sendmail.i386 sendmail-cf.i386 setarch.i386 setup.noarch setuptool.i386 sgml-common.noarch sgpio.i386 shadow-utils.i386 shared-mime-info.i386 slang.i386 slang-devel.i386 smartmontools.i386 sos.noarch sox.i386 specspo.noarch sqlite.i386 startup-notification.i386 stunnel.i386 subversion.i386 sudo.i386 symlinks.i386 sysfsutils.i386 sysklogd.i386 syslinux.i386 system-config-date.noarch system-config-display.noarch system-config-keyboard.noarch system-config-language.noarch system-config-network.noarch system-config-network-tui.noarch system-config-securitylevel.i386 system-config-securitylevel-tui.i386 system-config-soundcard.noarch system-config-users.noarch talk.i386 tar.i386 tcl.i386 tcp_wrappers.i386 tcpdump.i386 tcsh.i386 telnet.i386 termcap.noarch tftp-server.i386 time.i386 tmpwatch.i386 traceroute.i386 tree.i386 ttmkfdir.i386 tzdata.i386 udev.i386 unix2dos.i386 unixODBC.i386 unzip.i386 usbutils.i386 usermode.i386 usermode-gtk.i386 util-linux.i386 vconfig.i386 vim-minimal.i386 vixie-cron.i386 vsftpd.i386 webmin.noarch wget.i386 which.i386 wireless-tools.i386 words.noarch wpa_supplicant.i386 xinetd.i386 xkeyboard-config.noarch xml-common.noarch xorg-x11-apps.i386 xorg-x11-drivers.i386 xorg-x11-drv-acecad.i386 xorg-x11-drv-aiptek.i386 xorg-x11-drv-apm.i386 xorg-x11-drv-ark.i386 xorg-x11-drv-ast.i386 xorg-x11-drv-ati.i386 xorg-x11-drv-calcomp.i386 xorg-x11-drv-chips.i386 xorg-x11-drv-cirrus.i386 xorg-x11-drv-citron.i386 xorg-x11-drv-cyrix.i386 xorg-x11-drv-digitaledge.i386 xorg-x11-drv-dmc.i386 xorg-x11-drv-dummy.i386 xorg-x11-drv-dynapro.i386 xorg-x11-drv-elo2300.i386 xorg-x11-drv-elographics.i386 xorg-x11-drv-evdev.i386 xorg-x11-drv-fbdev.i386 xorg-x11-drv-fpit.i386 xorg-x11-drv-glint.i386 xorg-x11-drv-hyperpen.i386 xorg-x11-drv-i128.i386 xorg-x11-drv-i740.i386 xorg-x11-drv-i810.i386 xorg-x11-drv-jamstudio.i386 xorg-x11-drv-joystick.i386 xorg-x11-drv-keyboard.i386 xorg-x11-drv-magellan.i386 xorg-x11-drv-magictouch.i386 xorg-x11-drv-mga.i386 xorg-x11-drv-microtouch.i386 xorg-x11-drv-mouse.i386 xorg-x11-drv-mutouch.i386 xorg-x11-drv-neomagic.i386 xorg-x11-drv-nsc.i386 xorg-x11-drv-nv.i386 xorg-x11-drv-palmax.i386 xorg-x11-drv-penmount.i386 xorg-x11-drv-rendition.i386 xorg-x11-drv-s3.i386 xorg-x11-drv-s3virge.i386 xorg-x11-drv-savage.i386 xorg-x11-drv-siliconmotion.i386 xorg-x11-drv-sis.i386 xorg-x11-drv-sisusb.i386 xorg-x11-drv-spaceorb.i386 xorg-x11-drv-summa.i386 xorg-x11-drv-tdfx.i386 xorg-x11-drv-tek4957.i386 xorg-x11-drv-trident.i386 xorg-x11-drv-tseng.i386 xorg-x11-drv-ur98.i386 xorg-x11-drv-v4l.i386 xorg-x11-drv-vesa.i386 xorg-x11-drv-vga.i386 xorg-x11-drv-via.i386 xorg-x11-drv-vmmouse.i386 xorg-x11-drv-vmware.i386 xorg-x11-drv-void.i386 xorg-x11-drv-voodoo.i386 xorg-x11-filesystem.noarch xorg-x11-font-utils.i386 xorg-x11-fonts-ISO8859-1-75dpi.noarch xorg-x11-fonts-Type1.noarch xorg-x11-fonts-base.noarch xorg-x11-proto-devel.i386 xorg-x11-server-Xorg.i386 xorg-x11-server-utils.i386 xorg-x11-utils.i386 xorg-x11-xauth.i386 xorg-x11-xfs.i386 xorg-x11-xinit.i386 xorg-x11-xkb-utils.i386 xsri.i386 xulrunner.i386 yelp.i386 yp-tools.i386 ypbind.i386 yum.noarch yum-fastestmirror.noarch yum-metadata-parser.i386 yum-updatesd.noarch zip.i386 zlib.i386 zlib-devel.i386
fi

#Update it
yum -y update

#Make the ISO look like a PiaF, but don't start the install on reboot

mkdir -p /etc/pbx
date --iso-8601=minutes > /etc/pbx/install-date
echo "ISO=$PIAFVERS" > /etc/pbx/ISO-Version
echo "method=pbx=$PIAFVERS ks - from existing CentOS install" > /etc/pbx/install-method


#Note this step does not work on OpenVZ as we cannot mount - consider an update using fuseiso.
#Alternatively, PiaF dev team could put these files up for download, and adjust this script"
clear
echo "================================================================================"
echo "This next step will download the PiaF ISO and install"
echo "the dependencies that are included on the ISO but"
echo "but are not available in the CentOS repository."
echo "================================================================================"
echo "If this is an OpenVZ (e.g. Proxmox install) then the"
echo "following steps will fail, and you will have to install the"
echo "following pachages manually from your copy of the ISO in the "
echo "/pbx directory of the PIAF ISO."
echo ""
echo "================================================================================"
echo "The packages to upload and install are:-"
echo "flite flite-devel jack-audio-connection-kit nas piafdl piafxtras pulseaudio-libs webmin pfmon"
echo "================================================================================"
echo "NB. you can exit now, and install the above manually and save some bandwidth,"
echo "================================================================================"
echo "After reboot execute piafdl"
echo "Press CTRL C to exit or enter to continue"
read TEMP
clear


#Download appropriate ISO. 
cd /tmp

rm -rf pbxinaflash*.iso

if [ $KERNELARCH = "x86_64" ]; then
	wget $PIAFLOC64
else
	wget $PIAFLOC32
fi

#Mount it
mkdir /mnt/piaf
mount -o loop /tmp/pbxinaflash*.iso /mnt/piaf/

#Install the dependencies
cd /mnt/piaf/pbx/
yum --nogpgcheck --skip-broken localinstall flite-1*.rpm flite-devel*.rpm jack-audio-connection-kit*.rpm nas*.rpm piafdl*.rpm piafxtras*.rpm pulseaudio-libs*.rpm webmin*.rpm

#Don't install automatically, because you won't see the screen!
#echo "/usr/local/sbin/piafdl" >> /etc/rc.d/rc3.d/S99local 

#now clean up

cd ~
umount /mnt/piaf/
rm -rf /mnt/pbx/
rm -rf /tmp/pbxinaflash*.iso

#May as well check we have an up-to-date system, again.
yum -y update

#Now put in the piaf-extras menu
cp -f /usr/src/piafxtras/preinstallmenu/piafxtras-menu /usr/local/sbin/piafxtras-menu
chmod +x /usr/local/sbin/piafxtras-menu
cat /usr/src/piafxtras/preinstallmenu/motd.tmp >/etc/motd

echo ""
echo ""
echo ""
echo "Reboot the server, then type piafdl to continue the installation."
echo "Press CTRL C to exit or enter to reboot"
read TEMP

reboot
