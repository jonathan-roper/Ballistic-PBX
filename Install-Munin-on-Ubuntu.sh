#!/bin/bash

#install Munin for server monitoring 
apt-get -y install munin munin-node munin-plugins-extra libnet-netmask-perl libnet-telnet-perl python perl libcache-cache-perl


ln -s /usr/share/munin/plugins/mysql_bytes  /etc/munin/plugins/mysql_bytes
ln -s /usr/share/munin/plugins/mysql_innodb  /etc/munin/plugins/mysql_innodb
ln -s /usr/share/munin/plugins/mysql_queries /etc/munin/plugins/mysql_queries
ln -s /usr/share/munin/plugins/mysql_slowqueries /etc/munin/plugins/mysql_slowqueries
ln -s /usr/share/munin/plugins/mysql_threads /etc/munin/plugins/mysql_threads


echo '
Alias /munin /var/cache/munin/www

<Directory /var/cache/munin/www>
	DirectoryIndex index.html

	Options +FollowSymLinks
	AllowOverride None

	#order deny,allow
	#deny from all
	#allow from 127.0.0.0/255.0.0.0 ::1/128
	allow from all

	<IfModule mod_php5.c>
	  php_flag magic_quotes_gpc Off
	  php_flag track_vars On
	  php_flag register_globals Off
	</IfModule>
	
	<IfModule mod_expires.c>
        ExpiresActive On
        ExpiresDefault M310
    </IfModule>


	AuthUserFile /etc/apache2/htpassword/.htpasswd_munin
	AuthGroupFile /dev/null
	AuthName "Password Protected Area"
	AuthType Basic

	<limit GET POST>
		    require valid-user
	</limit>

</Directory>
' > /etc/munin/apache.conf

mkdir /etc/apache2/htpassword/
echo "Please enter the password you want to use for the admin interface, the username is admin"
htpasswd -c /etc/apache2/htpassword/.htpasswd_munin admin


service munin-node restart
service apache2 restart

#funcmunin
