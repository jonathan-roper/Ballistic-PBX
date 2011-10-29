#!/bin/bash
#Install Westany prompts on Asterisk
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




#change this line to suit the location of your prompts.
EXTRACTDIR=/tmp/prompts

#Change the defaults below to suit your install
ASTDIR=/var/lib/asterisk
ASTERISKUSER=asterisk
ASTERISKGROUP=asterisk

TEMPDIR=/tmp/westany-prompts-xyz
FILES=*.tar.gz


cd $EXTRACTDIR
mkdir $TEMPDIR

for f in $FILES
do 
	echo "First extract of $f file..."
	tar zxfv "$f"
	mv "$f" $TEMPDIR
done
	
for f in $FILES
do
	echo "Second extract of $f file..."
	tar zxfv "$f"
	rm "$f"
done


for d in $(find $EXTRACTDIR -name 'sounds.tar.gz')
do
	echo "Move $d to asterisk directory and extract it"
	mv $d $ASTDIR/sounds.tar.gz
	cd $ASTDIR
	ls -al sounds.tar.gz
	tar zxfv sounds.tar.gz
	rm $ASTDIR/sounds.tar.gz
done

#Put everything back and clean up
rm -rf $EXTRACTDIR/*
mv  $TEMPDIR/* $EXTRACTDIR
rm -rf $TEMPDIR
chown -R $ASTERISKUSER:$ASTERISKGROUP $ASTDIR/sounds/
