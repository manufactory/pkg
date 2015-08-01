#!/bin/sh

# Debian Archive Automatic Signing Key (7.0/wheezy) <ftpmaster@debian.org>
# Debian Archive Automatic Signing Key (8/jessie) <ftpmaster@debian.org>
# Jessie Stable Release Key <debian-release@lists.debian.org>
keys="46925553 2B90D010 518E17E1"

trusted_key_dir="/usr/share/keys/pkg/trusted"
keyring="$trusted_key_dir/Debian-keyring"


# Warning: if no slash is in keyring path, gpg will look in the users' home 
#          directory   
gpg_args="--keyserver 85.10.205.199 --no-default-keyring --keyring=$keyring --recv-key $keys"

# --keyserver keys.gnupg.net should work fine too, but not inside my
#	universities shitty network setting.

gpg_bin=""

if [ -e `which gpg2` ] ; then
	gpg_bin=`which gpg2`
elif [ -e `which gpg`] ; then
	gpg_bin=`which gpg`
else
	echo "No version of gnupg found."
	echo "Please install security/gnupg."
	exit 1
fi

$gpg_bin $gpg_args

if [ $? -ne 0 ]; then
	echo "Something went wrong with fetching the keys."
	exit 2
fi
