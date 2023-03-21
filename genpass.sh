#!/bin/bash -ex

salt=`openssl rand -hex 4`
echo -n "user: "
read user
echo -n "password: "
read pass

sha=`echo -n "${salt}${pass}" | openssl dgst -sha1 -binary | openssl base64`

sqlite3 luamud.sqlite "update mud_auth set password = \"$sha\", password_salt = \"$salt\""

echo "user $user updated."
