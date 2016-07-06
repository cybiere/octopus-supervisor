#!/bin/sh
#?Service Status

if [ `service > /dev/null 2>&1; echo $?` -eq 1 ]; then
	service $1 status
else
	systemctl status $1
fi
