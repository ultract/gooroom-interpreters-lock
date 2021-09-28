#!/bin/bash

set -e

make clean
make 
sleep 2

if `lsmod | grep -q "gooroom_interp_lock"`; 
then
	sudo rmmod gooroom_interp_lock;
fi

sudo insmod gooroom_interp_lock.ko 
sudo dmesg --follow
