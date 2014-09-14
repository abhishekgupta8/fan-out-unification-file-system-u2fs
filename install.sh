#!/bin/sh
set -x
lsmod
umount /mnt/warpfs
rmmod u2fs.ko
insmod u2fs.ko
mount -t u2fs fug /mnt/wrapfs
lsmod
