freenas-firewall
================

A script to block unauthorized access attempts to a freenas box. At this moment it generates a shell script that can be run as root.

To use it simply run it as root on your freenas box.

Example:

./generate_ipfw.sh > fw.sh

./fw.sh

Afterwards you can use "ipfw -q list" to verify the firewall.
