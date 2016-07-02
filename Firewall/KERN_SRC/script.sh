make
dmesg --clear
rmmod firewall.ko
insmod firewall.ko
chmod 777 /dev/conn_tab
chmod 777 /dev/fw_log