dmesg --clear
sudo rmmod fw.ko
sudo insmod fw.ko
chmod 666 /dev/fw_log

