
obj-m		:= firewall.o 
firewall-objs 	+= fw_module.o chardev_logs.o chardev_info.o chardev_rules.o packets_handeling.o stateful.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean 