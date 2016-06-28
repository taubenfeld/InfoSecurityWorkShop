
#ifndef CHARDEV_INFO_H_
#define CHARDEV_INFO_H_

#include "fw.h"

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * The basic device that we wrote on EX2. Might remove this later on.
 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/

#define INFO_DEVICE_NAME "fw_info"

extern int number_of_passed_packets;
extern int number_of_blocked_packets;


/***************************************************************************************************
 * Driver sysfs ops.
 **************************************************************************************************/

/*
 * Sysfs show implementation.
 * Returns a message that specifies the number of passed/blocked packets.
 */
ssize_t show(struct device *dev,struct device_attribute *attr, char *buf);

/*
 * Sysfs store implementation.
 * For now this implementation just resets the counters.
 */
ssize_t store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);


/***************************************************************************************************
 * Registration methods
 **************************************************************************************************/


int register_info_driver(struct class* fw_sysfs_class);

int remove_info_device(struct class* fw_sysfs_class);


#endif /* CHARDEV_INFO_H_ */
