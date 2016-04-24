
#ifndef CHARDEV_LOGS_H_
#define CHARDEV_LOGS_H_

#include "fw.h"
#include "linux/list.h"

/*
 * The size of each field in the log entry when printing it.
 */
#define SIZE_OF_LOG_FIELD_BUFFER 20
#define NUMBER_OF_FIELDS_TO_PRINT_IN_EACH_LOG 10
#define LOG_SIZE_AS_STRING SIZE_OF_LOG_FIELD_BUFFER * NUMBER_OF_FIELDS_TO_PRINT_IN_EACH_LOG

extern int logs_size;

/***************************************************************************************************
 * List handling methods.
 **************************************************************************************************/

void add_log(unsigned long timestamp, unsigned char protocol, unsigned char action,
    unsigned char hooknum, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port,
    reason_t reason);

void clear_logs_list(void);

void get_logs(char *buff);

int get_logs_size(void);

void init_logs_list(void);


/***************************************************************************************************
 * Driver file operations.
 **************************************************************************************************/

/*
 * Our custom open function  for file_operations. Each time we open the device we initializing the
 * changing variables (so we will be able to read it again and again).
 *
 * In this implementation we prepare the buffer that should be send to the user.
 */
int open_log_device(struct inode *_inode, struct file *_file);

/*
 * Implementation for the read method of file_operations.
 */
ssize_t read_logs(struct file *filp, char *buff, size_t length, loff_t *offp);


int release_log_device(struct inode *inode, struct file *file);

/***************************************************************************************************
 * Driver sysfs ops.
 **************************************************************************************************/

/*
 * Sysfs show logs size implementation.
 */
ssize_t sysfs_show_logs_size(struct device *dev,struct device_attribute *attr, char *buf);


/*
 * Sysfs clear logs implementation.
 */
ssize_t sysfs_clear_logs(
    struct device *dev, struct device_attribute *attr, const char *buf, size_t count);


/***************************************************************************************************
 * Registration methods
 **************************************************************************************************/


int register_logs_driver(struct class* fw_sysfs_class);

int remove_logs_device(struct class* fw_sysfs_class);

#endif /* CHARDEV_LOGS_H_ */
