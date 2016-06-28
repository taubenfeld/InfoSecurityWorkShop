
#ifndef CHARDEV_RULES_H_
#define CHARDEV_RULES_H_

#include <linux/string.h>
#include "fw.h"

#define NUMBER_OF_FIELDS_IN_RULE (11)
#define STATUS_NOT_ACTIVE (0)
#define STATUS_ACTIVE (1)

extern int firewall_rule_checking_status;
extern unsigned short number_of_rules;
extern rule_t rules_table[MAX_RULES];

/***************************************************************************************************
 * Functions for sysfs attributes
 **************************************************************************************************/


ssize_t get_rules(struct device *dev,struct device_attribute *attr, char *buf);

/*
 * Sysfs store implementation.
 * Sets the rules that are used by the sateless firewall.
 */
ssize_t set_rules(
    struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

/*
 * Sysfs show rules size implementation.
 */
ssize_t show_rules_size(struct device *dev,struct device_attribute *attr, char *buf);

/*
 * Displays the firewall status.
 */
ssize_t show_rules_checking_status(struct device *dev,struct device_attribute *attr, char *buf);

/*
 * Sysfs activate/deactivate rules function.
 */
ssize_t activate_rules_checking(
    struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

/***************************************************************************************************
 * Registration methods
 **************************************************************************************************/


int register_rules_driver(struct class* fw_sysfs_class);


int remove_rules_device(struct class* fw_sysfs_class);

#endif /* CHARDEV_RULES_H_ */
