
#include <linux/string.h>
//#include <linux/list.h>

#include "fw.h"

char *RULES_DEVICE_NAME = "fw_rules";

static unsigned short number_of_rules;
static rule_t rules_table[MAX_RULES];

static int PORT_1023 = 1023; // All ports greater than 1023 should be treated equally.
static int PORT_ANY_NUMBER = 1025;

int firewall_rule_checking_status;
#define STATUS_NOT_ACTIVE (0)
#define STATUS_ACTIVE (1)

static int IP_ANY = 0;

int rules_device_major_number;
struct device* rules_device_sysfs_device = NULL;
struct file_operations rules_device_fops = {
  .owner = THIS_MODULE
};


/***************************************************************************************************
 * Functions for sysfs attributes
 **************************************************************************************************/


ssize_t get_rules(struct device *dev,struct device_attribute *attr, char *buf) {
  rule_t rule;
  int i;
  char output_string_rule[80];
  buf[0] = 0;
  for (i=0; i < number_of_rules; i++){
    rule = rules_table[i];
    scnprintf(output_string_rule, 80, "%s %u %u %u %u %u %u %u %u %u %u\n",
        rule.rule_name,
        rule.direction,
        rule.src_ip,
        rule.src_prefix_size,
        rule.dst_ip,
        rule.dst_prefix_size,
        rule.protocol,
        rule.src_port,
        rule.dst_port,
        rule.ack,
        rule.action);
    strcat(buf, output_string_rule);
  }
  return strlen(buf);
}


/*
 * Sysfs store implementation.
 * Sets the rules that are used by the sateless firewall.
 */
ssize_t set_rules(
    struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {

  rule_t output_rule;
  int status;
  char *input_string_rule;
  char *input = (char *) buf;

  unsigned int src_prefix_size;
  unsigned int dst_prefix_size;
  unsigned int protocol;
  unsigned int action;

  number_of_rules = 0;
  while (strlen(input_string_rule = strsep(&input, "\n")) > 0) {
    if (number_of_rules > MAX_RULES) {
      number_of_rules = 0;
      return EINVAL;
    }
    // Only for debugging remove scanf.
    status = sscanf(input_string_rule, "%19s %u %u %u %u %u %u %hu %hu %u %u",
        output_rule.rule_name,
        &output_rule.direction,
        &output_rule.src_ip,
        &src_prefix_size,
        &output_rule.dst_ip,
        &dst_prefix_size,
        &protocol,
        &output_rule.src_port,
        &output_rule.dst_port,
        &output_rule.ack,
        &action);

    output_rule.src_prefix_size = (char) src_prefix_size;
    output_rule.dst_prefix_size = (char) dst_prefix_size;
    output_rule.protocol = (char) protocol;
    output_rule.action = (char) action;

    printk(KERN_INFO "input_string_rule: %s\n", input_string_rule);
    printk(KERN_INFO "output_rule.protocol: %u\n", output_rule.protocol);
    printk(KERN_INFO "status: %d\n", status);
    if (status < NUMBER_OF_FIELDS_IN_RULE) {
      number_of_rules = 0;
      return EINVAL;
    } else{
      rules_table[number_of_rules] = output_rule;
      number_of_rules++;
    }
  }
  printk(KERN_INFO "Done loading rules.");
  return 1;
}

static DEVICE_ATTR(rules_load_store, S_IRWXO , get_rules, set_rules);


/*
 * Sysfs show rules size implementation.
 */
ssize_t show_rules_size(struct device *dev,struct device_attribute *attr, char *buf) {
  return scnprintf(buf, sizeof(int), "%d\n", number_of_rules);
}
/*
 * Register attribute for display size.
 * TODO: verify that NULL is appropriate.
 */
static DEVICE_ATTR(rules_size, S_IROTH, show_rules_size, NULL);


/*
 * Displays the firewall status.
 */
ssize_t show_rules_checking_status(struct device *dev,struct device_attribute *attr, char *buf) {
  return scnprintf(buf, sizeof(int), "%u\n", firewall_rule_checking_status);
}

/*
 * Sysfs activate/deactivate rules function.
 */
ssize_t activate_rules_checking(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
  unsigned int action;
  int returnValue;
  printk(KERN_INFO " ------------ In activate.\n.");
  if((returnValue = sscanf(buf, "%u", &action)) == 1) {
    if (action == STATUS_NOT_ACTIVE || action == STATUS_ACTIVE) {
      printk(KERN_INFO " ------------ changing status.\n.");
      firewall_rule_checking_status = action;
      return strnlen(buf, count);
    }
    else {
      return EINVAL;
    }
  }
  printk(KERN_INFO " ------------ Done.\n.");
  return returnValue;
}

/*
 * Register attribute for firewall activation.
 * TODO: verify that NULL is appropriate.
 */
static DEVICE_ATTR(active, S_IRWXO, show_rules_checking_status, activate_rules_checking);


/***************************************************************************************************
 * Registration methods
 **************************************************************************************************/


int register_rules_driver(struct class* fw_sysfs_class) {
  // Create char device. fops is empty because we are using sysfs.
  rules_device_major_number = register_chrdev(0, RULES_DEVICE_NAME, &rules_device_fops);
  if(rules_device_major_number < 0) {
    printk(KERN_INFO "Failed to register rules device.\n.");
    return -1;
  }

  // Create sysfs device.
  rules_device_sysfs_device = device_create(
          fw_sysfs_class, NULL, MKDEV(rules_device_major_number, 0), NULL, RULES_DEVICE_NAME);
  if(IS_ERR(rules_device_sysfs_device)) {
    unregister_chrdev(rules_device_major_number, RULES_DEVICE_NAME);
    printk(KERN_INFO "Failed to create rules device.\n.");
    return -1;
  }

  // Create sysfs file attributes .
  if(device_create_file(rules_device_sysfs_device,
      (const struct device_attribute*) &dev_attr_rules_load_store.attr)) {
    device_destroy(fw_sysfs_class, MKDEV(rules_device_major_number, 0));
    unregister_chrdev(rules_device_major_number, RULES_DEVICE_NAME);
    printk(KERN_INFO "Failed to create rules load store attribute.\n.");
    return -1;
  }

  // Create sysfs file attributes .
  if(device_create_file(rules_device_sysfs_device,
      (const struct device_attribute*) &dev_attr_rules_size.attr)) {
    device_remove_file(rules_device_sysfs_device,
        (const struct device_attribute *)&dev_attr_rules_load_store.attr);
    device_destroy(fw_sysfs_class, MKDEV(rules_device_major_number, 0));
    unregister_chrdev(rules_device_major_number, RULES_DEVICE_NAME);
    printk(KERN_INFO "Failed to create rules size attribute.\n.");
    return -1;
  }

  // Create sysfs file attributes .
  if(device_create_file(rules_device_sysfs_device,
      (const struct device_attribute*) &dev_attr_active.attr)) {
    device_remove_file(
        rules_device_sysfs_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
    device_remove_file(rules_device_sysfs_device,
        (const struct device_attribute *)&dev_attr_rules_load_store.attr);
    device_destroy(fw_sysfs_class, MKDEV(rules_device_major_number, 0));
    unregister_chrdev(rules_device_major_number, RULES_DEVICE_NAME);
    printk(KERN_INFO "Failed to create rules size attribute.\n.");
    return -1;
  }
  return 0;
}

int remove_rules_device(struct class* fw_sysfs_class) {
  device_remove_file(
      rules_device_sysfs_device, (const struct device_attribute *)&dev_attr_active.attr);
  device_remove_file(
      rules_device_sysfs_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
  device_remove_file(
      rules_device_sysfs_device, (const struct device_attribute *)&dev_attr_rules_load_store.attr);
  device_destroy(fw_sysfs_class, MKDEV(rules_device_major_number, 0));
  unregister_chrdev(rules_device_major_number, RULES_DEVICE_NAME);
  return 0;
}

