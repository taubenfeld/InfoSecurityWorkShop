
#include "chardev_logs.h"

int logs_device_major_number;
struct device* logs_device_sysfs_device = NULL;

log_row_t logs_list;
int logs_size = 0;

/*
 * Variables that uses for the read operation.
 */
char *read_buffer;
int remaining_number_of_bytes_to_read;
char *pointer_to_current_location_in_read_buffer;

/***************************************************************************************************
 * List handling methods.
 **************************************************************************************************/

void add_log(unsigned long timestamp, unsigned char protocol, unsigned char action,
    unsigned char hooknum, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port,
    reason_t reason) {
  log_row_t *cur_entry;
  log_row_t *new;

  // Check if this log already exists.
  list_for_each_entry(cur_entry, &(logs_list.list), list) {
    if (cur_entry->protocol == protocol
        && cur_entry->action == action
        && cur_entry->hooknum == hooknum
        && cur_entry->src_ip == src_ip
        && cur_entry->dst_ip == dst_ip
        && cur_entry->src_port == src_port
        && cur_entry->dst_port == dst_port
        && cur_entry->reason == reason) {
      // We found an equal log, increment its count field.
      cur_entry->count++;
      return;
    }
  }

  // The log doesn't exists in the list. Create a new node.
  // Note that it is important to use GFP_ATOMIC due to concurrency considerations.
  new = kmalloc(sizeof(log_row_t), GFP_ATOMIC);
  if (new == NULL) {
    printk(KERN_INFO "ERROR: Failed to allocate space for new log. Not adding the current log.\n");
    return;
  }

  INIT_LIST_HEAD(&(new->list));
  new->timestamp = timestamp;
  new->protocol = protocol;
  new->action = action;
  new->hooknum = hooknum;
  new->src_ip = src_ip;
  new->dst_ip = dst_ip;
  new->src_port = src_port;
  new->dst_port = dst_port;
  new->reason = reason;
  new->count = 1;
  list_add_tail(&(new->list), &logs_list.list);
  logs_size++;
}

void clear_logs_list(void) {
  log_row_t *cur_entry, *temp;
  if (list_empty(&(logs_list.list))) { // List is empty nothing to do.
    return;
  }
  list_for_each_entry_safe(cur_entry, temp, &(logs_list.list), list) {
    list_del(&(cur_entry->list));
    kfree(cur_entry);
  }
  logs_size = 0;
}

void get_logs(char *buff) {
  log_row_t *cur_entry;
  char temp_str_log[LOG_SIZE_AS_STRING + 1] = {0};

  // Start to read from where we stopped last time (cur_entry_in_read).
  // Use this to align printing. Currently the align parsing is done only in userspace.
  // "%-19.lu %-19.u %-19.u %-19.u %-19.u %-19.u %-19.u %-19.u %-19.d %-19.u\n",
  list_for_each_entry(cur_entry, &(logs_list.list), list) {
    scnprintf(temp_str_log, LOG_SIZE_AS_STRING + 1,
        "%lu %u %u %u %u %u %u %u %d %u\n",
        cur_entry->timestamp,
        cur_entry->protocol,
        cur_entry->action,
        cur_entry->hooknum,
        cur_entry->src_ip,
        cur_entry->dst_ip,
        cur_entry->src_port,
        cur_entry->dst_port,
        cur_entry->reason,
        cur_entry->count);
    strcat(buff, temp_str_log);
  }
}
int get_logs_size(void) {
  return logs_size;
}

void init_logs_list(void) {
  INIT_LIST_HEAD(&logs_list.list);
  logs_size = 0;
}

/***************************************************************************************************
 * Driver file operations.
 **************************************************************************************************/

/*
 * Our custom open function  for file_operations. Each time we open the device we initializing the
 * changing variables (so we will be able to read it again and again).
 *
 * In this implementation we prepare the buffer that should be send to the user.
 */
int open_log_device(struct inode *_inode, struct file *_file) {

  remaining_number_of_bytes_to_read =
      (get_logs_size() + 1) * LOG_SIZE_AS_STRING + 1;

  // Prepare all the logs that should be written.
  read_buffer = kcalloc(remaining_number_of_bytes_to_read, 1, GFP_KERNEL);
  if (read_buffer == NULL) {
    return -1;
  }
  pointer_to_current_location_in_read_buffer = read_buffer;

  // Fill the buffer with the logs.
  get_logs(read_buffer);

  return 0;
}

/*
 * Implementation for the read method of file_operations.
 */
ssize_t read_logs(struct file *filp, char *buff, size_t length, loff_t *offp) {
  ssize_t bytes_to_write_in_the_current_iteration =
      (remaining_number_of_bytes_to_read < length) ? remaining_number_of_bytes_to_read : length;

  // If nothing left to write return.
  if (bytes_to_write_in_the_current_iteration == 0) {
    return 0;
  }

  // Send the data to the user through 'copy_to_user'
  if (copy_to_user(
      buff, pointer_to_current_location_in_read_buffer, bytes_to_write_in_the_current_iteration)) {
    kfree(read_buffer);
    return -EFAULT;
  } else {
    // function succeeded, we just sent the user 'num_of_bytes' bytes, so we updating the counter
    // and the string pointer index.
    remaining_number_of_bytes_to_read -= bytes_to_write_in_the_current_iteration;
    pointer_to_current_location_in_read_buffer += bytes_to_write_in_the_current_iteration;
    return bytes_to_write_in_the_current_iteration;
  }
}

int release_log_device(struct inode *inode, struct file *file) {
  kfree(read_buffer);
  return 0;
}

/*
 * File operations for log device.
 */
static struct file_operations logs_device_fops = {
  .owner = THIS_MODULE,
  .open = open_log_device,
  .read = read_logs,
  .release = release_log_device
};

/***************************************************************************************************
 * Driver sysfs ops.
 **************************************************************************************************/

/*
 * Sysfs show logs size implementation.
 */
ssize_t sysfs_show_logs_size(struct device *dev,struct device_attribute *attr, char *buf) {
  return scnprintf(buf, sizeof(int) + 1 , "%d\n", get_logs_size());
}
/*
 * Register attribute for display size.
 */
static DEVICE_ATTR(log_size, S_IROTH, sysfs_show_logs_size, NULL);


/*
 * Sysfs clear logs implementation.
 */
ssize_t sysfs_clear_logs(
    struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
  char c;
  int returnValue;
  if((returnValue = sscanf(buf, "%c", &c)) == 1) {
    clear_logs_list();
  }
  printk(KERN_INFO "Done clearing log\n");
  return returnValue;
}

/*
 * Register ops.
 */
static DEVICE_ATTR(log_clear, S_IWOTH , NULL, sysfs_clear_logs);


/***************************************************************************************************
 * Registration methods
 **************************************************************************************************/


int register_logs_driver(struct class* fw_sysfs_class) {
  logs_device_major_number = register_chrdev(0, DEVICE_NAME_LOG, &logs_device_fops);
  if(logs_device_major_number < 0) {
    return -1;
  }

  // Create sysfs device.
  logs_device_sysfs_device = device_create(
      fw_sysfs_class, NULL, MKDEV(logs_device_major_number, 0), NULL, DEVICE_NAME_LOG);
  if(IS_ERR(logs_device_sysfs_device)) {
    unregister_chrdev(logs_device_major_number, DEVICE_NAME_LOG);
    return -1;
  }

  // Create sysfs show size attribute.
  if(device_create_file(logs_device_sysfs_device,
      (const struct device_attribute*) &dev_attr_log_size.attr)) {
    device_destroy(fw_sysfs_class, MKDEV(logs_device_major_number, 0));
    unregister_chrdev(logs_device_major_number, DEVICE_NAME_LOG);
    return -1;
  }

  // Create sysfs clear logs attribute.
  if(device_create_file(logs_device_sysfs_device,
      (const struct device_attribute*) &dev_attr_log_clear.attr)) {
    device_remove_file(
        logs_device_sysfs_device, (const struct device_attribute *)&dev_attr_log_size.attr);
    device_destroy(fw_sysfs_class, MKDEV(logs_device_major_number, 0));
    unregister_chrdev(logs_device_major_number, DEVICE_NAME_LOG);
    return -1;
  }

  init_logs_list();
  return 0;
}

int remove_logs_device(struct class* fw_sysfs_class) {
  clear_logs_list();
  device_remove_file(
      logs_device_sysfs_device, (const struct device_attribute *)&dev_attr_log_clear.attr);
  device_remove_file(
      logs_device_sysfs_device, (const struct device_attribute *)&dev_attr_log_size.attr);
  device_destroy(fw_sysfs_class, MKDEV(logs_device_major_number, 0));
  unregister_chrdev(logs_device_major_number, DEVICE_NAME_LOG);
  return 0;
}


