#include "stateful.h"

int connections_device_major_number;
struct device* connections_sysfs_device = NULL;

/**
 * Variable that uses for the connections list.
 */
connections_list_entry connections_list;
int connections_list_size = 0;
char *connections_read_buffer;
int remaining_num_of_bytes_to_read;
char *pointer_to_current_location_in_connections_read_buffer;

/**
 * Variables for the hosts list.
 */
hosts_list_entry hosts_list;

/**
 * Variables for the FTP connections list.
 * This list holds all the connections that are open for FTP data connection.
 */
connections_list_entry ftp_connections_list;

/***************************************************************************************************
 * Private methods.
 **************************************************************************************************/

/*
 * Uses just for debugging.
 */
int count_connections(struct list_head *head) {
  connections_list_entry *cur_entry;
  int i = 0;
  list_for_each_entry(cur_entry, head, list) {
    i++;
  }
  return i;
}

/**
 * Adding a new connection with the given arguments. It is assumed that the caller already checked
 * that this is a valid connection.
 */
int add_connection(struct list_head *head,
    __be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, __u16 fragment) {
  connections_list_entry *new;
  struct timeval time;
  do_gettimeofday(&time);

  // Note that it is important to use GFP_ATOMIC due to concurrency considerations.
  new = kmalloc(sizeof(connections_list_entry), GFP_ATOMIC);
  if (new == NULL) {
    printk(KERN_INFO "ERROR: Failed to allocate space for new connection."
        " Not adding the current connection.\n");
    return -1;
  }
  INIT_LIST_HEAD(&(new->list));
  new->timestamp = time.tv_sec;
  new->src_ip = src_ip;
  new->dst_ip = dst_ip;
  new->src_port = src_port;
  new->dst_port = dst_port;
  new->fragment = fragment;
  new->tcp_state = SENT_SYN_WAIT_SYNACK;

  // Determine protocol.
  if (src_port == FTP_PORT || dst_port == FTP_PORT) {
    new->protocol = FTP;
  } else if (src_port == HTTP_PORT || dst_port == HTTP_PORT) {
    new->protocol = HTTP;
  } else {
    new->protocol = OTHER;
  }
  list_add_tail(&(new->list), head);

  printk(KERN_INFO "Done adding connection: src port[%u], dst port[%u]\n",  src_port, dst_port);
  printk(KERN_INFO "Current list size [%u]\n",  count_connections(head));
  return 1;
}

int remove_connection(struct list_head *head, connections_list_entry *entry) {
  if (list_empty(head)) { // List is empty nothing to do.
    return 0;
  }
  list_del(&(entry->list));
  kfree(entry);
  return 1;
}

connections_list_entry *find_connection(struct list_head *head,
    __be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port) {
  connections_list_entry *cur_entry;
  list_for_each_entry(cur_entry, head, list) {
    if ((cur_entry->src_ip == src_ip && cur_entry->src_port == src_port
        && cur_entry->dst_ip == dst_ip && cur_entry->dst_port == dst_port) ||
        (cur_entry->src_ip == dst_ip && cur_entry->src_port == dst_port
        && cur_entry->dst_ip == src_ip && cur_entry->dst_port == src_port)) {
      return cur_entry;
    }
  }
//  printk(KERN_INFO "Didn't find anything.");
  return NULL;
}

void get_connections_as_string(char *buff, int size) {
  connections_list_entry *cur_entry;
  char temp_str_connection[ROW_SIZE_AS_STRING + 1] = {0};
  int cursize = 0;

  list_for_each_entry(cur_entry, &(connections_list.list), list) {
    cursize += scnprintf(temp_str_connection, ROW_SIZE_AS_STRING + 1,
        "%u %u %u %u %u %u %u %lu\n",
        cur_entry->src_ip,
        cur_entry->src_port,
        cur_entry->dst_ip,
        cur_entry->dst_port,
        cur_entry->protocol,
        cur_entry->tcp_state,
        cur_entry->protocol_state,
        cur_entry->timestamp);
    if (cursize >= size) {
      return; // Can reach here only because of multi threading issues.
    }
    strcat(buff, temp_str_connection);
  }
}

void clear_list_connections(struct list_head *head) {
  connections_list_entry *cur_entry, *temp;
  if (list_empty(head)) { // List is empty nothing to do.
    return;
  }
  list_for_each_entry_safe(cur_entry, temp, head, list) {
    list_del(&(cur_entry->list));
    kfree(cur_entry);
  }
  connections_list_size = 0;
}

void add_host(char *name) {
  hosts_list_entry *new;
  int name_length = strlen(name);
  if (name_length < 2) {
    return;
  }

  // Note that it is important to use GFP_ATOMIC due to concurrency considerations.
  new = kmalloc(sizeof(hosts_list_entry), GFP_ATOMIC);
  if (new == NULL) {
    printk(KERN_INFO "ERROR: Failed to allocate space for new host. Not adding current host.\n");
    return;
  }
  new->host_name = kmalloc(name_length + 1, GFP_ATOMIC);
  if (new->host_name == NULL) {
    kfree(new);
    printk(KERN_INFO "ERROR: Failed to allocate space for host name. Not adding current host.\n");
    return;
  }
  (new->host_name)[0] = 0;
  strcat(new->host_name, name);

  INIT_LIST_HEAD(&(new->list));
  list_add_tail(&(new->list), &hosts_list.list);
}

void clear_list_hosts(void) {
  hosts_list_entry *cur_entry, *temp;
  struct list_head *head = &(hosts_list.list);
  if (list_empty(head)) { // List is empty nothing to do.
    return;
  }
  list_for_each_entry_safe(cur_entry, temp, head, list) {
    list_del(&(cur_entry->list));
    kfree(cur_entry->host_name);
    kfree(cur_entry);
  }
}

int is_timeout_expired(connections_list_entry *connection) {
  struct timeval time;
  do_gettimeofday(&time);
  return (time.tv_sec - connection->timestamp) > 25;
}

char *extract_payload(struct sk_buff *skb, struct tcphdr *tcph) {
  char *extracted_payload;
  unsigned char *skb_data_pointer = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));
  int data_length = skb->tail - skb_data_pointer + skb->data_len;

  extracted_payload = kcalloc(data_length + 1, sizeof(char) ,GFP_ATOMIC);
  skb_copy_bits(skb, skb_data_pointer - skb->data, extracted_payload, data_length);
  extracted_payload[data_length] = 0;
  return extracted_payload;
}

int is_host_in_blacklist(char *hostname) {
  hosts_list_entry *cur_entry;
  list_for_each_entry(cur_entry, &(hosts_list.list), list) {
    //printk(KERN_INFO "hostname [%s]\n", hostname);
    //printk(KERN_INFO "packet host name [%s], entry host name [%s]\n", hostname, cur_entry->host_name);
    if (strcmp(hostname, cur_entry->host_name) == 0) {
      return 1;
    }
  }
  return 0;
}

int handle_http_connection(
    struct sk_buff *skb, connections_list_entry *connection, reason_t *reason) {
  char* payload;
  char *hostname, *temp_hostname;
  struct tcphdr *tcph = (struct tcphdr *)((__u32 *)ip_hdr(skb) + ip_hdr(skb)->ihl);
  payload = extract_payload(skb, tcph);
//  printk(KERN_INFO "payload = [%s].", payload);
  // We only care about GET requests. We accept all other traffic.
  if (strnicmp(payload, "GET", 3) == 0) {
//    printk(KERN_INFO "\"GET\" found in payload.");
    temp_hostname = strstr(payload, "Host: ");
    if (temp_hostname != NULL) {
//      printk(KERN_INFO "\"Host: \" found in payload.");
      temp_hostname = temp_hostname + 6; // Advance to the start of the host name.
      hostname = strsep(&temp_hostname, "\r\n");
      if (is_host_in_blacklist(hostname)) {
//        printk(KERN_INFO "Host is in blacklist, blocking packet.");
        *reason = BLOCKED_HOST;
        kfree(payload);
        return NF_DROP;
      }
    }
  }
  kfree(payload);
  *reason = VALID_TCP_CONNECTION;
  return NF_ACCEPT;
}

int handle_ftp_connection(struct sk_buff *skb, connections_list_entry *connection, reason_t *reason){
  int server_ip, full_ip, full_port, ip_part_1, ip_part_2, ip_part_3, ip_part_4, port1, port2;
  char* payload;
  struct tcphdr *tcph = (struct tcphdr *)((__u32 *)ip_hdr(skb) + ip_hdr(skb)->ihl);
  payload = extract_payload(skb, tcph);

  switch (connection->protocol_state){
    case TCP_ESTABLISH:
      if (strnicmp(payload, "230", 3) == 0) {
        connection->protocol_state = FTP_CONNECTED;
      }
      break;
    case FTP_CONNECTED:
      if (strnicmp(payload, "PORT", 4) == 0) {
        sscanf(payload, "PORT %d,%d,%d,%d,%d,%d",
            &ip_part_1, &ip_part_2, &ip_part_3, &ip_part_4, &port1, &port2);
        // TODO: validate that I don't need to use ntohl or whatever...
        full_ip = htonl((ip_part_1<<24) + (ip_part_2<<16) + (ip_part_3<<8) + ip_part_4);
        full_port = (port1 * 256) + port2;

        // Open a connection on the requested port.
        server_ip = ip_hdr(skb)->daddr;
        if (find_connection(&(ftp_connections_list.list),
            full_ip, full_port, server_ip, FTP_DATA_PORT) == NULL) {
          printk(KERN_INFO "Adding new FTP connection to FTP list for port [%u].", full_port);
          add_connection(
              &(ftp_connections_list.list), full_ip, full_port, server_ip, FTP_DATA_PORT, 0); // TODO fragment.
        }
      }
      break;
    case FTP_TERMINATED:
      // If ftp terminated accept only goodbye message (status 221) or tcp with fin.
      if (strnicmp(payload, "221", 3) != 0 && !tcph->fin){
        *reason = TCP_NON_COMPLIANT;
        return NF_DROP;
      }
      break;
  }
  if (strnicmp(payload, "QUIT", 4) == 0) {
    connection->protocol_state = FTP_TERMINATED;
  }
  *reason = VALID_TCP_CONNECTION;
  return NF_ACCEPT;
}

/***************************************************************************************************
 * Public methods.
 **************************************************************************************************/

int ftp_initial_verification(rule_t rule, reason_t *reason) {
  connections_list_entry *connection;
  printk(KERN_INFO "FTP connections count in the begging of ftp_initial_verification = [%u].", count_connections(&(ftp_connections_list.list)));
  connection = find_connection(
      &(ftp_connections_list.list), rule.src_ip, rule.src_port, rule.dst_ip, rule.dst_port);
  if (connection == NULL) {
    printk(KERN_INFO "Did not find connection in the FTP table.");
    *reason = REASON_NO_MATCHING_RULE;
    return NF_DROP;
  } else {
    // Note that if we find such connection we remove it.
    printk(KERN_INFO "Removing FTP connection.");
    remove_connection(&(ftp_connections_list.list), connection);
    *reason = VALID_TCP_CONNECTION;
    return NF_ACCEPT;
  }
}

int validate_and_update_tcp_connection(struct sk_buff *skb, rule_t rule, reason_t *reason) {
  connections_list_entry *connection;
  int syn, ack, fin;

  // Convert syn and ack to a more comfortable form.
  syn = rule.syn == ACK_YES ? 1 : 0;
  ack = rule.ack == ACK_YES ? 1 : 0;
  fin = rule.fin == ACK_YES ? 1 : 0;

  connection = find_connection(&(connections_list.list),
      rule.src_ip, rule.src_port, rule.dst_ip, rule.dst_port);
  if (connection == NULL) {
    if (!ack) {
//      printk(KERN_INFO "Creating connection.");
      if (add_connection(&connections_list.list,
          rule.src_ip, rule.src_port, rule.dst_ip , rule.dst_port, 0 /* TODO frag */) > 0){
        connections_list_size++;
      }
      //*reason = VALID_TCP_CONNECTION;   In this case reason is set by the stateless firewall.
      return NF_ACCEPT;
    } else {
//      printk(KERN_INFO "Connection not exists.");
      *reason = CONN_NOT_EXIST;
      return NF_DROP;
    }
  }

  switch (connection->tcp_state) {
    case SENT_SYN_WAIT_SYNACK:
      printk(KERN_INFO "in SENT_SYN_WAIT_SYNACK.");
      if (ack && syn) {
//        printk(KERN_INFO "Received syn ack.");
        if (is_timeout_expired(connection)) {
//          printk(KERN_INFO "Timeout expired, removing connection.");
          if (remove_connection(&connections_list.list, connection) < 0) {
            connections_list_size--;
          }
          *reason = TIME_OUT_EXPIRED;
          return NF_DROP;
        }
        connection->tcp_state = SENT_SYNACK_WAIT_ACK;
        *reason = VALID_TCP_CONNECTION;
        return NF_ACCEPT;
      }
      break;
    case SENT_SYNACK_WAIT_ACK:
      if (ack && !syn) {
//        printk(KERN_INFO "Received ack.");
        if (is_timeout_expired(connection)) {
//          printk(KERN_INFO "Timeout expired, removing connection.");
          if (remove_connection(&connections_list.list, connection) < 0) {
            connections_list_size--;
          }
          *reason = TIME_OUT_EXPIRED;
          return NF_DROP;
        }
        connection->tcp_state = ESTABLISHED;
        connection->protocol_state = TCP_ESTABLISH;
        *reason = VALID_TCP_CONNECTION;
        return NF_ACCEPT;
      }
      break;
    case ESTABLISHED:
      if (fin) {
//        printk(KERN_INFO "Received fin.");
        connection->tcp_state = SENT_FIN_WAIT_FIN2;
        *reason = VALID_TCP_CONNECTION;
        return NF_ACCEPT;
      }
//      printk(KERN_INFO "Received normal packet after connection established.");
      if (connection->protocol == FTP) {
        return handle_ftp_connection(skb, connection, reason);
      } else if (connection->protocol == HTTP) {
        return handle_http_connection(skb, connection, reason);
      } else {
        *reason = VALID_TCP_CONNECTION;
        return NF_ACCEPT;
      }
    case SENT_FIN_WAIT_FIN2:
      if (fin) {
//        printk(KERN_INFO "Received fin2.");
        connection->tcp_state = SENT_FIN2_WAIT_ACK;
        *reason = VALID_TCP_CONNECTION;
        return NF_ACCEPT;
      }
      break;
    case SENT_FIN2_WAIT_ACK:
      if (ack) {
//        printk(KERN_INFO "Received final ack for fin removing connection.");
        if (remove_connection(&connections_list.list, connection) < 0) {
          connections_list_size--;
        }
        *reason = VALID_TCP_CONNECTION;
        return NF_ACCEPT;
      }
      break;
  }
//  printk(KERN_INFO "Not a valid packet.");
  *reason = TCP_NON_COMPLIANT;
  return NF_DROP;
}


/***************************************************************************************************
 * Driver file operations.
 **************************************************************************************************/

/*
 * Our custom open function for file_operations. Each time we open the device we initializing the
 * changing variables (so we will be able to read it again and again).
 *
 * In this implementation we prepare the buffer that should be sent to the user.
 */
int open_connections_device(struct inode *_inode, struct file *_file) {

  remaining_num_of_bytes_to_read =
      (connections_list_size + 1) * ROW_SIZE_AS_STRING + 1;

  // Prepare all the connections that should be written.
  connections_read_buffer = kcalloc(remaining_num_of_bytes_to_read, 1, GFP_KERNEL);
  if (connections_read_buffer == NULL) {
    return -1;
  }
  pointer_to_current_location_in_connections_read_buffer = connections_read_buffer;

  // Fill the buffer with the connections.
  get_connections_as_string(connections_read_buffer, remaining_num_of_bytes_to_read);

  return 0;
}

/*
 * Implementation for the read method of file_operations.
 */
ssize_t read_connections(struct file *filp, char *buff, size_t length, loff_t *offp) {
  ssize_t bytes_to_write_in_the_current_iteration =
      (remaining_num_of_bytes_to_read < length) ? remaining_num_of_bytes_to_read : length;

  // If nothing left to write return.
  if (bytes_to_write_in_the_current_iteration == 0) {
    return 0;
  }

  // Send the data to the user through 'copy_to_user'
  if (copy_to_user(buff, pointer_to_current_location_in_connections_read_buffer,
      bytes_to_write_in_the_current_iteration)) {
    kfree(connections_read_buffer);
    return -EFAULT;
  } else {
    // function succeeded, we just sent the user 'num_of_bytes' bytes, so we updating the counter
    // and the string pointer index.
    remaining_num_of_bytes_to_read -= bytes_to_write_in_the_current_iteration;
    pointer_to_current_location_in_connections_read_buffer +=
        bytes_to_write_in_the_current_iteration;
    return bytes_to_write_in_the_current_iteration;
  }
}

int release_connections_device(struct inode *inode, struct file *file) {
  kfree(connections_read_buffer);
  return 0;
}

/*
 * File operations for the connections device.
 */
static struct file_operations connections_device_fops = {
  .owner = THIS_MODULE,
  .open = open_connections_device,
  .read = read_connections,
  .release = release_connections_device
};


/***************************************************************************************************
 * Functions for sysfs attributes
 **************************************************************************************************/


ssize_t get_hosts(struct device *dev, struct device_attribute *attr, char *buf) {
  hosts_list_entry *cur_entry;
  buf[0] = 0;
  list_for_each_entry(cur_entry, &(hosts_list.list), list) {
    strcat(buf, cur_entry->host_name);
    strcat(buf, "\n");
  }
  return strlen(buf);
}

ssize_t set_hosts(
    struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
  char *input;
  char *host_name;
  clear_list_hosts();
  printk(KERN_INFO "In set hosts.\n");
  input = kmalloc(strlen(buf) + 2, GFP_ATOMIC);
  input[0] = 0;
  strcat(input, buf);
  strcat(input, "\n"); // Add \n to the last line.
//  printk(KERN_INFO "buf: [%s]\n", buf);
//  printk(KERN_INFO "input: [%s]\n", input);
  while (strlen(host_name = strsep(&input, "\n")) > 0) {
    if (input == NULL) {
      printk(KERN_INFO "Invalid format: There is a line that doesn't end with \\n. \n.");
      clear_list_hosts();
      break;
    }
    //printk(KERN_INFO "add host [%s]", host_name);
    add_host(host_name);
  }
  kfree(input);
  return count;
}

static DEVICE_ATTR(hosts_load_store, S_IRWXO , get_hosts, set_hosts);

/*
 * Sysfs clear connections implementation.
 */
ssize_t sysfs_clear_connections(
    struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
  char c;
  int returnValue;
  if((returnValue = sscanf(buf, "%c", &c)) == 1) {
    clear_list_connections(&(connections_list.list));;
  }
  printk(KERN_INFO "Done clearing connections\n");
  return returnValue;
}

/*
 * Register ops.
 */
static DEVICE_ATTR(connections_clear, S_IWOTH , NULL, sysfs_clear_connections);


/***************************************************************************************************
 * Registration methods.
 **************************************************************************************************/


int register_connections_driver(struct class* fw_sysfs_class) {
  connections_device_major_number =
      register_chrdev(0, DEVICE_NAME_CONNECTIONS, &connections_device_fops);
  if(connections_device_major_number < 0) {
    return -1;
  }

  // Create sysfs device.
  connections_sysfs_device = device_create(fw_sysfs_class, NULL,
      MKDEV(connections_device_major_number, 0), NULL, DEVICE_NAME_CONNECTIONS);
  if(IS_ERR(connections_sysfs_device)) {
    unregister_chrdev(connections_device_major_number, DEVICE_NAME_CONNECTIONS);
    return -1;
  }

  // Create sysfs hosts attribute.
  if(device_create_file(connections_sysfs_device,
      (const struct device_attribute*) &dev_attr_hosts_load_store.attr)) {
    device_destroy(fw_sysfs_class, MKDEV(connections_device_major_number, 0));
    unregister_chrdev(connections_device_major_number, DEVICE_NAME_CONNECTIONS);
    return -1;
  }

  // Create sysfs clear connections attribute.
  if(device_create_file(connections_sysfs_device,
      (const struct device_attribute*) &dev_attr_connections_clear.attr)) {
    device_remove_file(connections_sysfs_device,
        (const struct device_attribute *)&dev_attr_hosts_load_store.attr);
    device_destroy(fw_sysfs_class, MKDEV(connections_device_major_number, 0));
    unregister_chrdev(connections_device_major_number, DEVICE_NAME_CONNECTIONS);
    return -1;
  }
  // Initialize the lists.
  INIT_LIST_HEAD(&connections_list.list);
  INIT_LIST_HEAD(&ftp_connections_list.list);
  INIT_LIST_HEAD(&hosts_list.list);
  connections_list_size = 0;
  return 0;
}

int remove_connections_device(struct class* fw_sysfs_class) {
  clear_list_connections(&(connections_list.list));
  clear_list_connections(&(ftp_connections_list.list));
  clear_list_hosts();
  device_remove_file(connections_sysfs_device,
      (const struct device_attribute *)&dev_attr_connections_clear.attr);
  device_remove_file(connections_sysfs_device,
      (const struct device_attribute *)&dev_attr_hosts_load_store.attr);
  device_destroy(fw_sysfs_class, MKDEV(connections_device_major_number, 0));
  unregister_chrdev(connections_device_major_number, DEVICE_NAME_CONNECTIONS);
  return 0;
}

