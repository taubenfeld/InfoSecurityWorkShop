
#include <linux/string.h>
//#include <linux/list.h>

#include "fw.h"

char *RULES_DEVICE_NAME = "fw_rules";

// TODO(amirt): What is the limit on the number of rules? Should it be a char or an int?
static char number_of_rules;
static rule_t *rules_table;

static int PORT_ANY_NUMBER = 1025;
static int PORT_ERROR_NUMBER = 1025;

int rules_device_major_number;
struct device* rules_device_sysfs_device = NULL;
struct file_operations rules_device_fops = {
  .owner = THIS_MODULE
};


/***************************************************************************************************
 * Local functions.
***************************************************************************************************/

/*
 * Gets the direction enum value by string value.
 * Returns 0 on failure.
 */
direction_t get_direction_from_string(char *direction_str) {
	if (strcmp(direction_str, "in") == 0){
		return DIRECTION_IN;
	}
	if (strcmp(direction_str, "out") == 0){
		return DIRECTION_OUT;
	}
	if (strcmp(direction_str, "any") == 0){
		return DIRECTION_ANY;
	}
	return 0;
}

/*
 * Gets string representation of the direction enum.
 * Returns NULL on failure.
 */
char *get_string_from_direction(direction_t direction) {
  switch (direction) {
  case DIRECTION_IN:
    return "in";
  case DIRECTION_OUT:
    return "out";
  case DIRECTION_ANY:
    return "any";
  default:
    return NULL;
  }
}

/*
 * Gets the protocol enum value by string value.
 * Returns 0 on failure.
 */
prot_t get_protocol_from_string(char *protocol) {
  if (strcmp(protocol, "ICMP") == 0){
    return PROT_ICMP;
  }
  if (strcmp(protocol, "TCP") == 0){
    return PROT_TCP;
  }
  if (strcmp(protocol, "UDP") == 0){
    return PROT_UDP;
  }
  if (strcmp(protocol, "OTHER") == 0){
    return PROT_OTHER;
  }
  if (strcmp(protocol, "any") == 0){
    return PROT_ANY;
  }
  return 0;
}

/*
 * Gets string representation of the protocol enum.
 * Returns NULL on failure.
 */
char *get_string_from_protocol(prot_t protocol) {
  switch (protocol) {
  case PROT_ICMP:
    return "ICMP";
  case PROT_TCP:
    return "TCP";
  case PROT_UDP:
    return "UDP";
  case PROT_OTHER:
    return "OTHER";
  case PROT_ANY:
    return "any";
  default:
    return NULL;
  }
}

/*
 * Gets the ack enum value by string value.
 * Returns 0 on failure.
 */
ack_t get_ack_from_string(char *ack) {
  if (strcmp(ack, "no") == 0) {
    return ACK_NO;
  }
  if (strcmp(ack, "yes") == 0) {
    return ACK_YES;
  }
  if (strcmp(ack, "any") == 0) {
    return ACK_ANY;
  }
  return 0;
}

/*
 * Gets string representation of the ack enum.
 * Returns NULL on failure.
 */
char *get_string_from_ack(ack_t ack) {
  switch (ack) {
  case ACK_NO:
    return "no";
  case ACK_YES:
    return "yes";
  case ACK_ANY:
    return "any";
  default:
    return NULL;
  }
}

/*
 * Get Netfiler's action value from string value.
 */
int get_action_from_string(char *action) {
  if (strcmp(action, "accept") == 0){
    return NF_ACCEPT;
  }
  if (strcmp(action, "drop") == 0){
    return NF_DROP;
  }
  return 0;
}

/*
 * Get Netfiler's action value from string value.
 */
char *get_string_from_action(int action) {
  switch (action) {
  case NF_ACCEPT:
    return "accept";
  case NF_DROP:
    return "drop";
  default:
    return NULL;
  }
}

/*
 * Parse the port from string to int.
 * Returns 0 on failure.
 */
int parse_port_from_string(char *str_port) {
  int result;
  if (strcmp(str_port, "any") == 0) {
    return PORT_ANY_NUMBER;
  }
  if (str_port[0] == '>') {
    if (!kstrtoint(str_port+1, 10, &result) && result == 1023) { // Success.
      return htons(result);
    }
  }
  else if (!kstrtoint(str_port, 10, &result) && 0 < result && result < 1024) {
    return htons(result);
  }
  return PORT_ERROR_NUMBER;
}

/*
 * Parse the port from int to string.
 * Returns 0 on failure.
 */
void parse_string_from_port(int port, char target_str_port[]) {
  if (port == PORT_ANY_NUMBER) {
    sprintf(target_str_port, "%s", "any");
  }
  else {
    sprintf(target_str_port, "%d", port);
  }
}

/*
 * Parse IP base & mask.
 * Returns 0 on failure.
 */
int parse_ips_from_string(char *full_ip_string, __be32 *ip_base, __u8 *mask_size) {
  long temp;
  char *ip_base_string;

  if (strcmp(full_ip_string, "any") == 0) {
    *ip_base = 0;
    *mask_size = 0;
    return 1;
  }

  // The IP doesn't contains a prefix.
  if (strchr(full_ip_string, '/') == NULL) {
    *ip_base = in_aton(full_ip_string);
    *mask_size = 0;
    return 1;
  }

  // Parse the IP base. Split the base IP from the prefix.
  // After using strsep src_ip_string will point to the prefix part.
  // TODO(amirt): check all kmalloc allocations.
  ip_base_string = kmalloc(20 * sizeof(char), GFP_KERNEL);
  if ((ip_base_string = strsep(&full_ip_string, "/")) == NULL) {
    return 0;
  }

  // TODO: validate this.
  *ip_base = in_aton(ip_base_string);

  // Parse the IP prefix.
  if (kstrtol(full_ip_string, 10, &temp)
      || temp < 0 || temp > 32) {
    return 0;
  }
  *mask_size = temp;

  return 1;
}

/*
 * Function that convert int IP to dot notation string IP.
 * I took this function from: http://stackoverflow.com/questions/1680365/integer-to-ip-address-c.
 */
void int_ip_to_dot_ip(int ip, char str_ip[]) {
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    sprintf(str_ip, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
}

void parse_string_from_ip(int ip_base, int mask_size, char target_str_ip[]) {
  char mask_string[10] = {0};
  if (ip_base == 0) {
    sprintf(target_str_ip, "%s", "any");
  }
  int_ip_to_dot_ip(ip_base, target_str_ip);
  if (mask_size != 0) {
    sprintf(mask_string, "/%d", mask_size);
    strcat(target_str_ip, mask_string);
  }
}

/*
 * Parse a rule_t from a given string. On error returns 0.
 */
rule_t *parse_rule_from_string(char* str_rule) {
  // TODO(amirt): check all kmalloc allocations.
	rule_t *rule = kmalloc(sizeof(rule_t), GFP_KERNEL);
	char name[20] = {0};
	char direction[4] = {0};
	// TODO(amirt): check all kmalloc allocations.
  char *src_ip_string =
      kmalloc(20 * sizeof(char), GFP_KERNEL); // 16 chars for ip and 3 for mask
  // TODO(amirt): check all kmalloc allocations.
  char *dst_ip_string =
      kmalloc(20 * sizeof(char), GFP_KERNEL); // 16 chars for ip and 3 for mask
	char protocol[6] = {0}; 		    // Longest protocol name is OTHER\0.
	char src_port[6] = {0};
	char dst_port[6] = {0};
	char ack[4] = {0};
	char action[7] = {0};

	sscanf(str_rule, "%19s %3s %19s %19s %5s %5s %5s %3s %6s\n",
      name,
      direction,
      src_ip_string,
      dst_ip_string,
      protocol,
      src_port,
      dst_port,
      ack,
      action);

	if(!strcpy(rule->rule_name, name)
	    || !(rule->direction = get_direction_from_string(direction))
	    || !(parse_ips_from_string(src_ip_string, &rule->src_prefix_mask, &rule->src_prefix_size))
	    || !(parse_ips_from_string(dst_ip_string, &rule->dst_prefix_mask, &rule->dst_prefix_size))
	    || !(rule->protocol = get_protocol_from_string(protocol))
	    || ((rule->src_port = parse_port_from_string(src_port)) == PORT_ERROR_NUMBER)
	    || ((rule->dst_port = parse_port_from_string(dst_port)) == PORT_ERROR_NUMBER)
	    || !(rule->ack = get_ack_from_string(ack))
	    || !(rule->action = get_action_from_string(action))){
	  kfree(rule);
	  rule = NULL;
	}

	kfree(src_ip_string);
	kfree(dst_ip_string);
	return rule;
}

/*
 * Parse a given rule into a string, and writes it to the buffer.
 */
int parse_string_from_rule(rule_t rule, char *buffer, int size) {
  char src_ip[20] = {0};
  char dst_ip[20] = {0};
  char src_port[6] = {0};
  char dst_port[6] = {0};

  parse_string_from_ip(rule.src_ip, rule.src_prefix_size, src_ip);
  parse_string_from_ip(rule.dst_ip, rule.dst_prefix_size, dst_ip);
  parse_string_from_port(rule.src_port, src_port);
  parse_string_from_port(rule.dst_port, dst_port);

  scnprintf(buffer, size, "%20s %4s %20s %20s %6s %6s %6s %4s %7s\n",
      rule.rule_name,
      get_string_from_action(rule.direction),
      src_ip,
      dst_ip,
      get_string_from_protocol(rule.protocol),
      src_port,
      dst_port,
      get_string_from_ack(rule.ack),
      get_string_from_action(rule.action));
  return 0;
}


/***************************************************************************************************
 * Functions for sysfs attributes
 **************************************************************************************************/

ssize_t get_rules(struct device *dev,struct device_attribute *attr, char *buf) {
  rule_t rule;
  int i;
  char str_rule[200] = {0}; // 200 bytes is more the enough for one rule.
  for (i=0; i<number_of_rules; i++) {
    rule = rules_table[i];
    parse_string_from_rule(rule, str_rule, PAGE_SIZE);
    strcat(buf, str_rule);
  }
  return 0;
}

/*
 * Sysfs store implementation.
 * Sets the rules that are used by the sateless firewall.
 */
ssize_t set_rules(
    struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
  unsigned char i=0;
  char *str_rule;
  char *str_rules = (char *) buf + sizeof(number_of_rules);
  rule_t *rule;
  if(!(sscanf(buf, "%c", &number_of_rules) == 1)) {
    printk(KERN_INFO "Failed loading rule table: Invalid size for rules table.");
    return 0;
  }
  // TODO(amirt): check all kmalloc allocations.
  rules_table = kmalloc(number_of_rules * sizeof(rule_t), GFP_KERNEL);
  for (i=0; i<number_of_rules; i++) {
    str_rule = strsep(&str_rules, "\n");
    if ((rule = parse_rule_from_string(str_rule)) == NULL) {
      printk(KERN_INFO "Failed loading rule table: Invalid rule format.");
      kfree(rules_table);
      return 0;
    }
    rules_table[i] = *rule;
    kfree(rule);
  }
  return 1;
}

static DEVICE_ATTR(rules_load_store, S_IRWXO , get_rules, set_rules);


/***************************************************************************************************
 * Registration methods
 **************************************************************************************************/


int register_rules_driver(struct class* fw_sysfs_class) {
  // Create char device. fops is empty because we are using sysfs.
  rules_device_major_number = register_chrdev(0, RULES_DEVICE_NAME, &rules_device_fops);
  if(rules_device_major_number < 0) {
    return -1;
  }

  // Create sysfs device.
  rules_device_sysfs_device = device_create(
      fw_sysfs_class, NULL, MKDEV(rules_device_major_number, 0), NULL, RULES_DEVICE_NAME);
  if(IS_ERR(rules_device_sysfs_device)) {
    unregister_chrdev(rules_device_major_number, RULES_DEVICE_NAME);
    return -1;
  }

  // Create sysfs file attributes .
  if(device_create_file(rules_device_sysfs_device,
      (const struct device_attribute*) &dev_attr_rules_load_store.attr)) {
    device_destroy(fw_sysfs_class, MKDEV(rules_device_major_number, 0));
    unregister_chrdev(rules_device_major_number, RULES_DEVICE_NAME);
    return -1;
  }
  return 0;
}



// For debug.
//  printk(KERN_INFO "name: %s\n", name);
//  printk(KERN_INFO "direction: %s\n", direction);
//  printk(KERN_INFO "src_ip_string: %s\n", src_ip_string);
//  printk(KERN_INFO "dst_ip_string: %s\n", dst_ip_string);
//  printk(KERN_INFO "protocol: %s\n", protocol);
//  printk(KERN_INFO "src_port: %s\n", src_port);
//  printk(KERN_INFO "dst_port: %s\n", dst_port);
//  printk(KERN_INFO "ack: %s\n", ack);
//  printk(KERN_INFO "action: %s\n", action);
