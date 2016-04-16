#include "fw.h"
#include "chardev_rules.c"
#include "chardev_basic_info.c"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Amir Taubenfeld");

// Netfilter stuff.
static struct nf_hook_ops forward_hook_struct;
static struct nf_hook_ops post_routing_hook_struct;

static struct class* sysfs_class = NULL;


/***************************************************************************************************
 * Netfilter hooks.
 **************************************************************************************************/

/**
 * Function that will be hooked.
 * This function will be called by netfilter for forwarded packets.
 */
unsigned int  forward_packets_hook(unsigned int hooknum, struct sk_buff *skb,
    const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {
  printk(KERN_INFO "*** packet blocked ***\n");
  number_of_blocked_packets++;
  return NF_DROP;
}

/**
 * Function that will be hooked.
 * This function will be called by netfilter for packets that passed.
 */
unsigned int  post_routing_hook(unsigned int hooknum, struct sk_buff *skb,
    const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {
  printk(KERN_INFO "*** packet passed ***\n");
  number_of_passed_packets++;
  return NF_ACCEPT;
}


/***************************************************************************************************
 * Module's registeration and unregisteration methods.
 **************************************************************************************************/


int register_drivers(void) {
  sysfs_class = class_create(THIS_MODULE, "fw_class");
  if(IS_ERR(sysfs_class)) {
    return -1;
  }
  if (register_info_driver(sysfs_class) == -1) {
    class_destroy(sysfs_class);
    return -1;
  }
}

void register_hooks(void) {
  // Register hook that disables packet forwarding.
  forward_hook_struct.hook = forward_packets_hook;  // Hook our function.
  forward_hook_struct.hooknum = NF_INET_FORWARD;  // Hook to forward messages.
  forward_hook_struct.priority = NF_IP_PRI_FIRST;
  forward_hook_struct.pf = PF_INET;
  nf_register_hook(&forward_hook_struct);

  // Register print packed passed on all packed that have reached post rounting.
  post_routing_hook_struct.hook = post_routing_hook;  // Hook our function.
  post_routing_hook_struct.hooknum = NF_INET_POST_ROUTING;  // Hook to on post routing.
  post_routing_hook_struct.priority = NF_IP_PRI_LAST;
  post_routing_hook_struct.pf = PF_INET;
  nf_register_hook(&post_routing_hook_struct);
}

/**
 * The function that initialize the module.
 */
static int __init start_module(void) {
  printk(KERN_INFO "Amir's firewall is beening loaded!\n");
  register_hooks();
  return register_drivers();  // if non-0 return, then init_module have failed.
}

/**
 * The function that dismiss the module.
 */
static void __exit dismiss_module(void) {
  printk(KERN_INFO "Amir's firewall is been dismissed!\n");
  nf_unregister_hook(&forward_hook_struct);
  nf_unregister_hook(&post_routing_hook_struct);
  class_destroy(sysfs_class);
}

module_init(start_module);
module_exit(dismiss_module);