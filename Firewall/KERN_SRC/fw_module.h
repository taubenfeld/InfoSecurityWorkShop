
#ifndef FW_MODULE_H_
#define FW_MODULE_H_

#include "fw.h"
#include "chardev_rules.h"
#include "chardev_info.h"
#include "packets_handeling.h"
#include "chardev_logs.h"

/***************************************************************************************************
 * Netfilter hooks.
 **************************************************************************************************/

/**
 * Function that will be hooked.
 * This function will be called by netfilter for forwarded packets.
 */
unsigned int pre_routing_hook(unsigned int hooknum, struct sk_buff *skb,
    const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));

/**
 * Function that will be hooked.
 * This function will be called by netfilter for packets that passed.
 */
unsigned int post_routing_hook(unsigned int hooknum, struct sk_buff *skb,
    const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));

/***************************************************************************************************
 * Module's registeration and unregisteration methods.
 **************************************************************************************************/

/*
 * Register all the drivers.
 */
static int register_drivers(void);

/*
 * Register all the netfiler hooks.
 */
static int register_hooks(void);

/*
 * Dismiss all the netfiler hooks.
 */
static void dismiss_hooks(void);

/**
 * The function that initialize the module.
 */
static int __init start_module(void);
/**
 * The function that dismiss the module.
 */
static void __exit dismiss_module(void);

#endif /* FW_MODULE_H_ */
