
#ifndef PACKETS_HANDELING_H_
#define PACKETS_HANDELING_H_

#include "fw.h"
#include "chardev_rules.h"
#include "chardev_logs.h"
#include "stateful.h"

// All ports greater than 1023 should be treated equally.
#define PORT_ANY_NUMBER (1025)
#define IP_ANY (0)

/*
 * Create a rule from a given packet.
 */
int create_rule_from_packet(struct sk_buff *skb, rule_t *new_rule, int hooknum);

/*
 * Check if a given rule matches a given table rule.
 */
int match_rule_aginst_table_rule(rule_t rule, rule_t table_rule);

/*
 * Decides if the packet should be blocked.
 */
int verify_packet(struct sk_buff *skb, int hooknum);


#endif /* PACKETS_HANDELING_H_ */
