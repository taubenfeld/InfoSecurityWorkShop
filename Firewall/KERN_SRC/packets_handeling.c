#include "packets_handeling.h"

int create_rule_from_packet(struct sk_buff *skb, rule_t *new_rule) {
  struct iphdr *iph;
  struct udphdr *udph;
  struct tcphdr *tcph;
  iph = ip_hdr(skb);
  new_rule->src_ip = iph->saddr;
  new_rule->dst_ip = iph->daddr;
  new_rule->protocol = iph->protocol;
  // TODO(amirt): validate that this is what expected.
  new_rule->ack = ACK_ANY; // This is overridden in case it is a TCP protocol.

  switch (new_rule->protocol) {
  case PROT_TCP:
    tcph  = (struct tcphdr *)((__u32 *)iph + iph->ihl);
    new_rule->src_port = ntohs(tcph->source);
    new_rule->dst_port = ntohs(tcph->dest);
    printk(KERN_INFO "new_rule->src_port: %d\n", new_rule->src_port);
    printk(KERN_INFO "new_rule->dst_port: %d\n", new_rule->dst_port);
    new_rule->ack = tcph->ack ? ACK_YES : ACK_NO;
    // Check X_MAS_PACKET
    if (tcph->fin && tcph->urg && tcph->psh) {
      return REASON_XMAS_PACKET;
    }
    break;
  case PROT_UDP:
    udph = (struct udphdr *)((__u32 *)iph + iph->ihl);
    new_rule->src_port = ntohs(udph->source);
    new_rule->dst_port = ntohs(udph->dest);
    break;
  case PROT_ICMP: // ICMP doesn't uses port. TODO(amirt): validate that this is what expected.
  case PROT_OTHER:
  case PROT_ANY:
    new_rule->src_port = PORT_ANY;
    new_rule->dst_port = PORT_ANY;
  }
  return 0;
}

int ports_match(int rule_port, int table_rule_port) {
  return (table_rule_port == PORT_ANY_NUMBER)
      || ((table_rule_port > PORT_ABOVE_1023) && (rule_port > PORT_ABOVE_1023))
      || (table_rule_port == rule_port);
}

int ips_match(int rule_ip, int table_rule_ip) {
  return (table_rule_ip == IP_ANY) || (table_rule_ip == rule_ip);
}

/*
 * Check if a given rule matches a given table rule.
 */
int match_rule_aginst_table_rule(rule_t rule, rule_t table_rule) {
  if (!(rule.direction & table_rule.direction)) {
    //printk(KERN_INFO "%s\n", "Direction don't match");
    return 0;
  }
  if (table_rule.protocol != PROT_ANY && rule.protocol != table_rule.protocol) {
    //printk(KERN_INFO "%s\n", "protocol don't match");
    return 0;
  }
  if (!(rule.ack & table_rule.ack)) {
    //printk(KERN_INFO "%s\n", "ack don't match");
    return 0;
  }
  if (!(ports_match(rule.src_port, table_rule.src_port))) {
    //printk(KERN_INFO "%s\n", "src_port don't match");
    return 0;
  }
  if (!(ports_match(rule.dst_port, table_rule.dst_port))) {
    //printk(KERN_INFO "%s\n", "dst_port don't match");
    return 0;
  }
  if (!(ips_match(rule.src_ip, table_rule.src_ip))) {
    //printk(KERN_INFO "%s\n", "src_ip don't match");
    return 0;
  }
  if (!(ips_match(rule.dst_ip, table_rule.dst_ip))) {
    //printk(KERN_INFO "%s\n", "dst_ip don't match");
    return 0;
  }
  //printk(KERN_INFO "%s\n", "packet matched all fields.");
  return 1;
}

int verify_packet(struct sk_buff *skb, int hooknum) {
  int i;
  int status;
  rule_t new_rule;
  rule_t table_rule;
  int action = NF_ACCEPT;
  reason_t reason = REASON_NO_MATCHING_RULE;

  status = create_rule_from_packet(skb, &new_rule);

  if (firewall_rule_checking_status == STATUS_NOT_ACTIVE) {
    reason = REASON_FW_INACTIVE;
    action = NF_ACCEPT;
  }
  else if (status < 0) {
    action = NF_DROP;
    reason = REASON_XMAS_PACKET;
  }
  else { // Check for a matching rule. TODO(amirt): In and out for the hosts.
    new_rule.direction = (hooknum == NF_INET_PRE_ROUTING) ? DIRECTION_IN : DIRECTION_OUT;
    for (i = 0; i < number_of_rules; i++) {
      table_rule = rules_table[i];
      if (match_rule_aginst_table_rule(new_rule, table_rule)) {
        action = table_rule.action;
        reason = i; // Packet matched rule, the reason should be the rule number.
        break;
      }
    }
  }

  add_log(skb->tstamp.tv64, new_rule.protocol, action, hooknum,
      new_rule.src_ip, new_rule.dst_ip, new_rule.src_port, new_rule.dst_port, reason);
  return action;
}

