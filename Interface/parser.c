
#include "parser.h"

static int PORT_ANY_NUMBER = 1025;
static int PORT_ERROR_NUMBER = 1026;

static int IP_ANY = 0;
static int ACTION_ERROR_NUMBER = 255;

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
  printf("%s\n", "Failed to get direction from string");
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
  printf("%s\n", "Failed to get protocol from string");
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
  case PROT_ANY:
    return "any";
  default:
    return "OTHER";
  }
}

char *get_string_from_app_protocol(application_layer_protocol protocol) {
  switch (protocol) {
  case HTTP:
    return "HTTP";
  case FTP:
    return "FTP";
  default:
    return "OTHER";
  }
}

char *get_string_from_tcp_state(tcp_state state) {
  switch (state) {
  case SENT_SYN_WAIT_SYNACK:
    return "SENT_SYN_WAIT_SYNACK";
  case SENT_SYNACK_WAIT_ACK:
    return "SENT_SYNACK_WAIT_ACK";
  case ESTABLISHED:
    return "ESTABLISHED";
  case SENT_FIN_WAIT_FIN2:
    return "SENT_FIN_WAIT_FIN2";
  case SENT_FIN2_WAIT_ACK:
    return "SENT_FIN2_WAIT_ACK";
  default:
    return "OTHER";
  }
}

//typedef enum {
//  TCP_HANDSHAKE     = 1,
//  TCP_ESTABLISH     = 2,
//  TCP_TERMINATED    = 3,
//
//  FTP_HANDSHAKE     = 4,
//  FTP_ESTABLISHED   = 5,
//  FTP_CONNECTED     = 6,
//  FTP_TRANSFER      = 7,
//  FTP_TERMINATED    = 8,
//
//  HTTP_HANDSHAKE    = 9,
//  HTTP_ESTABLISHED  = 10,
//  HTTP_CONNECTED    = 11,
//  HTTP_TERMINATED   = 12,
//} protocol_state;


char *get_string_from_protocol_state(protocol_state state) {
  switch (state) {
  case TCP_ESTABLISH:
    return "TCP_ESTABLISH";
  case FTP_CONNECTED:
    return "FTP_CONNECTED";
  case FTP_TERMINATED:
    return "FTP_TERMINATED";
  default:
    return "OTHER";
  }
  return "NOT YET IMPLEMENTED";
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
  printf("%s\n", "Failed to get ack from string");
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
  printf("%s\n", "Failed to get action from string.");
  return ACTION_ERROR_NUMBER;
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
  char *strtol_test;
  if (strcmp(str_port, "any") == 0) {
    return PORT_ANY_NUMBER;
  }
  if (str_port[0] == '>') {
    result = strtol(str_port+1, &strtol_test, 10);
    if ((str_port+1 != strtol_test) && result == PORT_ABOVE_1023) { // Success.
      return result + 1;
    }
  }
  else {
    result = strtol(str_port, &strtol_test, 10);
    if ((str_port+1 != strtol_test) && result <= PORT_ABOVE_1023) { // Success.
      return result;
    }
  }
  printf("%s\n", "Failed to get port from string");
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
  else if (port > PORT_ABOVE_1023) {
    sprintf(target_str_port, "%s", ">1023");
  }
  else {
    sprintf(target_str_port, "%d", port);
  }
}

/*
 * Parse IP base & mask.
 * Returns 0 on failure.
 */
int parse_ips_from_string(char *full_ip_string, unsigned int *ip_base, unsigned char *mask_size) {
  char *strtol_test;
  char *ip_base_string;
  struct sockaddr_in sock_in;

  if (strcmp(full_ip_string, "any") == 0) {
    *ip_base = IP_ANY;
    *mask_size = 0;
    return 1;
  }

  // The IP doesn't contains a mask size.
  if (strchr(full_ip_string, '/') == NULL) {
    if (!inet_aton(full_ip_string, &sock_in.sin_addr)) {
      return 0;
    }
    *ip_base = sock_in.sin_addr.s_addr;
    *mask_size = 0;
    return 1;
  }

  // Parse the IP base. Split the base IP from the prefix.
  // After using strsep full_ip_string will point to the prefix part.
  if ((ip_base_string = strsep(&full_ip_string, "/")) == NULL) {
    printf("%s\n", "Failed to split the IP string.");
    return 0;
  }

  if (!inet_aton(ip_base_string, &sock_in.sin_addr)){
    return 0;
  }
  *ip_base = sock_in.sin_addr.s_addr;

  // Parse the IP prefix.
  *mask_size = strtol(full_ip_string, &strtol_test, 10);
  if (full_ip_string == strtol_test
      || *mask_size < 1 || *mask_size > 32) {
    printf("%s\n", "Mask size is not valid.");
    return 0;
  }
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
    sprintf(str_ip, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

void parse_string_from_ip(int ip_base, int mask_size, char target_str_ip[]) {
  char mask_size_string[10] = {0};
  if (ip_base == IP_ANY) {
    sprintf(target_str_ip, "%s", "any");
    return;
  }
  int_ip_to_dot_ip(ip_base, target_str_ip);
  if (mask_size != 0) {
    sprintf(mask_size_string, "/%d", mask_size);
    strcat(target_str_ip, mask_size_string);
  }
}

/*
 * Parse a rule_t from a given string. On error returns 0.
 * The caller function is responsible of freeing the returned pointer.
 */
rule_t *parse_rule_from_string(char* str_rule) {
  rule_t *rule = malloc(sizeof(rule_t));
  char direction[4] = {0};
  char *src_ip_string =
      malloc(20 * sizeof(char));            // 16 chars for ip and 3 for mask
  char *dst_ip_string =
      malloc(20 * sizeof(char));              // 16 chars for ip and 3 for mask
  char protocol[6] = {0};                     // Longest protocol name is OTHER\0.
  char src_port[6] = {0};
  char dst_port[6] = {0};
  char ack[4] = {0};
  char action[7] = {0};
  sscanf(str_rule, "%19s %3s %19s %19s %5s %5s %5s %3s %6s",
      rule->rule_name,
      direction,
      src_ip_string,
      dst_ip_string,
      protocol,
      src_port,
      dst_port,
      ack,
      action);

  if (!(rule->direction = get_direction_from_string(direction))
      || !(parse_ips_from_string(src_ip_string, &rule->src_ip, &rule->src_prefix_size))
      || !(parse_ips_from_string(dst_ip_string, &rule->dst_ip, &rule->dst_prefix_size))
      || !(rule->protocol = get_protocol_from_string(protocol))
      || ((rule->src_port = parse_port_from_string(src_port)) == PORT_ERROR_NUMBER)
      || ((rule->dst_port = parse_port_from_string(dst_port)) == PORT_ERROR_NUMBER)
      || !(rule->ack = get_ack_from_string(ack))
      || ((rule->action = get_action_from_string(action)) == ACTION_ERROR_NUMBER )) {
    free(rule);
    rule = NULL;
  }
  free(src_ip_string);
  free(dst_ip_string);
  return rule;
}

/*
 * Parse a given rule into a string, and writes it to the buffer.
 */
int parse_string_from_rule(rule_t rule, char *buffer) {
  char src_ip[20] = {0};
  char dst_ip[20] = {0};
  char src_port[6] = {0};
  char dst_port[6] = {0};

  parse_string_from_ip(rule.src_ip, rule.src_prefix_size, src_ip);
  parse_string_from_ip(rule.dst_ip, rule.dst_prefix_size, dst_ip);
  parse_string_from_port(rule.src_port, src_port);
  parse_string_from_port(rule.dst_port, dst_port);

  sprintf(buffer, "%-19s %-19s %-19s %-19s %-19s %-19s %-19s %-19s %-19s\n",
      rule.rule_name,
      get_string_from_direction(rule.direction),
      src_ip,
      dst_ip,
      get_string_from_protocol(rule.protocol),
      src_port,
      dst_port,
      get_string_from_ack(rule.ack),
      get_string_from_action(rule.action));
  return 0;
}

void get_string_from_reason(int reason, char buf[]) {
  switch (reason) {
  case (REASON_FW_INACTIVE):
    sprintf(buf, "%s", "REASON_FW_INACTIVE");
    break;
  case (REASON_NO_MATCHING_RULE):
    sprintf(buf, "%s", "REASON_NO_MATCHING_RULE");
    break;
  case (REASON_XMAS_PACKET):
    sprintf(buf, "%s", "REASON_XMAS_PACKET");
    break;
  case (REASON_ILLEGAL_VALUE):
    sprintf(buf, "%s", "REASON_ILLEGAL_VALUE");
    break;
  case (CONN_NOT_EXIST):
    sprintf(buf, "%s", "CONN_NOT_EXIST");
    break;
  case (TCP_NON_COMPLIANT):
    sprintf(buf, "%s", "TCP_NON_COMPLIANT");
    break;
  case (VALID_TCP_CONNECTION):
    sprintf(buf, "%s", "VALID_TCP_CONNECTION");
    break;
  case (TIME_OUT_EXPIRED):
    sprintf(buf, "%s", "TIME_OUT_EXPIRED");
    break;
  case (BLOCKED_HOST):
    sprintf(buf, "%s", "BLOCKED_HOST");
    break;
  case (CONTAINS_CODE):
    sprintf(buf, "%s", "CONTAINS_CODE");
    break;
  case (EXPLOIT_PHOTO_GALLERY):
    sprintf(buf, "%s", "EXPLOIT_PHOTO_GALLERY");
    break;
  default:
    sprintf(buf, "%d", reason);
  }
}

ssize_t parse_string_from_log(log_row_t log, char *output_string_rule) {
  char *string_time;
  char src_ip[20] = {0};
  char dst_ip[20] = {0};
  char reason[29] = {0};

  // Remove the \n in the end of the string that ctime returns.
  string_time = ctime((const time_t *) &log.timestamp);
  string_time[strlen(string_time)-1] = ' ';

  parse_string_from_ip(log.src_ip, 0, src_ip);
  parse_string_from_ip(log.dst_ip, 0, dst_ip);
  get_string_from_reason(log.reason, reason),

  sprintf(output_string_rule, "%-30s %-21s %-21s %-10u %-10u %-10s %-10u %-10s %-30s %-10u\n",
      string_time,
      src_ip,
      dst_ip,
      log.src_port,
      log.dst_port,
      get_string_from_protocol(log.protocol),
      log.hooknum,
      get_string_from_action(log.action),
      reason,
      log.count);
  return 0;
}

ssize_t parse_string_from_connection(connections_list_entry conn, char *output_string_conn) {
  char src_ip[20] = {0};
  char dst_ip[20] = {0};

  parse_string_from_ip(conn.src_ip, 0, src_ip);
  parse_string_from_ip(conn.dst_ip, 0, dst_ip);

  sprintf(output_string_conn, "%-21s %-21u %-21s %-21u %-21s %-21s %-21s\n",
      src_ip,
      conn.src_port,
      dst_ip,
      conn.dst_port,
      get_string_from_app_protocol(conn.protocol),
      get_string_from_tcp_state(conn.tcp_state),
      get_string_from_protocol_state(conn.protocol_state));
  return 0;
}

/***************************************************************************************************
 * Public functions
 **************************************************************************************************/



/*
 * Receives a buffer with rules in the raw kernel format, and return a buffer with rules in user
 * Readable format.
 */
ssize_t rules_kernel_format_to_user_format(char *input, char *output) {
  rule_t rule;
  char *input_string_rule;
  char output_string_rule[200] = {0}; // 200 bytes is more then enough for one formated rule.

  unsigned int src_prefix_size;
  unsigned int dst_prefix_size;
  unsigned int protocol;
  unsigned int action;

  output[0] = 0; // Prepare buffer for strcat.
  while (strlen(input_string_rule = strsep(&input, "\n")) > 0) {
    sscanf(input_string_rule, "%19s %u %u %u %u %u %u %hu %hu %u %u",
        rule.rule_name,
        &rule.direction,
        &rule.src_ip,
        &src_prefix_size,
        &rule.dst_ip,
        &dst_prefix_size,
        &protocol,
        &rule.src_port,
        &rule.dst_port,
        &rule.ack,
        &action);

    rule.src_prefix_size = (char) src_prefix_size;
    rule.dst_prefix_size = (char) dst_prefix_size;
    rule.protocol = (char) protocol;
    rule.action = (char) action;

    parse_string_from_rule(rule, output_string_rule);
    strcat(output, output_string_rule);
  }
  return strlen(output);
}

/*
 * Receives a buffer with rules in the user format, and return the rules raw format that is ready
 * to be delivered to the kernel.
 * The rules are validated and in case of an -1 is returned.
 */
ssize_t rules_user_format_to_kernel_format(char *input, char *output) {
  char *input_string_rule;
  rule_t *output_rule = {0};
  char output_string_rule[80] = {0}; // 80 bytes is more then enough for one kernel format rule.
  strcat(input, "\n"); // Add \n to the last line.

  output[0] = 0; // Prepare output for strcat.
  while (strlen(input_string_rule = strsep(&input, "\n")) > 0) {

    if (input == NULL) {
      printf("Invalid format: There is a line that doesn't end with \\n. \n.");
      return -1;
    }

    if ((output_rule = parse_rule_from_string(input_string_rule)) == NULL) {
      return -1;
    }
    sprintf(output_string_rule, "%s %u %u %u %u %u %u %u %u %u %u\n",
        output_rule->rule_name,
        output_rule->direction,
        output_rule->src_ip,
        output_rule->src_prefix_size,
        output_rule->dst_ip,
        output_rule->dst_prefix_size,
        output_rule->protocol,
        output_rule->src_port,
        output_rule->dst_port,
        output_rule->ack,
        output_rule->action);

    strcat(output, output_string_rule);
    free(output_rule);
  }
  return strlen(output);
}

/**
 * Receives a buffer with logs in the raw kernel format, and return a buffer with logs in user
 * Readable format.
 *
 * The remainder uses in case we read only a part of a log. This can happen because if the buffer
 * got full before we finished to read the log. Thus we need to wait to the other part of the log
 * before starting to parse it.
 *  - If the remainder length is not 0 add it before the begging of the first log.
 *  - If the last log didn't end with \n return it in the remainder buffer.
 */
int logs_kernel_format_to_user_format(char *input, char *output, char* remainder) {
  log_row_t log;
  char* input_string_log;
  char output_string_log[300];
  unsigned int protocol, action, hooknum;
  output[0] = 0;
  while (input != NULL && strlen(input_string_log = strsep(&input, "\n")) > 0) {

    // The input is terminated, but the input_string_log length > 0. That means that the current
    // log didn't end with \n. That means that we didn't read it until the end. Therefore we will
    // save the remainder to the next read iteration.
    if (input == NULL) {
      strncpy(remainder, input_string_log, MAX_USER_FORMAT_LOG_LENGTH);
      break;
    }

    // If there is a remainder from the last time this method was called, append it to the begging
    // of the first rule.
    if (strlen(remainder) > 0) {
      strcat(remainder, input_string_log);
      input_string_log = remainder;
    }
    sscanf(input_string_log,
        "%lu %u %u %u %u %u %hu %hu %d %u\n",
        &log.timestamp,
        &protocol,
        &action,
        &hooknum,
        &log.src_ip,
        &log.dst_ip,
        &log.src_port,
        &log.dst_port,
        &log.reason,
        &log.count);

    log.protocol = (char) protocol;
    log.action = (char) action;
    log.hooknum = (char) hooknum;

    remainder[0] = 0; // Truncate remainder.

    parse_string_from_log(log, output_string_log);
    strcat(output, output_string_log);
  }
  return strlen(output);
}

/**
 * Receives a buffer with string connections in the raw kernel format, and return a buffer with
 * string connections in user readable format.
 *
 * The remainder uses in case we read only a part of a string. This can happen because if the buffer
 * got full before we finished to read the string. Thus we need to wait to the other part of the
 * string before starting to parse it.
 *  - If the remainder length is not 0 add it before the begging of the first string.
 *  - If the last string didn't end with \n return it in the remainder buffer.
 */
int connections_kernel_format_to_user_format(char *input, char *output, char* remainder) {
  connections_list_entry conn;
  char* input_string_connection;
  char output_string_connection[300];
  unsigned int protocol;
  output[0] = 0;
  while (input != NULL && strlen(input_string_connection = strsep(&input, "\n")) > 0) {

    // The input is terminated, but the input_string length > 0. That means that the current
    // connection didn't end with \n. That means that we didn't read it until the end. Therefore we
    // will save the remainder to the next read iteration.
    if (input == NULL) {
      strncpy(remainder, input_string_connection, MAX_USER_FORMAT_CONNECTION_STRING_LENGTH);
      break;
    }

    // If there is a remainder from the last time this method was called, append it to the begging
    // of the first rule.
    if (strlen(remainder) > 0) {
      strcat(remainder, input_string_connection);
      input_string_connection = remainder;
    }
    sscanf(input_string_connection,
        "%u %hu %u %hu %u %u %u\n",
        &conn.src_ip,
        &conn.src_port,
        &conn.dst_ip,
        &conn.dst_port,
        &protocol,
        &conn.tcp_state,
        &conn.protocol_state);
    conn.protocol = (char) protocol;

    remainder[0] = 0; // Truncate remainder.

    parse_string_from_connection(conn, output_string_connection);
    strcat(output, output_string_connection);
  }
  return strlen(output);
}

