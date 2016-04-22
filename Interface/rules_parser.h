#ifndef _RULES_PARSER_
#define _RULES_PARSER_


#include <stdio.h>
#include <stdlib.h>


#define NF_DROP 0
#define NF_ACCEPT 1

// the protocols we will work with
typedef enum {
  PROT_ICMP = 1,
  PROT_TCP  = 6,
  PROT_UDP  = 17,
  PROT_OTHER  = 255,
  PROT_ANY  = 143,
} prot_t;


// various reasons to be registered in each log entry
typedef enum {
  REASON_FW_INACTIVE           = -1,
  REASON_NO_MATCHING_RULE      = -2,
  REASON_XMAS_PACKET           = -4,
  REASON_ILLEGAL_VALUE         = -6,
} reason_t;


// auxiliary strings, for your convenience
#define DEVICE_NAME_RULES         "rules"
#define DEVICE_NAME_LOG           "log"
#define DEVICE_NAME_CONN_TAB      "conn_tab"
#define CLASS_NAME                "fw"
#define LOOPBACK_NET_DEVICE_NAME  "lo"
#define IN_NET_DEVICE_NAME        "eth1"
#define OUT_NET_DEVICE_NAME       "eth2"

// auxiliary values, for your convenience
#define IP_VERSION        (4)
#define PORT_ANY          (0)
#define PORT_ABOVE_1023   (1023)
#define MAX_RULES         (50)

// device minor numbers, for your convenience
typedef enum {
  MINOR_RULES    = 0,
  MINOR_LOG      = 1,
} minor_t;

typedef enum {
  ACK_NO    = 0x01,
  ACK_YES   = 0x02,
  ACK_ANY   = ACK_NO | ACK_YES,
} ack_t;

typedef enum {
  DIRECTION_IN    = 0x01,
  DIRECTION_OUT   = 0x02,
  DIRECTION_ANY   = DIRECTION_IN | DIRECTION_OUT,
} direction_t;

// rule base
typedef struct {
  char rule_name[20];       // names will be no longer than 20 chars
  direction_t direction;
  unsigned int  src_ip;
  unsigned int  src_prefix_mask;               // e.g., 255.255.255.0 as int in the local endianness
  unsigned char    src_prefix_size;          // valid values: 0-32, e.g., /24 for the example above
                                            // (the field is redundant - easier to print)
  unsigned int  dst_ip;
  unsigned int  dst_prefix_mask;       // as above
  unsigned char    dst_prefix_size;   // as above
  unsigned short  src_port;           // number of port or 0 for any or port 1023 for any port number > 1023
  unsigned short  dst_port;           // number of port or 0 for any or port 1023 for any port number > 1023
  unsigned char  protocol;             // values from: prot_t
  ack_t ack;                          // values from: ack_t
  unsigned char  action;             // valid values: NF_ACCEPT, NF_DROP
} rule_t;


/***************************************************************************************************
 * Functions
***************************************************************************************************/

/*
 * Gets the direction enum value by string value.
 * Returns 0 on failure.
 */
direction_t get_direction_from_string(char *direction_str);

/*
 * Gets string representation of the direction enum.
 * Returns NULL on failure.
 */
char *get_string_from_direction(direction_t direction);

/*
 * Gets the protocol enum value by string value.
 * Returns 0 on failure.
 */
prot_t get_protocol_from_string(char *protocol);

/*
 * Gets string representation of the protocol enum.
 * Returns NULL on failure.
 */
char *get_string_from_protocol(prot_t protocol);

/*
 * Gets the ack enum value by string value.
 * Returns 0 on failure.
 */
ack_t get_ack_from_string(char *ack);

/*
 * Gets string representation of the ack enum.
 * Returns NULL on failure.
 */
char *get_string_from_ack(ack_t ack);
/*
 * Get Netfiler's action value from string value.
 */
int get_action_from_string(char *action);

/*
 * Get Netfiler's action value from string value.
 */
char *get_string_from_action(int action);
/*
 * Parse the port from string to int.
 * Returns 0 on failure.
 */
int parse_port_from_string(char *str_port);
/*
 * Parse the port from int to string.
 * Returns 0 on failure.
 */
void parse_string_from_port(int port, char target_str_port[]);

/*
 * Parse IP base & mask.
 * Returns 0 on failure.
 */
int parse_ips_from_string(char *full_ip_string, unsigned int *ip_base, unsigned char *mask_size);
/*
 * Function that convert int IP to dot notation string IP.
 * I took this function from: http://stackoverflow.com/questions/1680365/integer-to-ip-address-c.
 */
void int_ip_to_dot_ip(int ip, char str_ip[]);
/*
 * Parse a rule_t from a given string. On error returns 0.
 * The caller function is responsible of freeing the returned pointer.
 */
rule_t *parse_rule_from_string(char* str_rule);
/*
 * Parse a given rule into a string, and writes it to the buffer.
 */
int parse_string_from_rule(rule_t rule, char *buffer);

/*
 * Receives a buffer with rules in the raw kernel format, and return a buffer with rules in user
 * Readable format.
 */
ssize_t rules_kernel_format_to_user_format(char *input, char *output);

/*
 * Receives a buffer with rules in the user format, and return the rules raw format that is ready
 * to be delivered to the kernel.
 * The rules are validated and in case of an -1 is returned.
 */
ssize_t rules_user_format_to_kernel_format(char *input, char *output);



#endif // _RULES_PARSER_
