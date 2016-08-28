
#ifndef STATEFUL_H_
#define STATEFUL_H_

#include "fw.h"
#include "dlp.h"
#include "photo_gallery_patch.h"
#include "custom_contact_form_patch.h"

#define MAX_ACCUMULATED_PAYLOAD 300
typedef enum {
  TCP_ESTABLISH   = 1,
  FTP_CONNECTED     = 2,
  FTP_TERMINATED    = 3,
} protocol_state;


typedef enum {
  SENT_SYN_WAIT_SYNACK   = 1,
  SENT_SYNACK_WAIT_ACK   = 2,
  ESTABLISHED            = 3,
  SENT_FIN_WAIT_FIN2     = 4,
  SENT_FIN2_WAIT_ACK     = 5,
} tcp_state;

typedef enum {
  HTTP  = 1,
  FTP   = 2,
  SMTP  = 3,
  OTHER = 7,
} application_layer_protocol;

typedef struct {
  __be32          src_ip;
  __be16          src_port;
  __be32          dst_ip;
  __be16          dst_port;
  __u8            protocol;         // values from: application_layer_protocol
  tcp_state       tcp_state;
  char            payload[MAX_ACCUMULATED_PAYLOAD]; // Uses in fragmenation. 300 is a reasonable max len for payload.
  protocol_state  protocol_state;
  unsigned long   timestamp;
  struct list_head list;          /* kernel's list structure */
} connections_list_entry;

typedef struct {
  char *host_name;
  struct list_head list;
} hosts_list_entry;

/*
 * The size of each field in the connection entry when printing it.
 */
#define SIZE_OF_FIELD_BUFFER 20
#define NUMBER_OF_FIELDS 8
#define ROW_SIZE_AS_STRING SIZE_OF_FIELD_BUFFER * NUMBER_OF_FIELDS

int register_connections_driver(struct class* fw_sysfs_class);

int remove_connections_device(struct class* fw_sysfs_class);

int validate_and_update_tcp_connection(struct sk_buff *skb, rule_t rule, reason_t *reason);

int ftp_initial_verification(rule_t rule, reason_t *reason);

#endif /* STATEFUL_H_ */
