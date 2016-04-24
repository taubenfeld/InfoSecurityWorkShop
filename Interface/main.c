
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/kernel.h>
#include <string.h>
#include <assert.h>
#include "parser.h"

#define PAGE_SIZE (4096)
#define RULES_SYSFS_LOAD_STORE_DRIVER_PATH "/sys/class/fw/fw_rules/rules_load_store"
#define RULES_SYSFS_CLEAR_DRIVER_PATH "/sys/class/fw/fw_rules/rules_clear"
#define RULES_SYSFS_ACTIVE_DRIVER_PATH "/sys/class/fw/fw_rules/active"
#define LOG_SYSFS_CLEAR_DRIVER_PATH "/sys/class/fw/fw_log/log_clear"
#define LOG_DEV_DRIVER_PATH "/dev/fw_log"

#define STATUS_NOT_ACTIVE '0'
#define STATUS_ACTIVE '1'

int show_rules() {
  int driver_file_desc;
  int length;
  char rules_kernel_space_format[PAGE_SIZE + 1] = {0};
  char rules_user_space_format[PAGE_SIZE * 10] = {0};

  driver_file_desc = open(RULES_SYSFS_LOAD_STORE_DRIVER_PATH, O_RDONLY);
  if(driver_file_desc < 0) {
    printf("Unable to open driver.\n");
    return 1;
  }
  length = read(driver_file_desc, &rules_kernel_space_format, PAGE_SIZE);
  if (length < 0) {
    printf("Error while reading from driver.");
  }
  // Print exactly the number of bytes we have read.
  // .* takes the length and add it before s.
  length = rules_kernel_format_to_user_format(rules_kernel_space_format, rules_user_space_format);
  printf("%.*s", length, rules_user_space_format);
  close(driver_file_desc);
  printf("Done getting rules.\n");
  return 0;
}

int load_rules(const char *rules_file_path) {
  FILE *user_file;
  int driver_file_desc;
  int length;
  int return_status = 0;
  char rules_kernel_space_format[PAGE_SIZE + 1] = {0};
  char rules_user_space_format[PAGE_SIZE * 10 + 1] = {0};

  user_file = fopen(rules_file_path, "r");
  if(user_file == NULL) {
    printf("Unable to open logs driver: %s.\n", strerror(errno));
    return 1;
  }

  length = fread(rules_user_space_format, 1, PAGE_SIZE * 10 , user_file);
  fclose(user_file);
  if (length < 0) {
    printf("Error while reading rules file\n.");
  }
  else if (length > PAGE_SIZE) {
    printf("Rules size is too big\n.");
  }
  else {
    if (rules_user_format_to_kernel_format(
        rules_user_space_format, rules_kernel_space_format) < 0) {
      printf("Invalid rules format.\n");
    };
    driver_file_desc = open(RULES_SYSFS_LOAD_STORE_DRIVER_PATH, O_WRONLY);
    if(driver_file_desc < 0) {
      printf("Unable to open logs driver: %s.\n", strerror(errno));
      return 1;
    }
    return_status = write(driver_file_desc, rules_kernel_space_format, length);
  }
  close(driver_file_desc);
  printf("Done loading rules.\n");
  return return_status;
}

int show_log() {
  int driver_file_desc;
  int length;
  char logs_kernel_space_format[PAGE_SIZE + 1] = {0};
  char logs_user_space_format[PAGE_SIZE * 10] = {0};
  char remainder[MAX_USER_FORMAT_LOG_LENGTH] = {0};
  // Print the title.
  printf("%-30s %-20s %-20s %-10s %-10s %-10s %-10s %-10s %-30s %-10s\n",
      "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "hooknum", "action",
      "reason", "count");

  driver_file_desc = open(LOG_DEV_DRIVER_PATH, O_RDONLY);
  if(driver_file_desc < 0) {
    printf("Unable to open logs driver: %s.\n", strerror(errno));
    return -1;
  }
  while ((length =
      read(driver_file_desc, logs_kernel_space_format, PAGE_SIZE)) > 0) {
    logs_kernel_format_to_user_format(logs_kernel_space_format, logs_user_space_format, remainder);
    printf("%s", (logs_user_space_format));
  }
  close(driver_file_desc);
  printf("Done getting rules.\n");
  return 0;
}

/*
 * Writes 1 to the device path. This should clear the device for both the rules device and the log
 * device.
 */
int clear_device(char *path) {
  int filedesc = open(path, O_WRONLY);
  if (filedesc < 0) {
    return -1;
  }
  char c = '1';
  write(filedesc, &c, 1);
  close(filedesc);
  printf("Device cleared.\n");
  return 0;
}

/*
 * Activates/Reactivates the fire wall.
 */
int fw_activate_deactivate(char status) {
  int filedesc = open(RULES_SYSFS_ACTIVE_DRIVER_PATH, O_WRONLY);
  if (filedesc < 0) {
    return -1;
  }
  write(filedesc, &status, 1);
  close(filedesc);
  if (status == STATUS_ACTIVE){
    printf("Device active.\n");
  } else {
    printf("Device not active.\n");
  }
  return 0;
}

int main(int argc, char **argv) {

	if(argc < 2) {
	  printf("ERROR: User must specify argument.\n");
	  return -1;
	}

  if (strcmp(argv[1], "show_rules") == 0) {
    return show_rules();
  }
  if (strcmp(argv[1], "load_rules") == 0) {
    if(argc != 3) {
      printf("ERROR: User must specify path to rules file.\n");
      return -1;
    }
    return load_rules(argv[2]);
  }
  if (strcmp(argv[1], "show_log") == 0) {
    return show_log();
  }
  if (strcmp(argv[1], "clear_log") == 0) {
    return clear_device(LOG_SYSFS_CLEAR_DRIVER_PATH);
  }
  if (strcmp(argv[1], "clear_rules") == 0) {
    return clear_device(RULES_SYSFS_CLEAR_DRIVER_PATH);
  }
  if (strcmp(argv[1], "activate") == 0) {
    return fw_activate_deactivate(STATUS_ACTIVE);
  }
  if (strcmp(argv[1], "deactivate") == 0) {
    return fw_activate_deactivate(STATUS_NOT_ACTIVE);
  }

  printf("ERROR: Unrecognized command.\n");
  return -1;
}
