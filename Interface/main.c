
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/kernel.h>
#include <string.h>
#include <assert.h>


static char RULES_DRIVER_PATH[] = "/sys/class/fw_class/fw_rules/rules_load_store";

int main(int argc, char **argv) {
	int driver_file_desc;
	FILE *other_file_desc;
	int length;
	int return_status = 0;
	unsigned short num_of_lines = 0;
	char buff[4000] = {0};
	char ch;

	if(argc < 2) {
	  printf("ERROR: User must specify argument.\n");
	  return -1;
	}

  if (strcmp(argv[1], "show_rules") == 0) {
    driver_file_desc = open(RULES_DRIVER_PATH, O_RDONLY);
    if(driver_file_desc < 0) {
      printf("Unable to open driver.\n");
      return 1;
    }
    length = read(driver_file_desc, &buff, sizeof(buff));
    if (length < 0) {
      printf("Error while reading from driver.");
    }
    // Print exactly the number of bytes we have read.
    // .* takes the length and add it before s.
    printf("%.*s", length, buff);
    close(driver_file_desc);
    return 0;
  }

  if (strcmp(argv[1], "load_rules") == 0) {
    if(argc != 3) {
      printf("ERROR: User must specify path to rules file.\n");
      return -1;
    }

    other_file_desc = fopen(argv[2], "r");
    if(other_file_desc == NULL) {
      printf("Unable to open rules file.\n");
      return 1;
    }

    driver_file_desc = open(RULES_DRIVER_PATH, O_WRONLY);
    if(driver_file_desc < 0) {
      fclose(other_file_desc);
      printf("Unable to open driver.\n");
      return 1;
    }

    // Count how many rules the file contains. The number of rules will be passed to the driver.
    while(!feof(other_file_desc)) {
      ch = fgetc(other_file_desc);
      if(ch == '\n') {
        num_of_lines++;
      }
    }
    fseek(other_file_desc, SEEK_SET, 0);
    sprintf(buff, "%hu", num_of_lines);
    length = fread(buff + sizeof(num_of_lines) /* Append file content after the number of rules*/,
        1, sizeof(buff) - sizeof(num_of_lines), other_file_desc);
    if (length > 0) {
      return_status = write(driver_file_desc, buff, length+1);
    }
	  close(driver_file_desc);
	  fclose(other_file_desc);
	  return return_status;
  }
  printf("ERROR: Unrecognized command.\n");
  return -1;
}



	// Rule structure:
  // <rule_name> <direction> <Source_IP>/<nps> <Dest_IP>/<nps> <protocol> <Source_port> <Dest_port> <ack> <action>

//while((length = read(filedesc, &buff, sizeof(buff))) > 0) {
//  // Print exactly the number of bytes we have read.
//  printf("%.*s", length, buff);
//}
