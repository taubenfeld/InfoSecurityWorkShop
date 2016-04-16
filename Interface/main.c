
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>


static char drive_path[] = "/dev/sysfs_class_sysfs_Device";

int main(int argc, char **argv) {
	int filedesc, length;
	char buff[1000] = {0};

  // User didn't pass any parameters. Perform read opreation.
  if (argc == 1) {
	  filedesc = open(drive_path, O_RDONLY);
	  if(filedesc < 0) {
	    printf("Unable to open driver.\n");
	    return 1;
	  }
	  while((length = read(filedesc, &buff, sizeof(buff))) > 0) {
	  	// Print exactly the number of bytes we have read.
	    printf("%.*s", length, buff);
	  }
	  close(filedesc);
	  return 0;
  }

  // User pass 0 in the first argument. Perform write operation.
  if (argc == 2 && atoi(argv[1]) == 0) {
    filedesc = open(drive_path, O_WRONLY);
	  char c = '1';
	  write(filedesc, &c, 1);
	  close(filedesc);
	  return 0;
  }

  // User passed more than 1 argument, or the first argument wasn't 0. Print error.
  printf("Error. Usage: user_interface arg(Optional. Pass 0 to write)\n");
  return 1;


	// Rule structure:
  // <rule_name> <direction> <Source_IP>/<nps> <Dest_IP>/<nps> <protocol> <Source_port> <Dest_port> <ack> <action>

}
