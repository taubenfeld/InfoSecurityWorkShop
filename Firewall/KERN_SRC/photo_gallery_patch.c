
#include "photo_gallery_patch.h"

#define PASSED 0
#define FAILED 1

int contains(const char *data, const char *pattern) {
  if (strstr(data, pattern) != NULL) {
//    printk(KERN_INFO "Contains %s\n.", pattern);
    return FAILED;
  }
  return PASSED;
}

int contains_zip(const char *data) {
  const char *filename_pattern = "filename=\"";
  char *end_of_file_name, *zip_extension, *head;

  head = strstr(data, filename_pattern);
  if (head == NULL) {
    return PASSED;
  }

  while (head != NULL) {
    head += strlen(filename_pattern); // Jump over the keyword;

    end_of_file_name = strstr(head, "\"");
    zip_extension = strstr(head, ".zip");

    if (end_of_file_name == NULL || zip_extension == NULL) {
      return PASSED;
    } else if (zip_extension < end_of_file_name) {
      return FAILED; // The file name contain .zip extension (it must appear before the \").
    }
    // Check if there is another file name pattern. This is an extra security.
    head = strstr(head, filename_pattern);
  }

  return PASSED;
}

int run_photo_gallery_patch(const char *data) {
//  printk(KERN_INFO "----------------------------\n"
//                   "   Running photo gallery patch on: %s\n."
//                   "----------------------------\n", data);
  if (contains(data, "action=bwg_UploadHandler")
      && contains_zip(data)) {
    return FAILED;
  }

  return PASSED;
}
