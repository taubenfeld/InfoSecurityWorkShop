
#include "photo_gallery_patch.h"

#define PASSED 0
#define FAILED 1

int contains_text(const char *data, const char *pattern) {
  if (strstr(data, pattern) != NULL) {
//    printk(KERN_INFO "Contains %s\n.", pattern);
    return FAILED;
  }
  return PASSED;
}

int run_custom_contact_form_patch(const char *data) {
//  printk(KERN_INFO "----------------------------\n"
//                   "   Running custom contact form on: %s\n."
//                   "----------------------------\n", data);
  if (contains_text(data, "ccf_export")
      || contains_text(data, "ccf_export_all_csv")
      || contains_text(data, "ccf_clear_import")) {
    return FAILED;
  }

  return PASSED;
}
