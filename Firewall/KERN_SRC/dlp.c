
#include "dlp.h"

#define PASSED 0
#define FAILED 1


char *skip_whitespace(char *data) {
  while(data[0] != '\0' && isspace(data[0])) {
    data++;
  }
  return data;
}

char *skip_to_closing_brackets(
    char *data, char open_bracket_type, char closing_bracket_type) {
  int bracketConut = 1; // Starts after the first open bracket.

  while (data[0] != '\0') {
    if (bracketConut == 0) {
      return data;
    }

    if (data[0] == open_bracket_type) {
      bracketConut++;
    } else if (data[0] == closing_bracket_type) {
      bracketConut--;
    }
    data++;
  }

  return data;
}

/**
 * Tests if the data contains the pattern.
 */
int contains_pattern(const char *data, const char *pattern) {
  if (strstr(data, pattern) != NULL) {
    printk(KERN_INFO "Contains %s\n.", pattern);
    return FAILED;
  }
  return PASSED;
}

/**
 * Tests if the data contains the regex: [keyword]\((.)*\)( )*\{
 * In word: checks if the code contains "keyword" "white spaces" "open bracket"
 * "anything" "closing brackets" "white spaces" "open curly brackets.
 */
int contains_statement(const char *data, const char *keyword) {

  char *head = strstr(data, keyword);
  if (head == NULL) {
    return PASSED;
  }

  while (head != NULL) {
    head += strlen(keyword); // Jump over the keyword;
    head = skip_whitespace(head);
    if (head[0] == '(') { // The open bracket should appear immediately after the whitespace.
      head += 1; // Skip '('
      head = skip_to_closing_brackets(head, '(', ')');
      head = skip_whitespace(head);
      if (head[0] == '{') { // The open curly brackets should appear immediately after whitespace.
        printk(KERN_INFO "--------------------------------------------------------");
        printk(KERN_INFO "Contains %s\n.", keyword);
        printk(KERN_INFO "DATA %s\n.", data);
        printk(KERN_INFO "HEAD %s\n.", data);
        printk(KERN_INFO "--------------------------------------------------------");
        return FAILED;
      }
    }

    head = strstr(head, keyword);
  }

  return PASSED;
}

int run_dlp(const char *data) {
  if (contains_pattern(data, "typedef enum")
      || contains_pattern(data, "typedef struct")
      || contains_pattern(data, "int main ()")
      || contains_pattern(data, "#include")
      || contains_statement(data, "for")
      || contains_statement(data, "while")
      || contains_statement(data, "if")) {
    return FAILED;
  }
  return PASSED;
}
