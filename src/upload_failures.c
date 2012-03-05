#include "upload_failures.h"

#include <stdio.h>
#include <string.h>

static char format_string[256];  /* 256 is arbitrary. */

static int read_failures(const char* filename) {
  FILE* handle = fopen(filename, "r");
  if (handle == NULL) {
    perror("fopen");
    return -1;
  }

  char directory[FILENAME_MAX + 1];
  int num_failures;
  while (!feof(handle)) {
    fscanf(handle, format_string, directory, &num_failures);
    if (ferror(handle)) {
      perror("fscanf");
      break;
    }
    if (!strcmp(directory, "passive")) {
      fclose(handle);
      return num_failures;
    }
  }
  fclose(handle);
  return -1;
}

void upload_failures_init(upload_failures_t* failures, const char* filename) {
  failures->filename = filename;
  failures->valid = 0;

  snprintf(format_string, sizeof(format_string), "%%%ds %%d\n", FILENAME_MAX);
}

int upload_failures_check(upload_failures_t* failures) {
  int num_failures = read_failures(failures->filename);
  if (num_failures < 0) {
    return -1;
  } else if (!failures->valid) {
    failures->num_failures = num_failures;
    failures->valid = 1;
    return 0;
  } else if (failures->num_failures != num_failures) {
    failures->num_failures = num_failures;
    return 1;
  } else {
    return 0;
  }
}
