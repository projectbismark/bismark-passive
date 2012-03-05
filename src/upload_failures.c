#include "upload_failures.h"

#include <stdio.h>

static int read_failures(const char* filename) {
  FILE* handle = fopen(filename, "r");
  if (handle == NULL) {
    perror("fopen");
    return -1;
  }

  int num_failures;
  while (!feof(handle)) {
    if (fscanf(handle, "passive %d\n", &num_failures) == 1) {
      fclose(handle);
      return num_failures;
    }
    if (ferror(handle)) {
      perror("fscanf");
      break;
    }
  }
  fclose(handle);
  return -1;
}

void upload_failures_init(upload_failures_t* failures, const char* filename) {
  int num_failures = read_failures(filename);
  if (num_failures < 0) {
    failures->filename = NULL;
  } else {
    failures->filename = filename;
    failures->num_failures = num_failures;
  }
}

int upload_failures_check(upload_failures_t* failures) {
  if (failures->filename == NULL) {
    return -1;
  }
  int num_failures = read_failures(failures->filename);
  if (num_failures < 0) {
    return -1;
  } else if (num_failures != failures->num_failures) {
    failures->num_failures = num_failures;
    return 1;
  } else {
    return 0;
  }
}
