#ifndef _BISMARK_PASSIVE_UPLOAD_FAILURES_H_
#define _BISMARK_PASSIVE_UPLOAD_FAILURES_H_

typedef struct {
  const char* filename;
  int num_failures;
  int valid;
} upload_failures_t;

void upload_failures_init(upload_failures_t* failures, const char* filename);
int upload_failures_check(upload_failures_t* failures);

#endif
