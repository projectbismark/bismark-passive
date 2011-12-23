#include "http_table.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "anonymization.h"
#include "util.h"

void http_table_init(http_table_t* http_table) {
  memset(http_table, '\0', sizeof(*http_table));
}

void http_table_destroy(http_table_t* const http_table) {
  int idx;
  for (idx = 0; idx < http_table->length; ++idx) {
    free(http_table->entries[idx].url);
  }
}

int http_table_add_url(http_table_t* const http_table,
                    http_url_entry* const new_entry) {
  if (http_table->length >= HTTP_TABLE_URL_ENTRIES) {
    ++http_table->num_dropped_url_entries;
    return -1;
  }
#ifndef DISABLE_ANONYMIZATION
    new_entry->unanonymized = 1;
#endif
  http_table->entries[http_table->length] = *new_entry;
  ++http_table->length;
  return 0;
}

int http_table_write_update(http_table_t* const http_table, gzFile handle) {
  if (!gzprintf(handle,
                "%d \n",
                http_table->num_dropped_url_entries)){
    perror("Error writing update");
    return -1;
  }
  int idx;
  for (idx = 0; idx < http_table->length; ++idx) {
#ifndef DISABLE_ANONYMIZATION
    if (http_table->entries[idx].unanonymized) {
#endif
      if (!gzprintf(handle,
                    "%" PRIu16 " 0 %s \n",
                    http_table->entries[idx].flow_id,
                    http_table->entries[idx].url)) {
        perror("Error writing update");
        return -1;
      }
#ifndef DISABLE_ANONYMIZATION
    } else {
      unsigned char url_digest[ANONYMIZATION_DIGEST_LENGTH];
      if (anonymize_url(http_table->entries[idx].url, url_digest)){
        fprintf(stderr, "Error anonymizing URLs\n");
        return -1;
      }
      if (!gzprintf(handle,
            "%" PRIu16 " 1 %s\n",
            http_table->entries[idx].flow_id,
            buffer_to_hex(url_digest, ANONYMIZATION_DIGEST_LENGTH))) {
        perror("Error writing update");
        return -1;
      }
    }
#endif
  }
  if (!gzprintf(handle, "\n")) {
    perror("Error writing update");
    return -1;
  }

  return 0;
}
