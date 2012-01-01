#ifndef _BISMARK_PASSIVE_HTTP_TABLE_H_
#define _BISMARK_PASSIVE_HTTP_TABLE_H_

#include <stdint.h>
#include <stdio.h>
#include <zlib.h>

#include "constants.h"
#include "flow_table.h"

//domain_name -> url
//num_dropped_a_entries -> num_dropped_url_entries

typedef struct {
  uint16_t flow_id;
  unsigned char *url;
} http_url_entry;
            
typedef struct {

  http_url_entry entries[HTTP_TABLE_URL_ENTRIES];
  int length;
  int num_dropped_url_entries;
} http_table_t;

/* whitelist can be NULL, in which case no whitelist is performed. Does not
 * claim ownership of the whitelist. */
void http_table_init(http_table_t* const http_table);

/* You *must* call this before a table goes out of scope, since tables contain
 * malloced strings that must be freed. */
void http_table_destroy(http_table_t* const http_table);

/* Add a new retrieved URL to the table. Claims ownership of entry->domain_name
 * and will free() at some later point. Does *not* claim ownership of entry. */
int http_table_add_url(http_table_t* const http_table, http_url_entry* const entry);

/* Serialize all table data to an open gzFile handle. */
int http_table_write_update(http_table_t* const http_table, gzFile handle);

#endif
