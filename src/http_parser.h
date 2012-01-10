#ifndef _BISMARK_PASSIVE_HTTP_PARSER_
#define _BISMARK_PASSIVE_HTTP_PARSER_

#include <stdint.h>

#include "http_table.h"

/* Parse a HTTP request packet and add relevent entries to the provided HTTP
 * table. */
int process_http_packet(const uint8_t* const bytes,
                       int len, 
                       http_table_t* const http_table,
                       uint16_t flow_id);

#endif
