#ifndef _BISMARK_PASSIVE_DROP_STATISTICS_H_
#define _BISMARK_PASSIVE_DROP_STATISTICS_H_

#include <stdint.h>
#include <zlib.h>

#include "constants.h"

typedef struct {
  uint32_t packet_sizes[DROP_STATISTICS_MAXIMUM_PACKET_SIZE + 1];
} drop_statistics_t;

void drop_statistics_init(drop_statistics_t* drop_statistics);

void drop_statistics_process_packet(drop_statistics_t* drop_statistics,
                                    uint32_t packet_size);

int drop_statistics_write_update(drop_statistics_t* const drop_statistics,
                                 gzFile handle);

#endif
