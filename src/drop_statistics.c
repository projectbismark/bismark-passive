#include "drop_statistics.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

void drop_statistics_init(drop_statistics_t* drop_statistics) {
  memset(drop_statistics, '\0', sizeof(drop_statistics));
}

void drop_statistics_process_packet(drop_statistics_t* drop_statistics,
                                    uint32_t size) {
  if (size > DROP_STATISTICS_MAXIMUM_PACKET_SIZE) {
    size = DROP_STATISTICS_MAXIMUM_PACKET_SIZE;
  }
  ++drop_statistics->packet_sizes[size];
}

int drop_statistics_write_update(drop_statistics_t* const drop_statistics,
                                 gzFile handle) {
  uint32_t idx;
  for (idx = 0; idx < DROP_STATISTICS_MAXIMUM_PACKET_SIZE; ++idx) {
    if (drop_statistics->packet_sizes[idx] > 0) {
      if (gzprintf(handle,
                   "%" PRIu32 " %" PRIu32 "\n",
                   idx,
                   drop_statistics->packet_sizes[idx]) < 0) {
#ifndef NDEBUG
        perror("Error sending update");
#endif
        return -1;
      }
    }
  }
  return 0;
}
