#include "device_throughput_table.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "anonymization.h"
#include "util.h"

void device_throughput_table_init(device_throughput_table_t* const table) {
  table->length = 0;
}

int device_throughput_table_record(device_throughput_table_t* const table,
                                   const uint8_t mac_address[ETH_ALEN],
                                   const uint32_t bytes_transferred) {
  int idx;
  for (idx = 0; idx < table->length; ++idx) {
    if (memcmp(table->entries[idx].mac_address, mac_address, ETH_ALEN) == 0) {
      table->entries[idx].bytes_transferred += bytes_transferred;
      return 0;
    }
  }

  if (table->length >= DEVICE_THROUGHPUT_TABLE_SIZE) {
    return -1;
  }

  memcpy(table->entries[table->length].mac_address, mac_address, ETH_ALEN);
  table->entries[table->length].bytes_transferred = bytes_transferred;
  ++table->length;
  return 0;
}

int device_throughput_table_write_update(device_throughput_table_t* const table,
                                         FILE* handle) {
  if (fprintf(handle, "%d\n", table->length) < 0) {
    perror("Error writing update");
    return -1;
  }

  int idx;
  for (idx = 0; idx < table->length; ++idx) {
#ifndef DISABLE_ANONYMIZATION
    uint8_t digest_mac[ETH_ALEN];
    if (anonymize_mac(table->entries[idx].mac_address, digest_mac)) {
      fprintf(stderr, "Error anonymizing MAC address\n");
      return -1;
    }
    if (fprintf(handle,
                "%s %" PRId32 "\n",
                buffer_to_hex(digest_mac, ETH_ALEN),
                table->entries[idx].bytes_transferred) < 0) {
#else
    if (fprintf(handle,
                "%s %" PRId32 "\n",
                buffer_to_hex(table->entries[idx].mac_address, ETH_ALEN),
                table->entries[idx].bytes_transferred) < 0) {
#endif
      perror("Error writing update");
      return -1;
    }
  }
  if (fprintf(handle, "\n") < 0) {
    perror("Error writing update");
    return -1;
  }
  return 0;
}
