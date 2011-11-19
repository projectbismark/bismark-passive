#ifndef _BISMARK_PASSIVE_DEVICE_THROUGHPUT_TABLE_H
#define _BISMARK_PASSIVE_DEVICE_THROUGHPUT_TABLE_H

#include <net/ethernet.h>
#include <stdint.h>
#include <stdio.h>

#include "constants.h"

typedef struct {
  uint8_t mac_address[ETH_ALEN];
  uint32_t bytes_transferred;
} device_throughput_table_entry_t;

typedef struct {
  device_throughput_table_entry_t entries[DEVICE_THROUGHPUT_TABLE_SIZE];
  int length;
} device_throughput_table_t;

void device_throughput_table_init(device_throughput_table_t* const table);

int device_throughput_table_record(device_throughput_table_t* const table,
                                   const uint8_t mac[ETH_ALEN],
                                   const uint32_t bytes_transferred);

int device_throughput_table_write_update(device_throughput_table_t* const table,
                                         FILE* handle);

#endif
