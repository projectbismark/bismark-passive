#ifndef _BISMARK_PASSIVE_CONSTANTS_H_
#define _BISMARK_PASSIVE_CONSTANTS_H_

#include <stdint.h>

/* Uncomment to disable debug messages */
/*#define NDEBUG*/

/* Defining this variable disables anonymization. Don't uncomment this
 * line. Instead, pass DISABLE_ANONYMIZATION=yes as a Makefile argument. */
/*#define DISABLE_ANONYMIZATION*/

/* Defining this variable disables flow-level threshold accounting. This feature
 * counts the number of packets per flow during the first update period of that
 * flow; if the flow exceeds FLOW_THRESHOLD packets during that period then its
 * source and destination IP addresses are written to FLOW_THRESHOLDING_LOG. */
/*#define DISABLE_FLOW_THRESHOLDING*/

#define FILE_FORMAT_VERSION 2
#define FREQUENT_FILE_FORMAT_VERSION 1
#ifndef BUILD_ID
#define BUILD_ID "UNKNOWN"
#endif

/* Max is 65536, unless you modify dns_table.h */
#define PACKET_DATA_BUFFER_ENTRIES 65536

/* Last few indices of flow table reserved for alternate network protocols. */
enum reserved_flow_indices {
  FLOW_ID_ERROR,
  FLOW_ID_AARP,
  FLOW_ID_ARP,
  FLOW_ID_AT,
  FLOW_ID_IPV6,
  FLOW_ID_IPX,
  FLOW_ID_REVARP,
  FLOW_ID_FIRST_UNRESERVED,
  FLOW_ID_LAST_UNRESERVED = 65535
};
/* IMPORTANT: FLOW_TABLE_ENTRIES <= min(FLOW_ID_*) */
#define FLOW_TABLE_ENTRIES (FLOW_ID_LAST_UNRESERVED - FLOW_ID_FIRST_UNRESERVED + 1)

#define DNS_TABLE_A_ENTRIES 1024
#define DNS_TABLE_CNAME_ENTRIES 1024
#define MAC_TABLE_ENTRIES 256

/* Flows older than this are eligable for expiration. */
#define FLOW_TABLE_EXPIRATION_SECONDS (30 * 60)
/* Flows that are this many seconds newer than the base timestamp will be
 * expired to prevent timestamp inaccuracy. */
#define FLOW_TABLE_MAX_UPDATE_OFFSET INT16_MAX
/* Flows that are this many seconds older than the base timestamp will be
 * expired to prevent timestamp inaccuracy. */
#define FLOW_TABLE_MIN_UPDATE_OFFSET INT16_MIN

/* Generate differential updates this often. */
#ifndef UPDATE_PERIOD_SECONDS
#define UPDATE_PERIOD_SECONDS 30
#endif
#ifndef FREQUENT_UPDATE_PERIOD_SECONDS
#define FREQUENT_UPDATE_PERIOD_SECONDS 15
#endif
#define PENDING_UPDATE_FILENAME "/tmp/bismark-passive/current-update.gz"
#define PENDING_FREQUENT_UPDATE_FILENAME "/tmp/bismark-passive/current-frequent-update"
#define UPDATE_FILENAME "/tmp/bismark-passive/updates/%s-%" PRIu64 "-%d.gz"
#define FREQUENT_UPDATE_FILENAME "/tmp/bismark-passive/frequent-updates/%s-%" PRIu64 "-%d"

#ifndef BISMARK_ID_FILENAME
#define BISMARK_ID_FILENAME "/etc/bismark/ID"
#endif

#define ANONYMIZATION_SEED_LEN 16
#ifndef ANONYMIZATION_SEED_FILE
#define ANONYMIZATION_SEED_FILE "/etc/bismark/passive.key"
#endif

#ifndef DOMAIN_WHITELIST_FILENAME
#define DOMAIN_WHITELIST_FILENAME "/etc/bismark/domain-whitelist.txt"
#endif
#define DEFAULT_DOMAIN_WHITELIST_FILENAME "/tmp/etc/bismark/default-passive-domain-whitelist.txt"

#define FLOW_THRESHOLDING_LOG "/tmp/bismark-passive-flowlog"
#define FLOW_THRESHOLD 10

#define DROP_STATISTICS_MAXIMUM_PACKET_SIZE 1500

#define DEVICE_THROUGHPUT_TABLE_SIZE 32

/* Hashtable parameters */
#define HT_NUM_PROBES 3
#define HT_C1 0.5
#define HT_C2 0.5

#define NUM_MICROS_PER_SECOND 1e6
#define TIMEVAL_TO_MICROS(tv) ((tv)->tv_sec * NUM_MICROS_PER_SECOND + (tv)->tv_usec)

#endif
