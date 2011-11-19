#include <inttypes.h>
#include <pcap.h>
#include <pthread.h>
#include <stdio.h>
/* exit() */
#include <stdlib.h>
/* strdup() */
#include <string.h>
/* time() */
#include <time.h>
/* sleep() */
#include <unistd.h>
/* update compression */
#include <zlib.h>
/* inet_ntoa() */
#include <arpa/inet.h>
/* DNS message header */
#include <arpa/nameser.h>
/* ETHER_HDR_LEN */
#include <net/ethernet.h>
/* IPPROTO_... */
#include <netinet/in.h>
/* struct ip */
#include <netinet/ip.h>
/* struct tcphdr */
#include <netinet/tcp.h>
/* struct udphdr */
#include <netinet/udp.h>
/* gettimeofday */
#include <sys/time.h>

#include "address_table.h"
#ifndef DISABLE_ANONYMIZATION
#include "anonymization.h"
#endif
#include "device_throughput_table.h"
#include "dns_parser.h"
#include "dns_table.h"
#include "drop_statistics.h"
#include "flow_table.h"
#include "packet_series.h"
#include "whitelist.h"

static packet_series_t packet_data;
static flow_table_t flow_table;
static dns_table_t dns_table;
static address_table_t address_table;
static domain_whitelist_t domain_whitelist;
static drop_statistics_t drop_statistics;
static device_throughput_table_t device_throughput_table;

static pthread_t update_thread;
static pthread_t frequent_update_thread;
static pthread_mutex_t update_lock;

/* Will be filled in the bismark node ID, from /etc/bismark/ID. */
static char bismark_id[256];

/* Will be filled in with the current timestamp when the program starts. This
 * value serves as a unique identifier across instances of bismark-passive that
 * have run on the same machine. */
static int64_t start_timestamp_microseconds;

/* Will be incremented and sent with each update. */
static int sequence_number = 0;

static int frequent_sequence_number = 0;

/* This extracts flow information from raw packet contents. */
static uint16_t get_flow_entry_for_packet(
    const u_char* const bytes,
    int cap_length,
    int full_length,
    flow_table_entry_t* const entry,
    int* const mac_id,
    u_char** const dns_bytes,
    int* const dns_bytes_len) {
  const struct ether_header* const eth_header = (struct ether_header*)bytes;
  uint16_t ether_type = ntohs(eth_header->ether_type);
  if (device_throughput_table_record(&device_throughput_table,
                                     eth_header->ether_shost,
                                     full_length)
      || device_throughput_table_record(&device_throughput_table,
                                        eth_header->ether_dhost,
                                        full_length)) {
#ifndef NDEBUG
    fprintf(stderr, "Error adding to device throughput table\n");
#endif
  }
  if (ether_type == ETHERTYPE_IP) {
    const struct iphdr* ip_header = (struct iphdr*)(bytes + ETHER_HDR_LEN);
    entry->ip_source = ntohl(ip_header->saddr);
    entry->ip_destination = ntohl(ip_header->daddr);
    entry->transport_protocol = ip_header->protocol;
    address_table_lookup(
        &address_table, entry->ip_source, eth_header->ether_shost);
    address_table_lookup(
        &address_table, entry->ip_destination, eth_header->ether_dhost);
    if (ip_header->protocol == IPPROTO_TCP) {
      const struct tcphdr* tcp_header = (struct tcphdr*)(
          (void *)ip_header + ip_header->ihl * sizeof(uint32_t));
      entry->port_source = ntohs(tcp_header->source);
      entry->port_destination = ntohs(tcp_header->dest);
    } else if (ip_header->protocol == IPPROTO_UDP) {
      const struct udphdr* udp_header = (struct udphdr*)(
          (void *)ip_header + ip_header->ihl * sizeof(uint32_t));
      entry->port_source = ntohs(udp_header->source);
      entry->port_destination = ntohs(udp_header->dest);

      if (entry->port_source == NS_DEFAULTPORT) {
        *dns_bytes = (u_char*)udp_header + sizeof(struct udphdr);
        *dns_bytes_len = cap_length - (*dns_bytes - bytes);
        *mac_id = address_table_lookup(
            &address_table, entry->ip_destination, eth_header->ether_dhost);
      }
    } else {
#ifndef NDEBUG
      fprintf(stderr, "Unhandled transport protocol: %u\n", ip_header->protocol);
#endif
    }
  } else {
#ifndef NDEBUG
    fprintf(stderr, "Unhandled network protocol: %hu\n", ether_type);
#endif
  }
  return ether_type;
}

/* libpcap calls this function for every packet it receives. */
static void process_packet(
        u_char* const user,
        const struct pcap_pkthdr* const header,
        const u_char* const bytes) {
  if (pthread_mutex_lock(&update_lock)) {
    perror("Error locking global mutex");
    exit(1);
  }

#ifndef NDEBUG
  static int packets_received = 0;
  ++packets_received;
  if (packets_received % 1000 == 0) {
    pcap_t* const handle = (pcap_t*)user;
    struct pcap_stat statistics;
    pcap_stats(handle, &statistics);
    printf("-----\n");
    printf("STATISTICS (printed once for every thousand packets)\n");
    printf("Libpcap has dropped %d packets since process creation\n", statistics.ps_drop);
    printf("There are %d entries in the flow table\n", flow_table.num_elements);
    printf("The flow table has dropped %d flows\n", flow_table.num_dropped_flows);
    printf("The flow table has expired %d flows\n", flow_table.num_expired_flows);
    printf("-----\n");
  }
  if (packet_data.discarded_by_overflow % 1000 == 1) {
    printf("%d packets have overflowed the packet table!\n", packet_data.discarded_by_overflow);
  }
#endif

  flow_table_entry_t flow_entry;
  flow_table_entry_init(&flow_entry);
  int mac_id = -1;
  u_char* dns_bytes;
  int dns_bytes_len = -1;
  int ether_type = get_flow_entry_for_packet(
      bytes, header->caplen, header->len, &flow_entry, &mac_id, &dns_bytes, &dns_bytes_len);
  uint16_t flow_id;
  switch (ether_type) {
    case ETHERTYPE_AARP:
      flow_id = FLOW_ID_AARP;
      break;
    case ETHERTYPE_ARP:
      flow_id = FLOW_ID_ARP;
      break;
    case ETHERTYPE_AT:
      flow_id = FLOW_ID_AT;
      break;
    case ETHERTYPE_IP:
      {
        flow_id = flow_table_process_flow(&flow_table,
                                          &flow_entry,
                                          header->ts.tv_sec);
#ifndef NDEBUG
        if (flow_id == FLOW_ID_ERROR) {
          fprintf(stderr, "Error adding to flow table\n");
        }
#endif
      }
      break;
    case ETHERTYPE_IPV6:
      flow_id = FLOW_ID_IPV6;
      break;
    case ETHERTYPE_IPX:
      flow_id = FLOW_ID_IPX;
      break;
    case ETHERTYPE_REVARP:
      flow_id = FLOW_ID_REVARP;
      break;
    default:
      flow_id = FLOW_ID_ERROR;
      break;
  }

  int packet_id = packet_series_add_packet(
        &packet_data, &header->ts, header->len, flow_id);
  if (packet_id < 0) {
#ifndef NDEBUG
    fprintf(stderr, "Error adding to packet series\n");
#endif
    drop_statistics_process_packet(&drop_statistics, header->len);
  }

  if (dns_bytes_len > 0 && mac_id >= 0) {
    process_dns_packet(dns_bytes, dns_bytes_len, &dns_table, packet_id, mac_id);
  }

  if (pthread_mutex_unlock(&update_lock)) {
    perror("Error unlocking global mutex");
    exit(1);
  }
}

/* Write an update to UPDATE_FILENAME. This is the file that will be sent to the
 * server. The data is compressed on-the-fly using gzip. */
static void write_update(const struct pcap_stat* statistics) {
#ifndef DISABLE_FLOW_THRESHOLDING
  if (flow_table_write_thresholded_ips(&flow_table,
                                       start_timestamp_microseconds,
                                       sequence_number)) {
#ifndef NDEBUG
    fprintf(stderr, "Couldn't write thresholded flows log\n");
#endif
  }
#endif

#ifndef NDEBUG
  printf("Writing differential log to %s\n", PENDING_UPDATE_FILENAME);
#endif
  gzFile handle = gzopen (PENDING_UPDATE_FILENAME, "wb");
  if (!handle) {
#ifndef NDEBUG
    perror("Could not open update file for writing");
#endif
    exit(1);
  }

  dns_table_mark_unanonymized(&dns_table, &flow_table);

  time_t current_timestamp = time(NULL);

  if (!gzprintf(handle,
                "%d\n%s\n",
                FILE_FORMAT_VERSION,
                BUILD_ID)) {
#ifndef NDEBUG
    perror("Error writing update");
#endif
    exit(1);
  }
  if (!gzprintf(handle,
                "%s %" PRId64 " %d %" PRId64 "\n",
                bismark_id,
                start_timestamp_microseconds,
                sequence_number,
                (int64_t)current_timestamp)) {
#ifndef NDEBUG
    perror("Error writing update");
#endif
    exit(1);
  }
  if (statistics) {
    if (!gzprintf(handle,
                  "%u %u %u\n",
                  statistics->ps_recv,
                  statistics->ps_drop,
                  statistics->ps_ifdrop)) {
#ifndef NDEBUG
      perror("Error writing update");
#endif
      exit(1);
    }
  }
  if (!gzprintf(handle, "\n")) {
#ifndef NDEBUG
    perror("Error writing update");
#endif
    exit(1);
  }
  if (sequence_number == 0) {
    if (domain_whitelist_write_update(&domain_whitelist, handle)) {
      exit(1);
    }
  } else {
    if (!gzprintf(handle, "\n")) {
#ifndef NDEBUG
      perror("Error writing update");
#endif
      exit(1);
    }
  }
#ifndef DISABLE_ANONYMIZATION
  if (anonymization_write_update(handle)) {
    exit(1);
  }
#else
  if (!gzprintf(handle, "UNANONYMIZED\n\n")) {
#ifndef NDEBUG
    perror("Error writing update");
#endif
    exit(1);
  }
#endif
  if (packet_series_write_update(&packet_data, handle)
      || flow_table_write_update(&flow_table, handle)
      || dns_table_write_update(&dns_table, handle)
      || address_table_write_update(&address_table, handle)
      || drop_statistics_write_update(&drop_statistics, handle)) {
    exit(1);
  }
  gzclose(handle);

  char update_filename[FILENAME_MAX];
  snprintf(update_filename,
           FILENAME_MAX,
           UPDATE_FILENAME,
           bismark_id,
           start_timestamp_microseconds,
           sequence_number);
  if (rename(PENDING_UPDATE_FILENAME, update_filename)) {
#ifndef NDEBUG
    perror("Could not stage update");
#endif
    exit(1);
  }

  packet_series_init(&packet_data);
  flow_table_advance_base_timestamp(&flow_table, current_timestamp);
  dns_table_destroy(&dns_table);
  dns_table_init(&dns_table, &domain_whitelist);
  drop_statistics_init(&drop_statistics);
}

static void* updater(void* arg) {
  pcap_t* const handle = (pcap_t*)arg;
  while (1) {
    sleep (UPDATE_PERIOD_SECONDS);

    if (pthread_mutex_lock(&update_lock)) {
      perror("Error acquiring mutex for update");
      exit(1);
    }
    struct pcap_stat statistics;
    if (!pcap_stats(handle, &statistics)) {
      write_update(&statistics);
    } else {
#ifndef NDEBUG
      pcap_perror(handle, "Error fetching pcap statistics");
#endif
      write_update(NULL);
    }
    ++sequence_number;
    if (pthread_mutex_unlock(&update_lock)) {
      perror("Error unlocking update mutex");
      exit(1);
    }
  }
}

static void write_frequent_update() {
  FILE* handle = fopen (PENDING_FREQUENT_UPDATE_FILENAME, "w");
  if (!handle) {
#ifndef NDEBUG
    perror("Could not open update file for writing");
#endif
    exit(1);
  }
  if (!fprintf(handle,
               "%d\n%s\n",
               FREQUENT_FILE_FORMAT_VERSION,
               BUILD_ID) < 0) {
#ifndef NDEBUG
    perror("Error writing update");
#endif
    exit(1);
  }
  time_t current_timestamp = time(NULL);
  if (!fprintf(handle,
               "%s %" PRId64 " %d %" PRId64 "\n\n",
               bismark_id,
               start_timestamp_microseconds,
               frequent_sequence_number,
               (int64_t)current_timestamp) < 0) {
#ifndef NDEBUG
    perror("Error writing update");
#endif
    exit(1);
  }
  if (device_throughput_table_write_update(&device_throughput_table, handle)) {
    exit(1);
  }
  fclose(handle);

  char update_filename[FILENAME_MAX];
  snprintf(update_filename,
           FILENAME_MAX,
           FREQUENT_UPDATE_FILENAME,
           bismark_id,
           start_timestamp_microseconds,
           frequent_sequence_number);
  if (rename(PENDING_FREQUENT_UPDATE_FILENAME, update_filename)) {
#ifndef NDEBUG
    perror("Could not stage update");
#endif
    exit(1);
  }

  device_throughput_table_init(&device_throughput_table);
}

static void* frequent_updater(void* arg) {
  while (1) {
    sleep (FREQUENT_UPDATE_PERIOD_SECONDS);

    if (pthread_mutex_lock(&update_lock)) {
      perror("Error acquiring mutex for update");
      exit(1);
    }
    write_frequent_update();
    ++frequent_sequence_number;
    if (pthread_mutex_unlock(&update_lock)) {
      perror("Error unlocking update mutex");
      exit(1);
    }
  }
}

static pcap_t* initialize_pcap(const char* const interface) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* const handle = pcap_open_live(interface, BUFSIZ, 0, 1000, errbuf);
  if (!handle) {
    fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
    return NULL;
  }

  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "Must capture on an Ethernet link\n");
    return NULL;
  }
  return handle;
}

static int init_bismark_id() {
  FILE* handle = fopen(BISMARK_ID_FILENAME, "r");
  if (!handle) {
    perror("Cannot open Bismark ID file " BISMARK_ID_FILENAME);
    return -1;
  }
  if(fscanf(handle, "%255s\n", bismark_id) < 1) {
    perror("Cannot read Bismark ID file " BISMARK_ID_FILENAME);
    return -1;
  }
  fclose(handle);
  return 0;
}

static int init_domain_whitelist() {
  domain_whitelist_init(&domain_whitelist);

  FILE* handle = fopen(DOMAIN_WHITELIST_FILENAME, "r");
  if (!handle) {
    fprintf(stderr, "Using default domain whitelist\n");
    handle = fopen(DEFAULT_DOMAIN_WHITELIST_FILENAME, "r");
    if (!handle) {
      perror("Cannot open domain whitelist " DEFAULT_DOMAIN_WHITELIST_FILENAME);
      return -1;
    }
  }

  int length;
  if (fseek(handle, 0, SEEK_END) == -1
      || ((length = ftell(handle)) == -1)
      || fseek(handle, 0, SEEK_SET) == -1) {
    perror("Cannot read domain whitelist " DOMAIN_WHITELIST_FILENAME);
    fclose(handle);
    return -1;
  }

  char* contents = malloc(length);
  if (!contents) {
    perror("Cannot allocate whitelist buffer");
    fclose(handle);
    return -1;
  }
  if (fread(contents, length, 1, handle) != 1) {
    perror("Cannot read domain whitelist " DOMAIN_WHITELIST_FILENAME);
    free(contents);
    fclose(handle);
    return -1;
  }

  fclose(handle);

  if (domain_whitelist_load(&domain_whitelist, contents) < 0) {
    fprintf(stderr, "Error reading domain whitelist.\n");
    free(contents);
    return -1;
  }
  free(contents);
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
    return 1;
  }

  struct timeval start_timeval;
  gettimeofday(&start_timeval, NULL);
  start_timestamp_microseconds
      = start_timeval.tv_sec * NUM_MICROS_PER_SECOND + start_timeval.tv_usec;

  if (init_bismark_id()) {
    return 1;
  }

  pcap_t* handle = initialize_pcap(argv[1]);
  if (!handle) {
    return 1;
  }

  if (init_domain_whitelist()) {
    fprintf(stderr, "Error loading domain whitelist; whitelisting disabled.\n");
  }

#ifndef DISABLE_ANONYMIZATION
  if (anonymization_init()) {
    fprintf(stderr, "Error initializing anonymizer\n");
    return 1;
  }
#endif
  packet_series_init(&packet_data);
  flow_table_init(&flow_table);
  dns_table_init(&dns_table, &domain_whitelist);
  address_table_init(&address_table);
  drop_statistics_init(&drop_statistics);
  device_throughput_table_init(&device_throughput_table);

  if (pthread_mutex_init(&update_lock, NULL)) {
    perror("Error initializing mutex");
    return 1;
  }

  pthread_create(&update_thread, NULL, updater, handle);
  pthread_create(&frequent_update_thread, NULL, frequent_updater, NULL);

  /* By default, pcap uses an internal buffer of 500 KB. Any packets that
   * overflow this buffer will be dropped. pcap_stats tells the number of
   * dropped packets.
   *
   * Because pcap does its own buffering, we don't need to run packet
   * processing in a separate thread. (It would be easier to just increase
   * the buffer size if we experience performance problems.) */
  return pcap_loop(handle, -1, process_packet, (u_char *)handle);
}
