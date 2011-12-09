/* RFC 1305 will be very helpful for understanding this parser. */

#include "constants.h"
#include "dns_parser.h"
#include "dns_table.h"

#include <assert.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

typedef struct {
  char name[MAXDNAME];
  uint16_t type;
  uint16_t class;
  int32_t ttl;
  uint16_t rdlength;
  const uint8_t* rdata;
} resource_record_t;

static const uint8_t* parse_resource_record(const uint8_t* const bytes,
                                            int len,
                                            const uint8_t* offset,
                                            resource_record_t* record) {
  int compressed_len = dn_expand(bytes,
      bytes + len,
      offset,
      record->name,
      sizeof(record->name));
  if (compressed_len < 0) {
    fprintf(stderr, "Couldn't expand rr_name\n");
    return NULL;
  }

  const int rr_header_len
    = compressed_len + sizeof(record->type) + sizeof(record->class)
    + sizeof(record->ttl) + sizeof(record->rdlength);
  if (offset + rr_header_len > bytes + len) {
    fprintf(stderr, "Malformed DNS packet: premature end of packet\n");
    return NULL;
  }
  const uint8_t* beginning = offset;

  offset += compressed_len;
  record->type = ntohs(*(uint16_t*)offset);
  offset += sizeof(record->type);
  record->class = ntohs(*(uint16_t*)offset);
  offset += sizeof(record->class);
  record->ttl = ntohl(*(uint32_t*)offset);
  offset += sizeof(record->ttl);
  record->rdlength = ntohs(*(uint16_t*)offset);
  offset += sizeof(record->rdlength);
  record->rdata = offset;
  assert(beginning + rr_header_len == offset);  /* Sanity check */
  offset += record->rdlength;
  if (offset > bytes + len) {
    fprintf(stderr, "Malformed DNS packet: premature end of packet\n");
    return NULL;
  }
  return offset;
}

static void add_a_record(dns_table_t* dns_table,
                         uint16_t packet_id,
                         uint8_t mac_id,
                         const resource_record_t* record) {
  dns_a_entry_t entry;
  entry.packet_id = packet_id;
  entry.mac_id = mac_id;
  entry.domain_name = strdup(record->name);
  entry.ip_address = ntohl(*(uint32_t*)record->rdata);
  entry.ttl = record->ttl;
  dns_table_add_a(dns_table, &entry);
#ifndef NDEBUG
  char ip_buffer[16];
  inet_ntop(AF_INET, &entry.ip_address, ip_buffer, sizeof(ip_buffer));
  fprintf(stderr,
          "Added DNS A entry %d: %s %s %d\n",
          dns_table->a_length,
          entry.domain_name,
          ip_buffer,
          entry.ttl);
#endif
}

static void add_cname_record(dns_table_t* const dns_table,
                             uint16_t packet_id,
                             uint8_t mac_id,
                             const resource_record_t* const record,
                             const uint8_t* const bytes,
                             int len) {
  dns_cname_entry_t entry;
  entry.packet_id = packet_id;
  entry.mac_id = mac_id;
  entry.domain_name = strdup(record->name);
  entry.ttl = record->ttl;
  char cname[MAXDNAME];
  if (dn_expand(bytes, bytes + len, record->rdata, cname, sizeof(cname)) < 0) {
    fprintf(stderr, "Couldn't expand cname\n");
    return;
  }
  entry.cname = strdup(cname);
  dns_table_add_cname(dns_table, &entry);
#ifndef NDEBUG
  fprintf(stderr,
          "Added DNS CNAME entry %d: %s %s %d\n",
          dns_table->cname_length,
          entry.domain_name,
          entry.cname,
          entry.ttl);
#endif
}

int process_dns_packet(const uint8_t* const bytes,
                       int len,
                       dns_table_t* const dns_table,
                       uint16_t packet_id,
                       uint8_t mac_id)
{
  if (len < sizeof(HEADER)) {
    fprintf(stderr, "DNS packet too short\n");
    return -1;
  }

  HEADER* const dns_header = (HEADER*)bytes;
  if (dns_header->qr != 1 ||
      dns_header->opcode != QUERY ||
      dns_header->rcode != NOERROR) {
    fprintf(stderr, "Irrelevant DNS response\n");
    return -1;
  }

  uint16_t num_questions = ntohs(dns_header->qdcount);
  const uint8_t* offset = bytes + sizeof(HEADER);
  int idx;
  for (idx = 0; idx < num_questions; ++idx) {
    char qname[MAXDNAME];
    int compressed_len = dn_expand(bytes,
                                   bytes + len,
                                   offset,
                                   qname,
                                   sizeof(qname));
    if (compressed_len < 0) {
      fprintf(stderr, "Couldn't expand qname\n");
      return -1;
    }
    offset += compressed_len;
    offset += sizeof(uint16_t) + sizeof(uint16_t);  /* Skip QTYPE and QCLASS */
  }

  uint16_t num_answers = ntohs(dns_header->ancount);
  for (idx = 0; idx < num_answers; ++idx) {
    resource_record_t record;
    offset = parse_resource_record(bytes, len, offset, &record);
    if (!offset) {
      return -1;
    }

    if (record.class != C_IN) {
      fprintf(stderr, "Non-IN DNS record\n");
      continue;
    }

    if (record.type == T_A) {
      add_a_record(dns_table, packet_id, mac_id, &record);
    } else if (record.type == T_CNAME) {
      add_cname_record(dns_table, packet_id, mac_id, &record, bytes, len);
    }
  }

  uint16_t num_nameservers = ntohs(dns_header->nscount);
  for (idx = 0; idx < num_nameservers; ++idx) {
    resource_record_t record;
    offset = parse_resource_record(bytes, len, offset, &record);
    if (!offset) {
      return -1;
    }
  }

  uint16_t num_additional = ntohs(dns_header->arcount);
  for (idx = 0; idx < num_additional; ++idx) {
    resource_record_t record;
    offset = parse_resource_record(bytes, len, offset, &record);
    if (!offset) {
      return -1;
    }

    if (record.class != C_IN) {
      fprintf(stderr, "Non-IN DNS record\n");
      continue;
    }

    if (record.type == T_A) {
      add_a_record(dns_table, packet_id, mac_id, &record);
    } else if (record.type == T_CNAME) {
      add_cname_record(dns_table, packet_id, mac_id, &record, bytes, len);
    }
  }
  return 0;
}
