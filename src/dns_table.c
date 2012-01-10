#include "dns_table.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "anonymization.h"
#include "util.h"
#include "whitelist.h"

void dns_table_init(dns_table_t* table, domain_whitelist_t* whitelist) {
  memset(table, '\0', sizeof(*table));
  table->whitelist = whitelist;
}

void dns_table_destroy(dns_table_t* const table) {
  int idx;
  for (idx = 0; idx < table->a_length; ++idx) {
    free(table->a_entries[idx].domain_name);
  }
  for (idx = 0; idx < table->cname_length; ++idx) {
    free(table->cname_entries[idx].domain_name);
    free(table->cname_entries[idx].cname);
  }
}

int dns_table_add_a(dns_table_t* const table,
                    dns_a_entry_t* const new_entry) {
  if (table->a_length >= DNS_TABLE_A_ENTRIES) {
    ++table->num_dropped_a_entries;
    return -1;
  }
  table->a_entries[table->a_length] = *new_entry;
  ++table->a_length;
  return 0;
}

int dns_table_add_cname(dns_table_t* const table,
                        dns_cname_entry_t* const new_entry) {
  if (table->cname_length >= DNS_TABLE_CNAME_ENTRIES) {
    ++table->num_dropped_cname_entries;
    return -1;
  }
  table->cname_entries[table->cname_length] = *new_entry;
  ++table->cname_length;
  return 0;
}

int dns_table_write_update(dns_table_t* const table, gzFile handle) {
  if (!gzprintf(handle,
                "%d %d\n",
                table->num_dropped_a_entries,
                table->num_dropped_cname_entries)) {
    perror("Error writing update");
    return -1;
  }
  int idx;
  for (idx = 0; idx < table->a_length; ++idx) {
    uint64_t address_digest;
#ifndef DISABLE_ANONYMIZATION
    if (anonymize_ip(table->a_entries[idx].ip_address, &address_digest)) {
      fprintf(stderr, "Error anonymizing DNS data\n");
      return -1;
    }
#else
    address_digest = table->a_entries[idx].ip_address;
#endif
    unsigned int domain_anonymized;
    const char* domain_string;
    if (table->whitelist
        && !domain_whitelist_lookup(table->whitelist,
                                    table->a_entries[idx].domain_name)) {
      domain_anonymized = 0;
      domain_string = table->a_entries[idx].domain_name;
    } else {
      unsigned char domain_digest[ANONYMIZATION_DIGEST_LENGTH];
      if (anonymize_domain(table->a_entries[idx].domain_name, domain_digest)) {
        fprintf(stderr, "Error anonymizing DNS data\n");
        return -1;
      }
      char hex_domain_digest[ANONYMIZATION_DIGEST_LENGTH * 2 + 1];
      strcpy(hex_domain_digest,
          buffer_to_hex(domain_digest, ANONYMIZATION_DIGEST_LENGTH));
      domain_anonymized = 1;
      domain_string = hex_domain_digest;
    }
    if (!gzprintf(handle,
                  "%" PRIu16 " %" PRIu8 " %u %s %" PRIx64 " %" PRId32 "\n",
                  table->a_entries[idx].packet_id,
                  table->a_entries[idx].mac_id,
                  domain_anonymized,
                  domain_string,
                  address_digest,
                  table->a_entries[idx].ttl)) {
      perror("Error writing update");
      return -1;
    }
  }
  if (!gzprintf(handle, "\n")) {
    perror("Error writing update");
    return -1;
  }

  for (idx = 0; idx < table->cname_length; ++idx) {
    unsigned int domain_anonymized, cname_anonymized;
    const char* domain_string;
    const char* cname_string;
#ifndef DISABLE_ANONYMIZATION
    if (table->whitelist
        && !domain_whitelist_lookup(table->whitelist,
                                    table->cname_entries[idx].domain_name)) {
#endif
      domain_anonymized = 0;
      domain_string = table->cname_entries[idx].domain_name;
#ifndef DISABLE_ANONYMIZATION
    } else {
      domain_anonymized = 1;
      unsigned char domain_digest[ANONYMIZATION_DIGEST_LENGTH];
      if (anonymize_domain(table->cname_entries[idx].domain_name, domain_digest)) {
        fprintf(stderr, "Error anonymizing DNS data\n");
        return -1;
      }
      char hex_domain_digest[ANONYMIZATION_DIGEST_LENGTH * 2 + 1];
      strcpy(hex_domain_digest,
          buffer_to_hex(domain_digest, ANONYMIZATION_DIGEST_LENGTH));
      domain_string = hex_domain_digest;
    }
#endif
#ifndef DISABLE_ANONYMIZATION
    if (table->whitelist
        && !domain_whitelist_lookup(table->whitelist,
                                    table->cname_entries[idx].cname)) {
#endif
      cname_anonymized = 0;
      cname_string = table->cname_entries[idx].cname;
#ifndef DISABLE_ANONYMIZATION
    } else {
      cname_anonymized = 1;
      unsigned char cname_digest[ANONYMIZATION_DIGEST_LENGTH];
      if (anonymize_domain(table->cname_entries[idx].cname, cname_digest)) {
        fprintf(stderr, "Error anonymizing DNS data\n");
        return -1;
      }
      char hex_cname_digest[ANONYMIZATION_DIGEST_LENGTH * 2 + 1];
      strcpy(hex_cname_digest,
          buffer_to_hex(cname_digest, ANONYMIZATION_DIGEST_LENGTH));
      cname_string = hex_cname_digest;
    }
#endif
    if (!gzprintf(handle,
                  "%" PRIu16 " %" PRIu8 " %u %s %u %s %" PRId32 "\n",
                  table->cname_entries[idx].packet_id,
                  table->cname_entries[idx].mac_id,
                  domain_anonymized,
                  domain_string,
                  cname_anonymized,
                  cname_string,
                  table->cname_entries[idx].ttl)) {
      perror("Error writing update");
      return -1;
    }
  }
  if (!gzprintf(handle, "\n")) {
    perror("Error writing update");
    return -1;
  }
  return 0;
}
