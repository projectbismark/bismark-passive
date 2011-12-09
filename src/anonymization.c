#include "anonymization.h"

#ifndef NDEBUG
#include <assert.h>
#endif
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "constants.h"
#include "sha1.h"
#include "util.h"

static uint8_t seed[ANONYMIZATION_SEED_LEN];
static char seed_hex_digest[SHA_DIGEST_LENGTH * 2 + 1];
#ifndef NDEBUG
static int initialized = 0;
#endif

/* Anonymize a buffer of given length. Places the resulting digest into the
 * provided digest buffer, which must be at least ANONYMIZATION_DIGEST_LENGTH
 * bytes long. */
static void anonymization_process(const uint8_t* const data,
                                  const int len,
                                  unsigned char* const digest) {
#ifndef NDEBUG
  assert(initialized);
#endif

  sha1_hmac(seed, ANONYMIZATION_SEED_LEN, data, len, digest);
}

static int init_hex_seed_digest() {
  unsigned char seed_digest[SHA_DIGEST_LENGTH];
  anonymization_process(seed, ANONYMIZATION_SEED_LEN, seed_digest);
  const char* hex_digest = buffer_to_hex(seed_digest, SHA_DIGEST_LENGTH);
  if (!hex_digest) {
    return -1;
  }
  memcpy(seed_hex_digest, hex_digest, sizeof(seed_hex_digest));
  seed_hex_digest[sizeof(seed_hex_digest) - 1] = '\0';
  return 0;
}

int anonymization_init() {
  FILE* handle = fopen(ANONYMIZATION_SEED_FILE, "rb");
  if (!handle) {
#ifndef NDEBUG
    perror("Error opening seed file");
#endif
    return -1;
  }
  if (fread(seed, 1, ANONYMIZATION_SEED_LEN, handle) < ANONYMIZATION_SEED_LEN) {
#ifndef NDEBUG
    perror("Error reading seed file");
#endif
    fclose(handle);
    return -1;
  }

#ifndef NDEBUG
  initialized = 1;
#endif

  if (init_hex_seed_digest()) {
#ifndef NDEBUG
    initialized = 0;
#endif
    return -1;
  }

  return 0;
}

inline int anonymize_ip(uint32_t address, uint64_t* digest) {
  unsigned char address_digest[ANONYMIZATION_DIGEST_LENGTH];
  anonymization_process((unsigned char*)&address,
                        sizeof(address),
                        address_digest);
  *digest = *(uint64_t*)address_digest;
  return 0;
}

inline int anonymize_domain(const char* domain, unsigned char* digest) {
  anonymization_process((unsigned char*)domain, strlen(domain), digest);
  return 0;
}

#define MAC_UPPER_MASK 0xffffff000000
#define MAC_LOWER_MASK 0x000000ffffff

inline int anonymize_mac(uint8_t mac[ETH_ALEN], uint8_t digest[ETH_ALEN]) {
  unsigned char mac_digest[ANONYMIZATION_DIGEST_LENGTH];
  anonymization_process(mac, ETH_ALEN, mac_digest);
  memcpy(digest, mac_digest, ETH_ALEN);
  memcpy(digest, mac, ETH_ALEN / 2);
  return 0;
}

int anonymization_write_update(gzFile handle) {
  if (!gzprintf(handle, "%s\n\n", seed_hex_digest)) {
#ifndef NDEBUG
    perror("Error writing update");
#endif
    return -1;
  }
  return 0;
}
