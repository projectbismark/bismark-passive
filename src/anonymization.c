#include "anonymization.h"

#include <assert.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "constants.h"
#include "sha1.h"
#include "util.h"

static uint8_t seed[ANONYMIZATION_SEED_LEN];
static char seed_hex_digest[ANONYMIZATION_DIGEST_LENGTH * 2 + 1];
static int initialized = 0;

/* Anonymize a buffer of given length. Places the resulting digest into the
 * provided digest buffer, which must be at least ANONYMIZATION_DIGEST_LENGTH
 * bytes long. */
static void anonymization_process(const uint8_t* const data,
                                  const int len,
                                  unsigned char* const digest) {
  assert(initialized);
  sha1_hmac(seed, ANONYMIZATION_SEED_LEN, data, len, digest);
}

static int init_hex_seed_digest() {
  unsigned char seed_digest[ANONYMIZATION_DIGEST_LENGTH];
  anonymization_process(seed, ANONYMIZATION_SEED_LEN, seed_digest);
  const char* hex_digest = buffer_to_hex(seed_digest, ANONYMIZATION_DIGEST_LENGTH);
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
    perror("Error opening seed file");
    return -1;
  }
  if (fread(seed, 1, ANONYMIZATION_SEED_LEN, handle) < ANONYMIZATION_SEED_LEN) {
    perror("Error reading seed file");
    fclose(handle);
    return -1;
  }

  initialized = 1;

  if (init_hex_seed_digest()) {
    initialized = 0;
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

#ifdef ENABLE_HTTP_URL
inline int anonymize_url(const char* url, unsigned char* digest) {
  anonymization_process((unsigned char*)url, strlen(url), digest);
  return 0;
}
#endif

inline int anonymize_mac(uint8_t mac[ETH_ALEN], uint8_t digest[ETH_ALEN]) {
  unsigned char mac_digest[ANONYMIZATION_DIGEST_LENGTH];
  anonymization_process(mac, ETH_ALEN, mac_digest);
  memcpy(mac_digest, mac, ETH_ALEN / 2);
  memcpy(digest, mac_digest, ETH_ALEN);
  return 0;
}

int anonymization_write_update(gzFile handle) {
  if (!gzprintf(handle, "%s\n\n", seed_hex_digest)) {
    perror("Error writing update");
    return -1;
  }
  return 0;
}
