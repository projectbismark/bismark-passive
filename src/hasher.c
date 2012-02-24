#include <endian.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <net/ethernet.h>

#include "anonymization.h"

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <MAC address with colons>\n", argv[0]);
    return 1;
  }

  if (anonymization_init()) {
    fprintf(stderr, "Error initializing anonymizer\n");
    return 1;
  }

  uint8_t mac_address[ETH_ALEN];
  sscanf(argv[1],
         "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
         &mac_address[0],
         &mac_address[1],
         &mac_address[2],
         &mac_address[3],
         &mac_address[4],
         &mac_address[5]);
  uint8_t digest[ETH_ALEN];
  anonymize_mac(mac_address, digest);
  printf("%0hhx:%0hhx:%0hhx:%0hhx:%0hhx:%0hhx\n",
         digest[0],
         digest[1],
         digest[2],
         digest[3],
         digest[4],
         digest[5]);
  return 0;
}
