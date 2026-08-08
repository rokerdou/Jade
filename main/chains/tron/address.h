#ifndef TRON_ADDRESS_H_
#define TRON_ADDRESS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TRON_ADDRESS_PREFIX 0x41
#define TRON_ADDRESS_LEN 21
#define TRON_BASE58_ADDRESS_MAX_LEN 36

bool tron_address_from_uncompressed_pubkey(
    const uint8_t* pubkey, size_t pubkey_len, uint8_t* output, size_t output_len);
bool tron_owner_address_matches_uncompressed_pubkey(
    const uint8_t* pubkey, size_t pubkey_len, const uint8_t* owner_address, size_t owner_address_len);
bool tron_address_to_base58(const uint8_t* address, size_t address_len, char* output, size_t output_len);

#endif /* TRON_ADDRESS_H_ */
