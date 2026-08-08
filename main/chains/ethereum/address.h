#ifndef ETHEREUM_ADDRESS_H_
#define ETHEREUM_ADDRESS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ETHEREUM_ADDRESS_LEN 20
#define ETHEREUM_CHECKSUM_ADDRESS_STRING_LEN 43

bool ethereum_address_from_uncompressed_pubkey(
    const uint8_t* pubkey, size_t pubkey_len, uint8_t* output, size_t output_len);
bool ethereum_address_matches_uncompressed_pubkey(
    const uint8_t* pubkey, size_t pubkey_len, const uint8_t* address, size_t address_len);
bool ethereum_address_to_checksum_string(const uint8_t* address, size_t address_len, char* output, size_t output_len);

#endif /* ETHEREUM_ADDRESS_H_ */
