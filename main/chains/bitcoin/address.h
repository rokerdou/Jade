#ifndef BITCOIN_ADDRESS_H_
#define BITCOIN_ADDRESS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BITCOIN_P2PKH_ADDRESS_MAX_LEN 64

bool bitcoin_p2pkh_testnet_address_from_compressed_pubkey(
    const uint8_t* pubkey, size_t pubkey_len, char* output, size_t output_len);

#endif /* BITCOIN_ADDRESS_H_ */
