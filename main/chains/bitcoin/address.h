#ifndef BITCOIN_ADDRESS_H_
#define BITCOIN_ADDRESS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BITCOIN_ADDRESS_MAX_LEN 90
#define BITCOIN_P2PKH_ADDRESS_MAX_LEN BITCOIN_ADDRESS_MAX_LEN

bool bitcoin_p2pkh_testnet_address_from_compressed_pubkey(
    const uint8_t* pubkey, size_t pubkey_len, char* output, size_t output_len);
bool bitcoin_p2wpkh_testnet_address_from_compressed_pubkey(
    const uint8_t* pubkey, size_t pubkey_len, char* output, size_t output_len);
bool bitcoin_p2sh_p2wpkh_testnet_address_from_compressed_pubkey(
    const uint8_t* pubkey, size_t pubkey_len, char* output, size_t output_len);

#endif /* BITCOIN_ADDRESS_H_ */
