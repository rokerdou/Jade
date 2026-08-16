#ifndef TREZOR_BITCOIN_SCRIPT_BUILDER_H_
#define TREZOR_BITCOIN_SCRIPT_BUILDER_H_

#include "policy.h"

#include <stddef.h>
#include <stdint.h>

bool trezor_bitcoin_script_builder_output_script(const trezor_bitcoin_tx_output_t* output,
    trezor_bitcoin_coin_t coin, uint8_t* script, size_t script_len, size_t* written);
bool trezor_bitcoin_script_builder_p2pkh_script_code_from_path(
    const wallet_core_path_t* path, uint8_t* script, size_t script_len, size_t* written);
bool trezor_bitcoin_script_builder_p2sh_p2wpkh_scriptsig_from_path(
    const wallet_core_path_t* path, uint8_t* script, size_t script_len, size_t* written);
bool trezor_bitcoin_script_builder_p2pkh_scriptsig_from_signature(const uint8_t* signature, size_t signature_len,
    const uint8_t* pubkey, size_t pubkey_len, uint8_t* script, size_t script_len, size_t* written);

#endif /* TREZOR_BITCOIN_SCRIPT_BUILDER_H_ */
