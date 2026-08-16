#ifndef TREZOR_BITCOIN_MULTISIG_TX_H_
#define TREZOR_BITCOIN_MULTISIG_TX_H_

#include "protocol.h"

typedef struct {
    const trezor_bitcoin_multisig_policy_t* policy;
    const uint8_t* compact_signatures;
    size_t compact_signatures_len;
    size_t signatures_count;
} trezor_bitcoin_multisig_unlock_t;

typedef struct {
    trezor_bitcoin_multisig_policy_t policy;
    bool slot_has_signature[TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS];
    uint8_t slot_signatures[TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS][TREZOR_BITCOIN_MULTISIG_SIGNATURE_MAX_LEN];
    size_t slot_signature_lens[TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS];
    size_t local_slot;
    size_t existing_signatures;
} trezor_bitcoin_multisig_partial_t;

bool trezor_bitcoin_multisig_partial_prepare(const trezor_bitcoin_multisig_t* multisig, uint32_t script_type,
    const uint8_t* local_pubkey, size_t local_pubkey_len, trezor_bitcoin_multisig_partial_t* output);
bool trezor_bitcoin_multisig_partial_add_local_signature(
    trezor_bitcoin_multisig_partial_t* partial, const uint8_t* der_signature, size_t der_signature_len);
bool trezor_bitcoin_multisig_partial_compact_signatures(const trezor_bitcoin_multisig_partial_t* partial,
    uint8_t* compact_signatures, size_t compact_signatures_len, size_t* compact_signatures_written,
    size_t* signatures_count);

bool trezor_bitcoin_multisig_build_hash(const trezor_bitcoin_signing_state_t* state,
    const trezor_bitcoin_multisig_policy_t* const* policies, size_t policies_len, size_t input_index,
    wallet_core_path_t* path, uint8_t* digest, size_t digest_len);
bool trezor_bitcoin_multisig_build_hash_from_redeem_script(const trezor_bitcoin_signing_state_t* state,
    size_t input_index, const uint8_t* redeem_script, size_t redeem_script_len, wallet_core_path_t* path,
    uint8_t* digest, size_t digest_len, size_t* local_slot);

bool trezor_bitcoin_multisig_build_signed_tx(const trezor_bitcoin_signing_state_t* state,
    const trezor_bitcoin_multisig_unlock_t* unlocks, size_t unlocks_len, uint8_t* serialized_tx,
    size_t serialized_tx_len, size_t* serialized_tx_written);

#endif /* TREZOR_BITCOIN_MULTISIG_TX_H_ */
