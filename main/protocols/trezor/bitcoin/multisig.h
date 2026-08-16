#ifndef TREZOR_BITCOIN_MULTISIG_H_
#define TREZOR_BITCOIN_MULTISIG_H_

#include "../../../wallet.h"
#include "../../../wallet_core/wallet_core.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wally_bip32.h>
#include <wally_crypto.h>

// Keep this adapter-local so the Trezor protocol normalizer does not pull in
// Jade's CBOR RPC signer layer. The value intentionally mirrors signer.h.
#define TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS 15U
#define TREZOR_BITCOIN_MULTISIG_SIGNATURE_MAX_LEN (EC_SIGNATURE_DER_MAX_LEN + 1U)
#define TREZOR_BITCOIN_MULTISIG_SCRIPT_PUBKEY_MAX_LEN 520U
#define TREZOR_BITCOIN_MULTISIG_STANDARD_SCRIPT_PUBKEY_MAX_LEN 34U
#define TREZOR_BITCOIN_MULTISIG_REDEEM_SCRIPT_MAX_LEN                                                                              \
    (1U + 1U + (TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS * (1U + EC_PUBLIC_KEY_LEN)) + 1U + 1U)

typedef struct {
    uint8_t depth;
    uint32_t fingerprint;
    uint32_t child_num;
    uint8_t chain_code[WALLY_BIP32_CHAIN_CODE_LEN];
    uint8_t public_key[EC_PUBLIC_KEY_LEN];
} trezor_bitcoin_hd_node_t;

typedef struct {
    trezor_bitcoin_hd_node_t node;
    uint32_t address_n[WALLET_CORE_MAX_PATH_LEN];
    size_t address_n_len;
} trezor_bitcoin_hd_node_path_t;

typedef struct {
    trezor_bitcoin_hd_node_path_t pubkeys[TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS];
    size_t pubkeys_len;
    trezor_bitcoin_hd_node_t nodes[TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS];
    size_t nodes_len;
    uint32_t address_n[WALLET_CORE_MAX_PATH_LEN];
    size_t address_n_len;
    uint8_t signatures[TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS][TREZOR_BITCOIN_MULTISIG_SIGNATURE_MAX_LEN];
    size_t signature_lens[TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS];
    size_t signatures_len;
    uint32_t threshold;
    bool sorted;
} trezor_bitcoin_multisig_t;

typedef struct {
    script_variant_t variant;
    uint8_t threshold;
    size_t num_pubkeys;
    bool sorted;
    uint8_t fingerprint[SHA256_LEN];
    uint32_t address_n[WALLET_CORE_MAX_PATH_LEN];
    size_t address_n_len;
    uint8_t pubkeys[TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS * EC_PUBLIC_KEY_LEN];
    uint8_t redeem_script[TREZOR_BITCOIN_MULTISIG_REDEEM_SCRIPT_MAX_LEN];
    size_t redeem_script_len;
    uint8_t script_pubkey[TREZOR_BITCOIN_MULTISIG_SCRIPT_PUBKEY_MAX_LEN];
    size_t script_pubkey_len;
} trezor_bitcoin_multisig_policy_t;

typedef struct {
    script_variant_t variant;
    uint8_t threshold;
    uint8_t num_pubkeys;
    bool sorted;
    uint8_t script_pubkey[TREZOR_BITCOIN_MULTISIG_STANDARD_SCRIPT_PUBKEY_MAX_LEN];
    size_t script_pubkey_len;
} trezor_bitcoin_multisig_summary_t;

bool trezor_bitcoin_multisig_decode(const uint8_t* payload, size_t payload_len, trezor_bitcoin_multisig_t* output);
bool trezor_bitcoin_multisig_normalize(const trezor_bitcoin_multisig_t* multisig, uint32_t script_type,
    trezor_bitcoin_multisig_policy_t* output);
bool trezor_bitcoin_multisig_fingerprint(const trezor_bitcoin_multisig_t* multisig, uint8_t fingerprint[SHA256_LEN]);
bool trezor_bitcoin_multisig_script_pubkey_matches(const trezor_bitcoin_multisig_policy_t* policy,
    const uint8_t* script_pubkey, size_t script_pubkey_len);

#endif /* TREZOR_BITCOIN_MULTISIG_H_ */
