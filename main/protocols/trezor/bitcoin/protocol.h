#ifndef TREZOR_BITCOIN_PROTOCOL_H_
#define TREZOR_BITCOIN_PROTOCOL_H_

#include "../../../wallet_core/wallet_core.h"
#include "../../../chains/bitcoin/address.h"
#include "../../../chains/bitcoin/confirm.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TREZOR_BITCOIN_COIN_NAME_MAX_LEN 16
#define TREZOR_BITCOIN_TX_INPUTS_MAX 8
#define TREZOR_BITCOIN_TX_OUTPUTS_MAX 8
#define TREZOR_BITCOIN_ADDRESS_MAX_LEN 96
#define TREZOR_BITCOIN_SIGNATURE_MAX_LEN (EC_SIGNATURE_DER_MAX_LEN + 1U)
#define TREZOR_BITCOIN_SIGNED_TX_MAX_LEN 1800
#define TREZOR_BITCOIN_PREV_SCRIPT_MAX_LEN 520
#define TREZOR_BITCOIN_STANDARD_PREVOUT_SCRIPT_MAX_LEN 34
#define BITCOIN_PAYTOADDRESS 0
#define BITCOIN_PAYTOMULTISIG 2

#include "multisig.h"

struct wally_tx;

typedef enum {
    TREZOR_BITCOIN_REQUEST_TXINPUT = 0,
    TREZOR_BITCOIN_REQUEST_TXOUTPUT = 1,
    TREZOR_BITCOIN_REQUEST_TXMETA = 2,
    TREZOR_BITCOIN_REQUEST_TXFINISHED = 3,
    TREZOR_BITCOIN_REQUEST_TXEXTRADATA = 4,
    TREZOR_BITCOIN_REQUEST_TXORIGINPUT = 5,
    TREZOR_BITCOIN_REQUEST_TXORIGOUTPUT = 6,
    TREZOR_BITCOIN_REQUEST_TXPAYMENTREQ = 7,
} trezor_bitcoin_request_type_t;

typedef struct {
    uint32_t address_n[WALLET_CORE_MAX_PATH_LEN];
    size_t address_n_len;
    bool has_coin_name;
    char coin_name[TREZOR_BITCOIN_COIN_NAME_MAX_LEN];
    bool has_show_display;
    bool show_display;
    bool has_script_type;
    uint32_t script_type;
    bool has_ignore_xpub_magic;
    bool ignore_xpub_magic;
    bool has_chunkify;
    bool chunkify;
    bool has_multisig;
    trezor_bitcoin_multisig_summary_t multisig;
    bool has_multisig_policy;
    trezor_bitcoin_multisig_policy_t multisig_policy;
} trezor_bitcoin_get_address_t;

typedef struct {
    uint32_t inputs_count;
    uint32_t outputs_count;
    bool has_coin_name;
    char coin_name[TREZOR_BITCOIN_COIN_NAME_MAX_LEN];
    uint32_t version;
    uint32_t lock_time;
    bool has_amount_unit;
    uint32_t amount_unit;
    bool serialize;
    bool has_chunkify;
    bool chunkify;
} trezor_bitcoin_sign_tx_t;

typedef struct {
    uint32_t address_n[WALLET_CORE_MAX_PATH_LEN];
    size_t address_n_len;
    bool has_prev_hash;
    uint8_t prev_hash[32];
    bool has_prev_index;
    uint32_t prev_index;
    uint32_t sequence;
    uint32_t script_type;
    bool has_amount;
    uint64_t amount;
    bool has_verified_prevout_script;
    uint8_t verified_prevout_script[TREZOR_BITCOIN_STANDARD_PREVOUT_SCRIPT_MAX_LEN];
    size_t verified_prevout_script_len;
    bool has_multisig;
    trezor_bitcoin_multisig_summary_t multisig;
} trezor_bitcoin_tx_input_t;

typedef struct {
    bool has_address;
    char address[TREZOR_BITCOIN_ADDRESS_MAX_LEN];
    uint32_t address_n[WALLET_CORE_MAX_PATH_LEN];
    size_t address_n_len;
    bool has_amount;
    uint64_t amount;
    uint32_t script_type;
    bool has_multisig;
    trezor_bitcoin_multisig_summary_t multisig;
} trezor_bitcoin_tx_output_t;

typedef struct {
    bool has_version;
    uint32_t version;
    bool has_lock_time;
    uint32_t lock_time;
    bool has_inputs_cnt;
    uint32_t inputs_cnt;
    bool has_outputs_cnt;
    uint32_t outputs_cnt;
    trezor_bitcoin_tx_input_t inputs[TREZOR_BITCOIN_TX_INPUTS_MAX];
    size_t inputs_len;
    trezor_bitcoin_tx_output_t outputs[TREZOR_BITCOIN_TX_OUTPUTS_MAX];
    size_t outputs_len;
} trezor_bitcoin_transaction_t;

typedef struct {
    bool input_has_multisig_fingerprint[TREZOR_BITCOIN_TX_INPUTS_MAX];
    uint8_t input_multisig_fingerprints[TREZOR_BITCOIN_TX_INPUTS_MAX][SHA256_LEN];
    bool output_has_multisig_fingerprint[TREZOR_BITCOIN_TX_OUTPUTS_MAX];
    uint8_t output_multisig_fingerprints[TREZOR_BITCOIN_TX_OUTPUTS_MAX][SHA256_LEN];
} trezor_bitcoin_tx_ack_multisig_fingerprints_t;

typedef struct {
    bool has_prev_hash;
    uint8_t prev_hash[SHA256_LEN];
    bool has_prev_index;
    uint32_t prev_index;
    bool has_script_sig;
    uint8_t script_sig[TREZOR_BITCOIN_PREV_SCRIPT_MAX_LEN];
    size_t script_sig_len;
    bool has_sequence;
    uint32_t sequence;
} trezor_bitcoin_prev_input_t;

typedef struct {
    bool has_amount;
    uint64_t amount;
    bool has_script_pubkey;
    uint8_t script_pubkey[TREZOR_BITCOIN_PREV_SCRIPT_MAX_LEN];
    size_t script_pubkey_len;
} trezor_bitcoin_prev_output_t;

typedef enum {
    TREZOR_BITCOIN_SIGNING_PHASE_NONE = 0,
    TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_META,
    TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_INPUT,
    TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_OUTPUT,
    TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_PREV_META,
    TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_PREV_INPUT,
    TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_PREV_OUTPUT,
    TREZOR_BITCOIN_SIGNING_PHASE_READY,
} trezor_bitcoin_signing_phase_t;

typedef struct {
    struct wally_tx* tx;
    bool initialized;
    uint8_t expected_txid[SHA256_LEN];
    uint32_t inputs_count;
    uint32_t outputs_count;
    uint32_t prev_index;
    size_t inputs_seen;
    size_t outputs_seen;
    bool has_prevout;
    uint64_t prevout_amount;
    uint8_t prevout_script[TREZOR_BITCOIN_PREV_SCRIPT_MAX_LEN];
    size_t prevout_script_len;
} trezor_bitcoin_prev_tx_verifier_t;

typedef struct {
    trezor_bitcoin_sign_tx_t request;
    trezor_bitcoin_tx_input_t inputs[TREZOR_BITCOIN_TX_INPUTS_MAX];
    trezor_bitcoin_tx_output_t outputs[TREZOR_BITCOIN_TX_OUTPUTS_MAX];
    bool input_has_multisig_fingerprint[TREZOR_BITCOIN_TX_INPUTS_MAX];
    uint8_t input_multisig_fingerprints[TREZOR_BITCOIN_TX_INPUTS_MAX][SHA256_LEN];
    bool output_has_multisig_fingerprint[TREZOR_BITCOIN_TX_OUTPUTS_MAX];
    uint8_t output_multisig_fingerprints[TREZOR_BITCOIN_TX_OUTPUTS_MAX][SHA256_LEN];
    size_t inputs_len;
    size_t outputs_len;
    size_t prev_tx_input_index;
    uint64_t total_input;
    uint64_t total_output;
    uint64_t fee;
    uint64_t fee_rate_sats_per_vbyte;
    trezor_bitcoin_signing_phase_t phase;
    trezor_bitcoin_prev_tx_verifier_t prev_tx_verifier;
} trezor_bitcoin_signing_state_t;

typedef struct {
    uint8_t bytes[TREZOR_BITCOIN_SIGNATURE_MAX_LEN];
    size_t len;
} trezor_bitcoin_signature_t;

typedef struct {
    trezor_bitcoin_signature_t signatures[TREZOR_BITCOIN_TX_INPUTS_MAX];
    size_t signatures_len;
    uint8_t serialized_tx[TREZOR_BITCOIN_SIGNED_TX_MAX_LEN];
    size_t serialized_tx_len;
    size_t next_signature_index;
} trezor_bitcoin_signed_tx_t;

bool trezor_bitcoin_signing_to_confirm_request(
    const trezor_bitcoin_signing_state_t* state, bitcoin_confirm_request_t* request);
bool trezor_bitcoin_signing_build_hash(const trezor_bitcoin_signing_state_t* state, size_t input_index,
    wallet_core_path_t* path, uint8_t* digest, size_t digest_len);
bool trezor_bitcoin_signing_build_p2wpkh_hash(const trezor_bitcoin_signing_state_t* state, size_t input_index,
    wallet_core_path_t* path, uint8_t* digest, size_t digest_len);
bool trezor_bitcoin_signing_build_signed_tx(const trezor_bitcoin_signing_state_t* state,
    const trezor_bitcoin_signature_t* signatures, size_t signatures_len, uint8_t* serialized_tx,
    size_t serialized_tx_len, size_t* serialized_tx_written);
bool trezor_bitcoin_signing_build_p2wpkh_signed_tx(const trezor_bitcoin_signing_state_t* state,
    const trezor_bitcoin_signature_t* signatures, size_t signatures_len, uint8_t* serialized_tx,
    size_t serialized_tx_len, size_t* serialized_tx_written);

#endif /* TREZOR_BITCOIN_PROTOCOL_H_ */
