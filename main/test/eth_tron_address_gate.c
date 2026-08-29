#include "ccan/ccan/crypto/ripemd160/ripemd160.h"
#include "chains/bitcoin/address.h"
#include "chains/bitcoin/confirm.h"
#include "chains/bitcoin/path.h"
#include "chains/bitcoin/wallet.h"
#include "chains/ethereum/address.h"
#include "chains/ethereum/authorize.h"
#include "chains/ethereum/confirm.h"
#include "chains/ethereum/digest.h"
#include "chains/ethereum/path.h"
#include "chains/ethereum/safe_tx.h"
#include "chains/ethereum/sign.h"
#include "chains/ethereum/tx.h"
#include "chains/ethereum/tx_request.h"
#include "chains/evm_abi.h"
#include "chains/path.h"
#include "chains/tron/address.h"
#include "chains/tron/authorize.h"
#include "chains/tron/confirm.h"
#include "chains/tron/path.h"
#include "chains/tron/tx.h"
#include "crypto/keccak256.h"
#include "memzero.h"
#include "protocols/trezor/bitcoin/messages.h"
#include "protocols/trezor/bitcoin/multisig.h"
#include "protocols/trezor/bitcoin/multisig_tx.h"
#include "protocols/trezor/bitcoin/normalizer.h"
#include "protocols/trezor/bitcoin/policy.h"
#include "protocols/trezor/bitcoin/prev_tx_verifier.h"
#include "protocols/trezor/bitcoin/protocol.h"
#include "protocols/trezor/bitcoin/public_node.h"
#include "protocols/trezor/bitcoin/requests.h"
#include "protocols/trezor/bitcoin/script_policy.h"
#include "protocols/trezor/bitcoin/signing_state.h"
#include "protocols/trezor/dispatcher.h"
#include "protocols/trezor/ethereum/protocol.h"
#include "protocols/trezor/ethereum/definitions.h"
#include "protocols/trezor/ethereum/safe_normalizer.h"
#include "protocols/trezor/failure.h"
#include "protocols/trezor/features.h"
#include "protocols/trezor/misc.h"
#include "protocols/trezor/protobuf.h"
#include "protocols/trezor/public_key.h"
#include "protocols/trezor/session.h"
#include "protocols/trezor/trace.h"
#include "protocols/trezor/wire.h"
#include "sha2.h"
#include "ui/chain_confirm.h"
#include "ui/chain_confirm_format.h"
#include "wallet_entropy.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_map.h>
#include <wally_script.h>
#include <wally_transaction.h>

#define CHECK(cond)                                                                                                    \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            fprintf(stderr, "ETH/TRON address gate failed at %s:%d\n", __FILE__, __LINE__);                            \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (false)

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define HEX_UI_LINES_FOR_BYTES(bytes_len)                                                                                \
    (((2U + (2U * (bytes_len))) + CHAIN_CONFIRM_UI_HEX_LINE_CHARS - 1U) / CHAIN_CONFIRM_UI_HEX_LINE_CHARS)

static const uint8_t PRIVATE_KEY_ONE[EC_PRIVATE_KEY_LEN]
    = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

static const uint8_t PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY[EC_PUBLIC_KEY_UNCOMPRESSED_LEN]
    = { 0x04, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02,
          0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98, 0x48, 0x3a, 0xda,
          0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6,
          0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8 };

static const uint8_t PRIVATE_KEY_ONE_COMPRESSED_PUBKEY[EC_PUBLIC_KEY_LEN]
    = { 0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
          0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98 };

static const uint8_t EXPECTED_BTC_TESTNET_HASH160[HASH160_LEN]
    = { 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
          0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6 };

static const uint8_t EXPECTED_BTC_TESTNET_ADDRESS_BYTES[1 + HASH160_LEN]
    = { 0x6f, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
          0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6 };

static const uint8_t EXPECTED_BTC_MAINNET_ADDRESS_BYTES[1 + HASH160_LEN]
    = { 0x00, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
          0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6 };

static const uint8_t EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY[2 + HASH160_LEN]
    = { 0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
          0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6 };

static const uint8_t EXPECTED_BTC_TEST_DIGEST[SHA256_LEN]
    = { 0x42, 0x7a, 0x11, 0x03, 0x99, 0x18, 0x52, 0x61, 0xab, 0xcd, 0xee, 0x10, 0x22, 0x34, 0x46, 0x58,
          0x6a, 0x7c, 0x8e, 0x90, 0xa2, 0xb4, 0xc6, 0xd8, 0xea, 0xfc, 0x0d, 0x1f, 0x20, 0x31, 0x42, 0x53 };

static const uint8_t EXPECTED_BTC_TEST_TX_BYTES[]
    = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x11, 0x11, 0x11, 0x11, 0x01 };

static const uint8_t EXPECTED_BTC_P2SH_P2WPKH_HASH160[HASH160_LEN]
    = { 0xbc, 0xfe, 0xb7, 0x28, 0xb5, 0x84, 0x25, 0x3d, 0x5f, 0x3f,
          0x70, 0xbc, 0xb7, 0x80, 0xe9, 0xef, 0x21, 0x8a, 0x68, 0xf4 };

static const uint8_t EXPECTED_BTC_P2SH_P2WPKH_ADDRESS_BYTES[1 + HASH160_LEN]
    = { 0xc4, 0xbc, 0xfe, 0xb7, 0x28, 0xb5, 0x84, 0x25, 0x3d, 0x5f, 0x3f,
          0x70, 0xbc, 0xb7, 0x80, 0xe9, 0xef, 0x21, 0x8a, 0x68, 0xf4 };

static const uint8_t EXPECTED_BTC_P2SH_P2WPKH_MAINNET_ADDRESS_BYTES[1 + HASH160_LEN]
    = { 0x05, 0xbc, 0xfe, 0xb7, 0x28, 0xb5, 0x84, 0x25, 0x3d, 0x5f, 0x3f,
          0x70, 0xbc, 0xb7, 0x80, 0xe9, 0xef, 0x21, 0x8a, 0x68, 0xf4 };

static const uint8_t EXPECTED_ETH_ADDRESS[ETHEREUM_ADDRESS_LEN] = { 0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12,
    0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2, 0x65, 0x90, 0x29, 0x39, 0x5b, 0xdf };

static const uint8_t EXPECTED_TRON_ADDRESS[TRON_ADDRESS_LEN] = { 0x41, 0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12,
    0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2, 0x65, 0x90, 0x29, 0x39, 0x5b, 0xdf };

static const uint8_t SAFE_TEST_ADDRESS[ETHEREUM_ADDRESS_LEN]
    = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34,
          0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78 };

static const uint8_t SAFE_TEST_USDT_ADDRESS[ETHEREUM_ADDRESS_LEN]
    = { 0xda, 0xc1, 0x7f, 0x95, 0x8d, 0x2e, 0xe5, 0x23, 0xa2, 0x20,
          0x62, 0x06, 0x99, 0x45, 0x97, 0xc1, 0x3d, 0x83, 0x1e, 0xc7 };

static const uint8_t SAFE_TEST_RECIPIENT[ETHEREUM_ADDRESS_LEN]
    = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
          0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };

static const uint8_t EXPECTED_SAFE_DOMAIN_HASH[KECCAK256_LEN]
    = { 0x5c, 0x92, 0xda, 0xda, 0xda, 0x03, 0x78, 0xbc, 0x05, 0xc7, 0x4d, 0x0b, 0x8f, 0x6f, 0x2f, 0xd8,
          0x7d, 0xc3, 0x54, 0xb8, 0x2d, 0x31, 0x45, 0xea, 0x56, 0x2a, 0x3b, 0xe6, 0x3d, 0x0c, 0x78, 0x00 };

static const uint8_t EXPECTED_SAFE_MESSAGE_HASH[KECCAK256_LEN]
    = { 0xbc, 0x7c, 0x1a, 0xe4, 0xea, 0x1f, 0x3a, 0xc5, 0x35, 0xd6, 0xca, 0x97, 0xc5, 0xfb, 0xd5, 0x39,
          0x51, 0x6e, 0xfb, 0x90, 0x3c, 0x73, 0xda, 0x7a, 0x84, 0x3c, 0xa5, 0xa6, 0xff, 0xdb, 0x76, 0xf7 };

static const uint8_t EXPECTED_SAFE_SIGNING_HASH[KECCAK256_LEN]
    = { 0x35, 0x2d, 0x31, 0x8c, 0x28, 0x51, 0x79, 0xfb, 0x67, 0xc3, 0xa9, 0xaa, 0x1c, 0xcd, 0x10, 0x8d,
          0x7f, 0x1c, 0xbf, 0x0f, 0x89, 0x0f, 0x02, 0xa1, 0xbe, 0x24, 0x09, 0xcf, 0x25, 0x7d, 0x29, 0x33 };

static const uint8_t EXPECTED_SAFE_CALLDATA_HASH[KECCAK256_LEN]
    = { 0x5a, 0x2e, 0x4f, 0x8e, 0xc4, 0x58, 0xf1, 0x46, 0x93, 0xf8, 0x37, 0x2d, 0xb3, 0xad, 0x9a, 0xb5,
          0x3a, 0x81, 0x88, 0x7c, 0x99, 0x2d, 0xe1, 0x86, 0xcc, 0x9e, 0x1e, 0x50, 0xfe, 0x61, 0x9d, 0x73 };

static const uint8_t EXPECTED_KECCAK256_EMPTY[KECCAK256_LEN]
    = { 0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0, 0xe5, 0x00,
          0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70 };

static const uint8_t EXPECTED_KECCAK256_ABC[KECCAK256_LEN]
    = { 0x4e, 0x03, 0x65, 0x7a, 0xea, 0x45, 0xa9, 0x4f, 0xc7, 0xd4, 0x7b, 0xa8, 0x26, 0xc8, 0xd6, 0x67, 0xc0, 0xd1,
          0xe6, 0xe3, 0x3a, 0x64, 0xa0, 0x36, 0xec, 0x44, 0xf5, 0x8f, 0xa1, 0x2d, 0x6c, 0x45 };

static bool g_wallet_pubkey_ok = true;
static bool g_host_real_multisig_hashes = false;
static bool g_ui_accept = true;
static size_t g_ui_calls = 0;
static chain_confirm_summary_t g_last_ui_summary;
static bool g_wallet_sign_ok = true;
static uint8_t g_wallet_signature_header = 31;
static uint8_t g_test_btc_compact_signatures[TREZOR_BITCOIN_TX_INPUTS_MAX][EC_SIGNATURE_RECOVERABLE_LEN];
static size_t g_test_btc_compact_signatures_len = 0;
static size_t g_test_btc_compact_signature_index = 0;
static uint8_t g_test_eth_compact_signature[EC_SIGNATURE_RECOVERABLE_LEN];
static bool g_test_eth_compact_signature_has_value = false;
static bool g_trezor_eth_address_ok = true;
static bool g_trezor_bitcoin_address_ok = true;
static trezor_bitcoin_get_address_t g_last_trezor_bitcoin_address_request;
static trezor_ethereum_get_address_t g_last_trezor_eth_address_request;
static bool g_trezor_public_key_ok = true;
static trezor_public_key_request_t g_last_trezor_public_key_request;
static bool g_trezor_eth_sign_ok = true;
static size_t g_trezor_eth_sign_calls = 0;
static size_t g_trezor_eth_safe_sign_calls = 0;
static size_t g_trezor_btc_confirm_calls = 0;
static size_t g_trezor_btc_sign_calls = 0;
static void write_u32_be(uint8_t output[4], uint32_t value);
static bitcoin_confirm_request_t g_last_trezor_btc_confirm_request;
static ethereum_tx_preflight_request_t g_last_trezor_eth_sign_request;
static uint32_t g_last_trezor_eth_sign_path[WALLET_CORE_MAX_PATH_LEN];
static uint8_t g_last_trezor_eth_sign_value[EVM_ABI_WORD_LEN];
static uint8_t g_last_trezor_eth_sign_data[ETHEREUM_TX_MAX_PREFLIGHT_DATA_LEN];
static trezor_ethereum_sign_typed_hash_t g_last_trezor_eth_safe_typed_hash;
static ethereum_safe_tx_t g_last_trezor_eth_safe_tx;
static uint8_t g_last_trezor_eth_safe_tx_data[ETHEREUM_SAFE_TX_MAX_DATA_LEN];
static uint8_t g_last_trezor_eth_safe_signing_hash[ETHEREUM_TX_SIGNING_HASH_LEN];
static bool g_trezor_needs_local_unlock = false;
static bool g_trezor_local_unlock_ok = true;
static size_t g_trezor_local_unlock_calls = 0;
static bool g_trezor_initialize_session_ok = true;
static uint8_t g_trezor_last_initialize_session_id[TREZOR_FEATURES_SESSION_ID_LEN];
static size_t g_trezor_last_initialize_session_id_len = 0;

bool trezor_ethereum_definitions_host_verify(
    const uint8_t root[SHA256_LEN], const uint8_t sigmask, const uint8_t signature[64])
{
    (void)root;
    return sigmask == 0x03 && signature && signature[0] == 0xa5;
}

static bool hex_char_to_nibble(const char c, uint8_t* const output)
{
    if (!output) {
        return false;
    }
    if (c >= '0' && c <= '9') {
        *output = (uint8_t)(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f') {
        *output = (uint8_t)(10 + c - 'a');
        return true;
    }
    if (c >= 'A' && c <= 'F') {
        *output = (uint8_t)(10 + c - 'A');
        return true;
    }
    return false;
}

static bool hex_to_bytes(const char* const hex, uint8_t* const output, const size_t output_len)
{
    if (!hex || !output || strlen(hex) != output_len * 2) {
        return false;
    }

    for (size_t i = 0; i < output_len; ++i) {
        uint8_t high = 0;
        uint8_t low = 0;
        if (!hex_char_to_nibble(hex[2 * i], &high) || !hex_char_to_nibble(hex[(2 * i) + 1], &low)) {
            return false;
        }
        output[i] = (uint8_t)((high << 4) | low);
    }
    return true;
}

static const chain_confirm_field_t* find_confirm_field(
    const chain_confirm_summary_t* const summary, const chain_confirm_field_kind_t kind)
{
    if (!summary) {
        return NULL;
    }
    for (size_t i = 0; i < summary->num_fields; ++i) {
        if (summary->fields[i].kind == kind) {
            return &summary->fields[i];
        }
    }
    return NULL;
}

static size_t decimal_len(uint64_t value)
{
    size_t len = 1;
    while (value >= 10U) {
        value /= 10U;
        ++len;
    }
    return len;
}

static size_t path_part_len(const uint32_t part)
{
    uint32_t index = chain_path_unharden(part);
    size_t len = 1;
    while (index >= 10U) {
        index /= 10U;
        ++len;
    }
    return len + (chain_path_is_hardened(part) ? 1U : 0U);
}

static bool test_text_line_fits_display(const char* const text)
{
    const size_t len = text ? strnlen(text, CHAIN_CONFIRM_MAX_TEXT + 1U) : 0;
    const size_t chars_per_line = CHAIN_CONFIRM_UI_DISPLAY_LINE_MAX - 1U;
    const size_t lines = chars_per_line ? (len + chars_per_line - 1U) / chars_per_line : 0;
    return len > 0 && len < CHAIN_CONFIRM_MAX_TEXT && lines > 0 && lines <= CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES;
}

static bool test_path_line_fits_display(const chain_confirm_path_t* const path)
{
    if (!path || path->len == 0 || path->len > CHAIN_CONFIRM_MAX_PATH_LEN) {
        return false;
    }

    size_t len = 1; // "m"
    for (size_t i = 0; i < path->len; ++i) {
        len += 1U + path_part_len(path->parts[i]); // "/" + index + optional "'"
    }
    return len < CHAIN_CONFIRM_UI_DISPLAY_LINE_MAX;
}

static bool test_hex_field_fits_dialog(const size_t bytes_len)
{
    if (bytes_len > CHAIN_CONFIRM_MAX_BYTES) {
        return false;
    }
    const size_t hex_chars = 2U + (2U * bytes_len);
    const size_t lines = (hex_chars + CHAIN_CONFIRM_UI_HEX_LINE_CHARS - 1U) / CHAIN_CONFIRM_UI_HEX_LINE_CHARS;
    return lines > 0 && lines <= CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES
        && CHAIN_CONFIRM_UI_HEX_LINE_CHARS + 1U <= CHAIN_CONFIRM_UI_DISPLAY_LINE_MAX;
}

static bool test_confirm_field_fits_tdisplay_s3(const chain_confirm_field_t* const field)
{
    if (!field) {
        return false;
    }

    switch (field->value_type) {
    case CHAIN_CONFIRM_VALUE_U64:
        return decimal_len(field->value.u64) < CHAIN_CONFIRM_UI_DISPLAY_LINE_MAX;
    case CHAIN_CONFIRM_VALUE_BYTES:
        return test_hex_field_fits_dialog(field->value.bytes.len);
    case CHAIN_CONFIRM_VALUE_PATH:
        return test_path_line_fits_display(&field->value.path);
    case CHAIN_CONFIRM_VALUE_TEXT:
        return test_text_line_fits_display(field->value.text);
    }
    return false;
}

static bool test_confirm_summary_fits_tdisplay_s3(const chain_confirm_summary_t* const summary)
{
    if (!summary || (summary->flags & CHAIN_CONFIRM_FLAG_USER_CONFIRM) == 0 || summary->num_fields == 0
        || summary->num_fields > CHAIN_CONFIRM_MAX_FIELDS) {
        return false;
    }

    if (CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES < 3U) {
        return false;
    }
    for (size_t i = 0; i < summary->num_fields; ++i) {
        if (!test_confirm_field_fits_tdisplay_s3(&summary->fields[i])) {
            return false;
        }
    }
    return true;
}

static bool test_protobuf_rejects_malformed_inputs(void)
{
    static const uint8_t field_zero[] = { 0x00 };
    static const uint8_t unsupported_wire_type[] = { 0x0d, 0x00, 0x00, 0x00, 0x00 };
    static const uint8_t truncated_varint_value[] = { 0x08, 0x80 };
    static const uint8_t overlong_varint_value[]
        = { 0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02 };
    static const uint8_t truncated_len_field[] = { 0x0a, 0x05, 0xaa, 0xbb };
    static const uint8_t overlong_len_varint[]
        = { 0x0a, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02 };
    static const uint8_t oversized_len_field[] = { 0x0a, 0x81, 0x10 };
    static const uint8_t too_large_field_number[] = { 0x80, 0x80, 0x80, 0x80, 0x80, 0x01, 0x00 };
    static const uint8_t valid_varint[] = { 0x08, 0x01 };
    static const uint8_t* const malformed_cases[] = {
        field_zero,
        unsupported_wire_type,
        truncated_varint_value,
        overlong_varint_value,
        truncated_len_field,
        overlong_len_varint,
        oversized_len_field,
        too_large_field_number,
    };
    static const size_t malformed_lens[] = {
        sizeof(field_zero),
        sizeof(unsupported_wire_type),
        sizeof(truncated_varint_value),
        sizeof(overlong_varint_value),
        sizeof(truncated_len_field),
        sizeof(overlong_len_varint),
        sizeof(oversized_len_field),
        sizeof(too_large_field_number),
    };

    for (size_t i = 0; i < ARRAY_LEN(malformed_cases); ++i) {
        trezor_protobuf_reader_t reader;
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        trezor_protobuf_reader_init(&reader, malformed_cases[i], malformed_lens[i]);
        if (trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            return false;
        }
    }

    uint8_t oversized_message[TREZOR_PROTOBUF_MAX_MESSAGE_LEN + 1U];
    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, oversized_message, sizeof(oversized_message));
    if (reader.len != 0) {
        return false;
    }

    trezor_protobuf_reader_init(&reader, valid_varint, sizeof(valid_varint));
    uint32_t field_number = 0;
    uint8_t wire_type = 0;
    const uint8_t* value = NULL;
    size_t value_len = 0;
    uint64_t decoded = 0;
    if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)
        || field_number != 1 || wire_type != TREZOR_PROTOBUF_WIRE_VARINT
        || !trezor_protobuf_read_varint_value(value, value_len, &decoded) || decoded != 1
        || trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
        return false;
    }

    uint8_t output[16];
    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, output, sizeof(output));
    if (trezor_protobuf_write_varint_field(&writer, 0, 1)) {
        return false;
    }
    uint8_t oversized_field[TREZOR_PROTOBUF_MAX_FIELD_BYTES + 1U];
    trezor_protobuf_writer_init(&writer, output, sizeof(output));
    if (trezor_protobuf_write_bytes_field(&writer, 1, oversized_field, sizeof(oversized_field))) {
        return false;
    }
    trezor_protobuf_writer_init(&writer, output, 1);
    if (trezor_protobuf_write_bytes_field(&writer, 1, (const uint8_t*)"abcd", 4)) {
        return false;
    }
    return true;
}

static bool test_fake_ui_rejects_unrenderable_summary(void)
{
    chain_confirm_summary_t summary;
    chain_confirm_summary_init(&summary, CHAIN_CONFIRM_CHAIN_ETHEREUM, CHAIN_CONFIRM_OPERATION_NATIVE_TRANSFER,
        CHAIN_CONFIRM_FLAG_USER_CONFIRM);

    char long_text[CHAIN_CONFIRM_MAX_TEXT];
    memset(long_text, 'A', sizeof(long_text));
    long_text[sizeof(long_text) - 1U] = '\0';
    if (!chain_confirm_summary_add_text(&summary, CHAIN_CONFIRM_FIELD_TOKEN_NAME, long_text)
        || test_confirm_summary_fits_tdisplay_s3(&summary) || show_chain_confirm_summary_activity(&summary)) {
        return false;
    }

    const uint32_t too_long_path[] = { chain_path_harden(2147483647U), chain_path_harden(2147483647U),
        chain_path_harden(2147483647U), chain_path_harden(2147483647U) };
    chain_confirm_summary_init(&summary, CHAIN_CONFIRM_CHAIN_ETHEREUM, CHAIN_CONFIRM_OPERATION_NATIVE_TRANSFER,
        CHAIN_CONFIRM_FLAG_USER_CONFIRM);
    if (!chain_confirm_summary_add_path(&summary, CHAIN_CONFIRM_FIELD_PATH, too_long_path, ARRAY_LEN(too_long_path))
        || test_confirm_summary_fits_tdisplay_s3(&summary) || show_chain_confirm_summary_activity(&summary)) {
        return false;
    }
    return true;
}

static bool test_chain_confirm_ui_pagination_stops_at_nul(void)
{
    char text[CHAIN_CONFIRM_MAX_TEXT];
    char line[CHAIN_CONFIRM_UI_DISPLAY_LINE_MAX];
    size_t consumed = 0;

    memset(text, 'R', sizeof(text));
    memcpy(text, "1 wei", sizeof("1 wei"));
    if (!chain_confirm_ui_copy_text_line(line, sizeof(line), text, strlen("1 wei"), 0, &consumed)
        || strcmp(line, "1 wei") != 0 || consumed != strlen("1 wei") || text[consumed] != '\0') {
        return false;
    }

    memset(text, 'R', sizeof(text));
    memcpy(text, "21000000000000", sizeof("21000000000000"));
    if (!chain_confirm_ui_copy_text_line(line, sizeof(line), text, strlen("21000000000000"), 0, &consumed)
        || strcmp(line, "21000000000000") != 0 || consumed != strlen("21000000000000") || text[consumed] != '\0') {
        return false;
    }

    memset(text, 'R', sizeof(text));
    memcpy(text, "12345678901234567890123", sizeof("12345678901234567890123"));
    if (!chain_confirm_ui_copy_text_line(line, sizeof(line), text, strlen("12345678901234567890123"), 0, &consumed)
        || strcmp(line, "12345678901234567890123") != 0
        || consumed != CHAIN_CONFIRM_UI_DISPLAY_LINE_MAX - 1U || text[consumed] != '\0') {
        return false;
    }

    char hex[(2U * CHAIN_CONFIRM_MAX_BYTES) + 3U];
    memset(hex, 'R', sizeof(hex));
    memcpy(hex, "0xf2a82bf45c0ea76b3e0e187102858a869d121366",
        sizeof("0xf2a82bf45c0ea76b3e0e187102858a869d121366"));
    const size_t hex_len = strlen("0xf2a82bf45c0ea76b3e0e187102858a869d121366");
    size_t offset = 0;
    if (!chain_confirm_ui_copy_hex_line(line, sizeof(line), hex, hex_len, offset, &consumed)
        || strcmp(line, "0xf2a82bf45c0ea76b3e0e") != 0 || consumed != CHAIN_CONFIRM_UI_HEX_LINE_CHARS) {
        return false;
    }
    offset += consumed;
    if (!chain_confirm_ui_copy_hex_line(line, sizeof(line), hex, hex_len, offset, &consumed)
        || strcmp(line, "187102858a869d121366") != 0 || consumed != 20U) {
        return false;
    }
    offset += consumed;
    if (hex[offset] != '\0') {
        return false;
    }

    memset(hex, 'R', sizeof(hex));
    memcpy(hex, "0x01", sizeof("0x01"));
    if (!chain_confirm_ui_copy_hex_line(line, sizeof(line), hex, strlen("0x01"), 0, &consumed)
        || strcmp(line, "0x01") != 0 || consumed != strlen("0x01") || hex[consumed] != '\0') {
        return false;
    }

    return true;
}

static bool test_trezor_bitcoin_multisig_matcher(void)
{
    trezor_bitcoin_multisig_matcher_t matcher;
    uint8_t fingerprint_a[SHA256_LEN];
    uint8_t fingerprint_b[SHA256_LEN];
    memset(fingerprint_a, 0x11, sizeof(fingerprint_a));
    memset(fingerprint_b, 0x22, sizeof(fingerprint_b));

    trezor_bitcoin_multisig_matcher_reset(NULL);
    trezor_bitcoin_multisig_matcher_reset(&matcher);
    if (matcher.has_fingerprint || matcher.mismatched || matcher.read_only) {
        return false;
    }
    if (trezor_bitcoin_multisig_matcher_add(NULL, fingerprint_a, sizeof(fingerprint_a))
        || trezor_bitcoin_multisig_matcher_add(&matcher, NULL, sizeof(fingerprint_a))
        || trezor_bitcoin_multisig_matcher_add(&matcher, fingerprint_a, sizeof(fingerprint_a) - 1U)
        || trezor_bitcoin_multisig_matcher_check(&matcher, fingerprint_a, sizeof(fingerprint_a))) {
        return false;
    }

    if (!trezor_bitcoin_multisig_matcher_add(&matcher, fingerprint_a, sizeof(fingerprint_a))
        || !matcher.has_fingerprint || matcher.mismatched
        || !trezor_bitcoin_multisig_matcher_add(&matcher, fingerprint_a, sizeof(fingerprint_a))
        || !trezor_bitcoin_multisig_matcher_check(&matcher, fingerprint_a, sizeof(fingerprint_a))
        || trezor_bitcoin_multisig_matcher_check(&matcher, fingerprint_b, sizeof(fingerprint_b))
        || !trezor_bitcoin_multisig_matcher_output_matches(&matcher, fingerprint_a, sizeof(fingerprint_a))
        || !matcher.read_only
        || trezor_bitcoin_multisig_matcher_add(&matcher, fingerprint_a, sizeof(fingerprint_a))) {
        return false;
    }

    trezor_bitcoin_multisig_matcher_reset(&matcher);
    if (!trezor_bitcoin_multisig_matcher_add(&matcher, fingerprint_a, sizeof(fingerprint_a))
        || !trezor_bitcoin_multisig_matcher_add(&matcher, fingerprint_b, sizeof(fingerprint_b))
        || !matcher.mismatched || matcher.has_fingerprint
        || !trezor_bitcoin_multisig_matcher_check(&matcher, fingerprint_a, sizeof(fingerprint_a))
        || trezor_bitcoin_multisig_matcher_output_matches(&matcher, fingerprint_a, sizeof(fingerprint_a))
        || !matcher.read_only
        || trezor_bitcoin_multisig_matcher_add(&matcher, fingerprint_b, sizeof(fingerprint_b))) {
        return false;
    }

    trezor_bitcoin_multisig_matcher_reset(&matcher);
    if (trezor_bitcoin_multisig_matcher_output_matches(&matcher, fingerprint_a, sizeof(fingerprint_a))
        || !matcher.read_only
        || trezor_bitcoin_multisig_matcher_add(&matcher, fingerprint_a, sizeof(fingerprint_a))) {
        return false;
    }
    return true;
}

static void test_init_basic_btc_policy_state(trezor_bitcoin_signing_state_t* const state)
{
    const uint32_t path[] = { chain_path_harden(84), chain_path_harden(1), chain_path_harden(0), 0, 0 };

    wally_bzero(state, sizeof(*state));
    state->phase = TREZOR_BITCOIN_SIGNING_PHASE_READY;
    state->request.inputs_count = 1;
    state->request.outputs_count = 1;
    state->request.has_coin_name = true;
    memcpy(state->request.coin_name, "Testnet", sizeof("Testnet"));
    state->request.serialize = true;
    state->inputs_len = 1;
    state->outputs_len = 1;
    state->inputs[0].address_n_len = ARRAY_LEN(path);
    memcpy(state->inputs[0].address_n, path, sizeof(path));
    state->inputs[0].script_type = BITCOIN_P2WPKH_SPENDWITNESS;
    state->inputs[0].has_prev_hash = true;
    state->inputs[0].has_prev_index = true;
    state->inputs[0].has_amount = true;
    state->inputs[0].amount = 100000;
    state->outputs[0].has_address = true;
    memcpy(state->outputs[0].address, "tb1qgatemultisigguard0000000000000000000000000",
        sizeof("tb1qgatemultisigguard0000000000000000000000000"));
    state->outputs[0].has_amount = true;
    state->outputs[0].amount = 99000;
    state->outputs[0].script_type = BITCOIN_PAYTOADDRESS;
    state->total_input = 100000;
    state->total_output = 99000;
    state->fee = 1000;
    state->fee_rate_sats_per_vbyte = 5;
}

static bool test_trezor_bitcoin_multisig_signing_stays_rejected(void)
{
    trezor_bitcoin_signing_state_t state;

    test_init_basic_btc_policy_state(&state);
    if (!trezor_bitcoin_policy_is_basic(&state)) {
        return false;
    }
    state.inputs[0].address_n_len = 2;
    if (trezor_bitcoin_policy_is_basic(&state) || trezor_bitcoin_policy_is_p2wpkh_basic(&state)) {
        return false;
    }
    test_init_basic_btc_policy_state(&state);

    state.inputs[0].has_multisig = true;
    state.inputs[0].multisig.variant = MULTI_P2WSH;
    state.inputs[0].multisig.threshold = 2;
    state.inputs[0].multisig.num_pubkeys = 3;
    state.inputs[0].multisig.script_pubkey_len = WALLY_SCRIPTPUBKEY_P2WSH_LEN;
    state.inputs[0].multisig.script_pubkey[0] = 0;
    state.inputs[0].multisig.script_pubkey[1] = SHA256_LEN;
    if (!trezor_bitcoin_policy_has_multisig(&state) || trezor_bitcoin_policy_is_basic(&state)) {
        return false;
    }
    state.inputs_len = TREZOR_BITCOIN_TX_INPUTS_MAX + 1U;
    if (trezor_bitcoin_policy_has_multisig(&state)) {
        return false;
    }

    test_init_basic_btc_policy_state(&state);
    state.outputs[0].has_multisig = true;
    state.outputs[0].multisig.variant = MULTI_P2WSH;
    state.outputs[0].multisig.threshold = 2;
    state.outputs[0].multisig.num_pubkeys = 3;
    state.outputs[0].multisig.script_pubkey_len = WALLY_SCRIPTPUBKEY_P2WSH_LEN;
    state.outputs[0].multisig.script_pubkey[0] = 0;
    state.outputs[0].multisig.script_pubkey[1] = SHA256_LEN;
    if (!trezor_bitcoin_policy_has_multisig(&state) || trezor_bitcoin_policy_is_basic(&state)) {
        return false;
    }
    state.outputs_len = TREZOR_BITCOIN_TX_OUTPUTS_MAX + 1U;
    return !trezor_bitcoin_policy_has_multisig(&state);
}

static bool write_test_trezor_hd_node(trezor_protobuf_writer_t* const writer, const uint32_t fingerprint,
    const uint32_t child_num, const uint8_t public_key[EC_PUBLIC_KEY_LEN], const uint8_t chain_code_tag)
{
    uint8_t node_payload[128];
    uint8_t chain_code[WALLY_BIP32_CHAIN_CODE_LEN];
    trezor_protobuf_writer_t node_writer;
    memset(chain_code, chain_code_tag, sizeof(chain_code));
    trezor_protobuf_writer_init(&node_writer, node_payload, sizeof(node_payload));
    return trezor_protobuf_write_varint_field(&node_writer, 1, 3)
        && trezor_protobuf_write_varint_field(&node_writer, 2, fingerprint)
        && trezor_protobuf_write_varint_field(&node_writer, 3, child_num)
        && trezor_protobuf_write_bytes_field(&node_writer, 4, chain_code, sizeof(chain_code))
        && trezor_protobuf_write_bytes_field(&node_writer, 6, public_key, EC_PUBLIC_KEY_LEN)
        && trezor_protobuf_write_bytes_field(writer, 4, node_payload, node_writer.len);
}

static bool make_test_trezor_multisig_private_key_payload(
    const uint32_t multisig_node_field, uint8_t* const output, const size_t output_len, size_t* const written)
{
    if (!output || !written || (multisig_node_field != 1U && multisig_node_field != 4U)) {
        return false;
    }

    uint8_t node_payload[160];
    uint8_t chain_code[WALLY_BIP32_CHAIN_CODE_LEN];
    uint8_t private_key[EC_PRIVATE_KEY_LEN];
    trezor_protobuf_writer_t node_writer;
    memset(chain_code, 0x33, sizeof(chain_code));
    memset(private_key, 0x44, sizeof(private_key));
    trezor_protobuf_writer_init(&node_writer, node_payload, sizeof(node_payload));
    bool ok = trezor_protobuf_write_varint_field(&node_writer, 1, 3)
        && trezor_protobuf_write_varint_field(&node_writer, 2, 0x11223344U)
        && trezor_protobuf_write_varint_field(&node_writer, 3, 0x80000030U)
        && trezor_protobuf_write_bytes_field(&node_writer, 4, chain_code, sizeof(chain_code))
        && trezor_protobuf_write_bytes_field(&node_writer, 5, private_key, sizeof(private_key))
        && trezor_protobuf_write_bytes_field(&node_writer, 6, PRIVATE_KEY_ONE_COMPRESSED_PUBKEY,
            sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY));

    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, output, output_len);
    if (ok && multisig_node_field == 1U) {
        uint8_t node_path_payload[192];
        trezor_protobuf_writer_t node_path_writer;
        trezor_protobuf_writer_init(&node_path_writer, node_path_payload, sizeof(node_path_payload));
        ok = trezor_protobuf_write_bytes_field(&node_path_writer, 1, node_payload, node_writer.len)
            && trezor_protobuf_write_bytes_field(&writer, 1, node_path_payload, node_path_writer.len);
        wally_bzero(node_path_payload, sizeof(node_path_payload));
    } else if (ok) {
        ok = trezor_protobuf_write_bytes_field(&writer, 4, node_payload, node_writer.len);
    }
    ok = ok && trezor_protobuf_write_varint_field(&writer, 3, 1)
        && trezor_protobuf_write_varint_field(&writer, 6, 1);

    wally_bzero(node_payload, sizeof(node_payload));
    wally_bzero(chain_code, sizeof(chain_code));
    wally_bzero(private_key, sizeof(private_key));
    *written = ok ? writer.len : 0;
    return ok;
}

static bool make_test_trezor_multisig_payload(uint8_t* const output, const size_t output_len, size_t* const written)
{
    if (!output || !written) {
        return false;
    }

    uint8_t second_pubkey[EC_PUBLIC_KEY_LEN];
    memcpy(second_pubkey, PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(second_pubkey));
    second_pubkey[0] = 0x03;
    second_pubkey[EC_PUBLIC_KEY_LEN - 1U] ^= 0x55;

    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, output, output_len);
    const bool ok = write_test_trezor_hd_node(&writer, 0x01020304U, 0x80000030U, PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, 0x11)
        && write_test_trezor_hd_node(&writer, 0x05060708U, 0x80000030U, second_pubkey, 0x22)
        && trezor_protobuf_write_varint_field(&writer, 3, 2)
        && trezor_protobuf_write_varint_field(&writer, 6, 1);
    memset(second_pubkey, 0, sizeof(second_pubkey));
    if (ok) {
        *written = writer.len;
    } else {
        *written = 0;
    }
    return ok;
}

static bool trezor_test_get_eth_address(
    void* ctx, const trezor_ethereum_get_address_t* const request, char* const address, const size_t address_len)
{
    (void)ctx;
    const char expected[] = "0x52908400098527886E0F7030069857D2E4169EE7";
    if (!g_trezor_eth_address_ok || !request || !address || address_len < sizeof(expected)) {
        return false;
    }

    memcpy(&g_last_trezor_eth_address_request, request, sizeof(g_last_trezor_eth_address_request));
    memcpy(address, expected, sizeof(expected));
    return true;
}

static bool trezor_test_get_bitcoin_address(
    void* ctx, const trezor_bitcoin_get_address_t* const request, char* const address, const size_t address_len)
{
    (void)ctx;
    if (!g_trezor_bitcoin_address_ok || !request || !address || !address_len
        || (request->has_show_display && request->show_display)) {
        return false;
    }

    const uint32_t script_type = request->has_script_type ? request->script_type : BITCOIN_P2PKH_SPENDADDRESS;
    const bool mainnet = request->has_coin_name && strcmp(request->coin_name, "Bitcoin") == 0;
    bool ok = false;
    if (request->has_multisig) {
        bool has_local_pubkey = request->has_multisig_policy && request->multisig_policy.num_pubkeys > 0;
        for (size_t i = 0; has_local_pubkey && i < request->multisig_policy.num_pubkeys; ++i) {
            const uint8_t* const candidate = request->multisig_policy.pubkeys + (i * EC_PUBLIC_KEY_LEN);
            if (memcmp(candidate, PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY)) == 0) {
                break;
            }
            if (i + 1 == request->multisig_policy.num_pubkeys) {
                has_local_pubkey = false;
            }
        }
        const char* expected = NULL;
        if (has_local_pubkey && request->multisig.variant == MULTI_P2SH) {
            expected = mainnet ? "3GateMultisigP2SHMainnet1111111" : "2NGateMultisigP2SHTestnet1111111";
        } else if (has_local_pubkey && request->multisig.variant == MULTI_P2WSH) {
            expected = mainnet ? "bc1qgatemultisigp2wsh000000000000000000000000000000000"
                               : "tb1qgatemultisigp2wsh000000000000000000000000000000000";
        } else if (has_local_pubkey && request->multisig.variant == MULTI_P2WSH_P2SH) {
            expected = mainnet ? "3GateMultisigNestedMainnet111111" : "2NGateMultisigNestedTestnet111111";
        }
        if (expected && strlen(expected) < address_len) {
            memcpy(address, expected, strlen(expected) + 1);
            ok = true;
        }
    } else if (script_type == BITCOIN_P2PKH_SPENDADDRESS && !mainnet) {
        ok = bitcoin_p2pkh_testnet_address_from_compressed_pubkey(
            PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), address, address_len);
    } else if (script_type == BITCOIN_P2PKH_SPENDADDRESS && mainnet) {
        ok = bitcoin_p2pkh_mainnet_address_from_compressed_pubkey(
            PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), address, address_len);
    } else if (script_type == BITCOIN_P2WPKH_SPENDWITNESS) {
        ok = mainnet
            ? bitcoin_p2wpkh_mainnet_address_from_compressed_pubkey(
                  PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), address, address_len)
            : bitcoin_p2wpkh_testnet_address_from_compressed_pubkey(
                  PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), address, address_len);
    } else if (script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS && !mainnet) {
        ok = bitcoin_p2sh_p2wpkh_testnet_address_from_compressed_pubkey(
            PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), address, address_len);
    } else if (script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS && mainnet) {
        ok = bitcoin_p2sh_p2wpkh_mainnet_address_from_compressed_pubkey(
            PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), address, address_len);
    }
    if (!ok) {
        return false;
    }
    memcpy(&g_last_trezor_bitcoin_address_request, request, sizeof(g_last_trezor_bitcoin_address_request));
    return true;
}

static bool trezor_test_get_public_key(
    void* ctx, const trezor_public_key_request_t* const request, trezor_public_key_response_t* const response)
{
    (void)ctx;
    if (!g_trezor_public_key_ok || !request || !response) {
        return false;
    }

    memcpy(&g_last_trezor_public_key_request, request, sizeof(g_last_trezor_public_key_request));
    wally_bzero(response, sizeof(*response));
    response->depth = 4;
    response->fingerprint = 0x11223344;
    response->child_num = 0;
    response->root_fingerprint = 0xaabbccdd;
    response->has_root_fingerprint = true;
    for (size_t i = 0; i < sizeof(response->chain_code); ++i) {
        response->chain_code[i] = (uint8_t)(i + 1);
    }
    response->public_key[0] = 0x02;
    for (size_t i = 1; i < sizeof(response->public_key); ++i) {
        response->public_key[i] = (uint8_t)(0x80 + i);
    }

    uint32_t public_version = BIP32_VER_MAIN_PUBLIC;
    if (!trezor_bitcoin_public_node_version(request, &public_version)) {
        public_version = BIP32_VER_MAIN_PUBLIC;
    }

    uint8_t serialized[BIP32_SERIALIZED_LEN];
    size_t offset = 0;
    write_u32_be(serialized + offset, public_version);
    offset += sizeof(uint32_t);
    serialized[offset++] = response->depth;
    write_u32_be(serialized + offset, response->fingerprint);
    offset += sizeof(uint32_t);
    write_u32_be(serialized + offset, response->child_num);
    offset += sizeof(uint32_t);
    memcpy(serialized + offset, response->chain_code, sizeof(response->chain_code));
    offset += sizeof(response->chain_code);
    memcpy(serialized + offset, response->public_key, sizeof(response->public_key));
    offset += sizeof(response->public_key);

    char* xpub = NULL;
    const bool xpub_ok = offset == sizeof(serialized)
        && wally_base58_from_bytes(serialized, sizeof(serialized), BASE58_FLAG_CHECKSUM, &xpub) == WALLY_OK && xpub
        && strlen(xpub) < sizeof(response->xpub);
    if (xpub_ok) {
        memcpy(response->xpub, xpub, strlen(xpub) + 1);
    }
    if (xpub) {
        wally_free_string(xpub);
    }
    wally_bzero(serialized, sizeof(serialized));
    if (!xpub_ok) {
        return false;
    }
    return true;
}

static bool trezor_test_sign_eth_tx(
    void* ctx, const ethereum_tx_preflight_request_t* const request, ethereum_signature_t* const signature)
{
    (void)ctx;
    if (!g_trezor_eth_sign_ok || !request || !signature) {
        return false;
    }

    ++g_trezor_eth_sign_calls;
    memcpy(&g_last_trezor_eth_sign_request, request, sizeof(g_last_trezor_eth_sign_request));
    wally_bzero(g_last_trezor_eth_sign_path, sizeof(g_last_trezor_eth_sign_path));
    wally_bzero(g_last_trezor_eth_sign_value, sizeof(g_last_trezor_eth_sign_value));
    wally_bzero(g_last_trezor_eth_sign_data, sizeof(g_last_trezor_eth_sign_data));
    if (request->path && request->path_len <= WALLET_CORE_MAX_PATH_LEN) {
        memcpy(g_last_trezor_eth_sign_path, request->path, request->path_len * sizeof(request->path[0]));
    }
    if (request->value && request->value_len <= EVM_ABI_WORD_LEN) {
        memcpy(g_last_trezor_eth_sign_value, request->value, request->value_len);
    }
    if (request->data && request->data_len <= ETHEREUM_TX_MAX_PREFLIGHT_DATA_LEN) {
        memcpy(g_last_trezor_eth_sign_data, request->data, request->data_len);
    }
    wally_bzero(signature, sizeof(*signature));
    signature->v = request->tx_type == ETHEREUM_TX_TYPE_EIP1559 ? 1 : (2U * request->chain_id) + 35U;
    for (size_t i = 0; i < sizeof(signature->r); ++i) {
        signature->r[i] = (uint8_t)(0xa0 + i);
        signature->s[i] = (uint8_t)(0xc0 + i);
    }
    return true;
}

static bool trezor_test_recovery_id_from_wally_signature(const uint8_t header, uint8_t* const recovery_id)
{
    if (!recovery_id) {
        return false;
    }
    if (header == 27 || header == 28) {
        *recovery_id = (uint8_t)(header - 27);
        return true;
    }
    if (header == 31 || header == 32) {
        *recovery_id = (uint8_t)(header - 31);
        return true;
    }
    return false;
}

static bool trezor_test_sign_eth_safe_tx(void* ctx, const trezor_ethereum_sign_typed_hash_t* const typed_hash,
    const ethereum_safe_tx_t* const tx, const ethereum_safe_tx_summary_t* const result,
    const uint8_t signing_hash[ETHEREUM_TX_SIGNING_HASH_LEN],
    trezor_ethereum_typed_data_signature_t* const signature)
{
    (void)ctx;
    if (!g_trezor_eth_sign_ok || !typed_hash || !tx || !result || !signing_hash || !signature) {
        return false;
    }

    chain_confirm_summary_t summary;
    wallet_core_path_t path;
    uint8_t recoverable_signature[EC_SIGNATURE_RECOVERABLE_LEN];
    wally_bzero(&summary, sizeof(summary));
    wally_bzero(&path, sizeof(path));
    wally_bzero(recoverable_signature, sizeof(recoverable_signature));
    wally_bzero(signature, sizeof(*signature));

    ++g_trezor_eth_safe_sign_calls;
    memcpy(&g_last_trezor_eth_safe_typed_hash, typed_hash, sizeof(g_last_trezor_eth_safe_typed_hash));
    memcpy(&g_last_trezor_eth_safe_tx, tx, sizeof(g_last_trezor_eth_safe_tx));
    wally_bzero(g_last_trezor_eth_safe_tx_data, sizeof(g_last_trezor_eth_safe_tx_data));
    if (tx->data && tx->data_len <= sizeof(g_last_trezor_eth_safe_tx_data)) {
        memcpy(g_last_trezor_eth_safe_tx_data, tx->data, tx->data_len);
    }
    g_last_trezor_eth_safe_tx.data = g_last_trezor_eth_safe_tx_data;
    memcpy(g_last_trezor_eth_safe_signing_hash, signing_hash, sizeof(g_last_trezor_eth_safe_signing_hash));

    bool ok = ethereum_safe_tx_confirm_summary_from_preflight(
        typed_hash->address_n, typed_hash->address_n_len, tx, result, signing_hash, &summary)
        && show_chain_confirm_summary_activity(&summary);
    if (ok) {
        path.len = typed_hash->address_n_len;
        memcpy(path.parts, typed_hash->address_n, typed_hash->address_n_len * sizeof(typed_hash->address_n[0]));
        ok = wallet_core_sign_digest_ecdsa_recoverable(
            &path, signing_hash, ETHEREUM_TX_SIGNING_HASH_LEN, recoverable_signature, sizeof(recoverable_signature));
    }
    if (ok) {
        uint8_t recovery_id = 0;
        ok = trezor_test_recovery_id_from_wally_signature(recoverable_signature[0], &recovery_id);
        if (ok) {
            memcpy(signature->signature, recoverable_signature + 1, ETHEREUM_SIGNATURE_R_LEN);
            memcpy(signature->signature + ETHEREUM_SIGNATURE_R_LEN,
                recoverable_signature + 1 + ETHEREUM_SIGNATURE_R_LEN, ETHEREUM_SIGNATURE_S_LEN);
            signature->signature[ETHEREUM_SIGNATURE_R_LEN + ETHEREUM_SIGNATURE_S_LEN] = recovery_id;
            ok = ethereum_address_to_checksum_string(
                EXPECTED_ETH_ADDRESS, sizeof(EXPECTED_ETH_ADDRESS), signature->address, sizeof(signature->address));
        }
    }
    if (!ok) {
        wally_bzero(signature, sizeof(*signature));
    }
    wally_bzero(&summary, sizeof(summary));
    wally_bzero(&path, sizeof(path));
    wally_bzero(recoverable_signature, sizeof(recoverable_signature));
    return ok;
}

static bool trezor_test_confirm_btc_tx(void* ctx, const bitcoin_confirm_request_t* const request)
{
    (void)ctx;
    if (!request) {
        return false;
    }

    chain_confirm_summary_t summary;
    if (!bitcoin_confirm_summary_from_request(request, &summary)) {
        return false;
    }

    ++g_trezor_btc_confirm_calls;
    memcpy(&g_last_trezor_btc_confirm_request, request, sizeof(g_last_trezor_btc_confirm_request));
    return show_chain_confirm_summary_activity(&summary);
}

static bool trezor_test_sign_btc_digest(void* ctx, const wallet_core_path_t* const path, const uint8_t* const digest,
    const size_t digest_len, uint8_t* const signature, const size_t signature_len)
{
    (void)ctx;
    if (!digest || digest_len != sizeof(EXPECTED_BTC_TEST_DIGEST)) {
        return false;
    }
    ++g_trezor_btc_sign_calls;
    return wallet_core_sign_digest_ecdsa_recoverable(path, digest, digest_len, signature, signature_len);
}

static size_t g_trezor_entropy_calls = 0;
static uint32_t g_trezor_entropy_last_size = 0;
static bool g_trezor_entropy_ok = true;

static bool trezor_test_get_entropy(
    void* ctx, const uint32_t size, uint8_t* const entropy, const size_t entropy_len)
{
    (void)ctx;
    ++g_trezor_entropy_calls;
    g_trezor_entropy_last_size = size;
    if (!g_trezor_entropy_ok || size != entropy_len || size > TREZOR_GET_ENTROPY_MAX_SIZE || (!entropy && size)) {
        return false;
    }
    for (uint32_t i = 0; i < size; ++i) {
        entropy[i] = (uint8_t)(0xa0U + (i & 0x0fU));
    }
    return true;
}

static bool trezor_test_needs_local_unlock(void* ctx)
{
    (void)ctx;
    return g_trezor_needs_local_unlock;
}

static bool trezor_test_perform_local_unlock(void* ctx)
{
    (void)ctx;
    ++g_trezor_local_unlock_calls;
    if (g_trezor_local_unlock_ok) {
        g_trezor_needs_local_unlock = false;
    }
    return g_trezor_local_unlock_ok;
}

static bool trezor_test_initialize_session(
    void* ctx, const uint8_t* const session_id, const size_t session_id_len)
{
    (void)ctx;
    if (!g_trezor_initialize_session_ok || session_id_len > sizeof(g_trezor_last_initialize_session_id)) {
        return false;
    }
    g_trezor_last_initialize_session_id_len = session_id_len;
    wally_bzero(g_trezor_last_initialize_session_id, sizeof(g_trezor_last_initialize_session_id));
    if (session_id_len) {
        memcpy(g_trezor_last_initialize_session_id, session_id, session_id_len);
    }
    return true;
}

static bool trezor_payload_has_varint(
    const uint8_t* payload, size_t payload_len, uint32_t expected_field, uint64_t expected_value);

static bool trezor_test_state_has_any_pending(const trezor_session_state_t* const state)
{
    return state
        && (state->has_pending_local_unlock || state->has_pending_eth_signing || state->has_pending_eth_safe_typed_hash
            || state->has_pending_btc_signing || state->has_pending_btc_signed_tx || state->has_pending_get_entropy);
}

static void trezor_test_set_one_pending(trezor_session_state_t* const state, const size_t pending_index)
{
    wally_bzero(state, sizeof(*state));
    if (pending_index == 0) {
        state->has_pending_local_unlock = true;
        state->pending_request_type = TREZOR_MSG_ETHEREUM_GET_ADDRESS;
    } else if (pending_index == 1) {
        state->has_pending_eth_signing = true;
    } else if (pending_index == 2) {
        state->has_pending_eth_safe_typed_hash = true;
    } else if (pending_index == 3) {
        state->has_pending_btc_signing = true;
    } else if (pending_index == 4) {
        state->has_pending_btc_signed_tx = true;
        state->pending_btc_signed_tx.signatures_len = 1;
    } else if (pending_index == 5) {
        state->has_pending_get_entropy = true;
        state->pending_entropy_size = 16;
    }
}

static int trezor_test_control_messages_clear_pending(trezor_session_t* const session, uint8_t* const response_payload,
    const size_t response_payload_len)
{
    uint16_t response_type = 0;
    size_t response_payload_written = 0;
    const uint16_t control_messages[] = { TREZOR_MSG_INITIALIZE, TREZOR_MSG_CANCEL, TREZOR_MSG_END_SESSION };

    CHECK(session && session->state && response_payload);
    for (size_t pending_index = 0; pending_index < 6; ++pending_index) {
        for (size_t control_index = 0; control_index < ARRAY_LEN(control_messages); ++control_index) {
            const size_t eth_sign_before = g_trezor_eth_sign_calls;
            const size_t eth_safe_sign_before = g_trezor_eth_safe_sign_calls;
            const size_t btc_confirm_before = g_trezor_btc_confirm_calls;
            const size_t btc_sign_before = g_trezor_btc_sign_calls;
            const size_t entropy_before = g_trezor_entropy_calls;
            const size_t unlock_before = g_trezor_local_unlock_calls;

            trezor_test_set_one_pending(session->state, pending_index);
            CHECK(trezor_test_state_has_any_pending(session->state));
            CHECK(trezor_session_handle_payload(session, control_messages[control_index], NULL, 0, &response_type,
                response_payload, response_payload_len, &response_payload_written));
            if (control_messages[control_index] == TREZOR_MSG_INITIALIZE) {
                CHECK(response_type == TREZOR_MSG_FEATURES);
            } else if (control_messages[control_index] == TREZOR_MSG_CANCEL) {
                CHECK(response_type == TREZOR_MSG_FAILURE);
                CHECK(trezor_payload_has_varint(response_payload, response_payload_written, 1,
                    TREZOR_FAILURE_ACTION_CANCELLED));
            } else {
                CHECK(response_type == TREZOR_MSG_SUCCESS);
                CHECK(response_payload_written == 0);
            }
            CHECK(!trezor_test_state_has_any_pending(session->state));
            CHECK(g_trezor_eth_sign_calls == eth_sign_before);
            CHECK(g_trezor_eth_safe_sign_calls == eth_safe_sign_before);
            CHECK(g_trezor_btc_confirm_calls == btc_confirm_before);
            CHECK(g_trezor_btc_sign_calls == btc_sign_before);
            CHECK(g_trezor_entropy_calls == entropy_before);
            CHECK(g_trezor_local_unlock_calls == unlock_before);
        }
    }
    return 0;
}

static bool trezor_payload_has_varint(const uint8_t* const payload, const size_t payload_len,
    const uint32_t expected_field, const uint64_t expected_value)
{
    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    while (reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        uint64_t decoded = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            return false;
        }
        if (field_number == expected_field && wire_type == TREZOR_PROTOBUF_WIRE_VARINT
            && trezor_protobuf_read_varint_value(value, value_len, &decoded) && decoded == expected_value) {
            return true;
        }
    }
    return false;
}

static bool trezor_payload_has_bytes(const uint8_t* const payload, const size_t payload_len,
    const uint32_t expected_field, const size_t expected_len)
{
    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    while (reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            return false;
        }
        if (field_number == expected_field && wire_type == TREZOR_PROTOBUF_WIRE_LEN && value_len == expected_len) {
            return true;
        }
    }
    return false;
}

static bool trezor_btc_tx_request_has_signed_payload(const uint8_t* const payload, const size_t payload_len,
    const trezor_bitcoin_request_type_t expected_request_type, const uint32_t expected_signature_index,
    const bool expect_serialized_tx, const uint8_t expected_tx_inputs, const uint8_t expected_tx_outputs)
{
    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    bool saw_request_type = false;
    bool saw_signature = false;
    bool saw_serialized_tx = false;

    while (reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        uint64_t decoded = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            return false;
        }
        if (field_number == 1 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT
            && trezor_protobuf_read_varint_value(value, value_len, &decoded) && decoded == expected_request_type) {
            saw_request_type = true;
            continue;
        }
        if (field_number != 3 || wire_type != TREZOR_PROTOBUF_WIRE_LEN) {
            continue;
        }

        trezor_protobuf_reader_t serialized_reader;
        trezor_protobuf_reader_init(&serialized_reader, value, value_len);
        bool saw_signature_index = false;
        while (serialized_reader.pos < serialized_reader.len) {
            uint32_t serialized_field = 0;
            uint8_t serialized_wire_type = 0;
            const uint8_t* serialized_value = NULL;
            size_t serialized_value_len = 0;
            if (!trezor_protobuf_reader_next(&serialized_reader, &serialized_field, &serialized_wire_type,
                    &serialized_value, &serialized_value_len)) {
                return false;
            }
            if (serialized_field == 1 && serialized_wire_type == TREZOR_PROTOBUF_WIRE_VARINT
                && trezor_protobuf_read_varint_value(serialized_value, serialized_value_len, &decoded)
                && decoded == expected_signature_index) {
                saw_signature_index = true;
            } else if (serialized_field == 2 && serialized_wire_type == TREZOR_PROTOBUF_WIRE_LEN
                && serialized_value_len >= 2 && serialized_value[serialized_value_len - 1] == 1) {
                saw_signature = true;
            } else if (serialized_field == 3 && serialized_wire_type == TREZOR_PROTOBUF_WIRE_LEN
                && serialized_value_len > sizeof(EXPECTED_BTC_TEST_TX_BYTES)
                && serialized_value[0] == EXPECTED_BTC_TEST_TX_BYTES[0] && serialized_value[4] == 0
                && serialized_value[5] == 1 && serialized_value[6] == expected_tx_inputs
                && serialized_value_len > (size_t)(7U + (41U * expected_tx_inputs))
                && serialized_value[7U + (41U * expected_tx_inputs)] == expected_tx_outputs) {
                saw_serialized_tx = true;
            }
        }
        if (!saw_signature_index) {
            return false;
        }
    }
    return saw_request_type && saw_signature && saw_serialized_tx == expect_serialized_tx;
}

static bool trezor_btc_tx_request_has_signed_serialized_payload(
    const uint8_t* const payload, const size_t payload_len)
{
    return trezor_btc_tx_request_has_signed_payload(payload, payload_len, TREZOR_BITCOIN_REQUEST_TXFINISHED, 0, true, 1,
        1);
}

static int trezor_check_rejected_message(
    const trezor_session_t* const session, const uint16_t message_type, const char* const label)
{
    uint8_t response_payload[256];
    size_t response_payload_len = 0;
    uint16_t response_type = 0;

    if (!session || !label
        || !trezor_session_handle_payload(
            session, message_type, NULL, 0, &response_type, response_payload, sizeof(response_payload),
            &response_payload_len)
        || response_type != TREZOR_MSG_FAILURE
        || !trezor_payload_has_varint(response_payload, response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE)) {
        fprintf(stderr, "Trezor USB sensitive message was not rejected: %s (%u)\n", label, message_type);
        return 1;
    }
    return 0;
}

static int trezor_check_rejected_wire_message(
    const trezor_session_t* const session, const uint16_t message_type, const char* const label)
{
    uint8_t request_chunks[TREZOR_WIRE_CHUNK_SIZE];
    size_t request_chunks_len = 0;
    uint8_t response_chunks[TREZOR_WIRE_CHUNK_SIZE];
    size_t response_chunks_len = 0;
    uint8_t response_payload[128];
    size_t response_payload_len = 0;
    uint16_t response_type = 0;

    if (!session || !label || !trezor_wire_encode_message(message_type, NULL, 0, request_chunks,
                              sizeof(request_chunks), &request_chunks_len)
        || !trezor_session_handle_wire(
            session, request_chunks, request_chunks_len, response_chunks, sizeof(response_chunks), &response_chunks_len)
        || !trezor_wire_decode_message(
            response_chunks, response_chunks_len, &response_type, response_payload, sizeof(response_payload),
            &response_payload_len)
        || response_type != TREZOR_MSG_FAILURE
        || !trezor_payload_has_varint(response_payload, response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE)) {
        fprintf(stderr, "Trezor USB sensitive wire message was not rejected: %s (%u)\n", label, message_type);
        return 1;
    }
    return 0;
}

static bool trezor_check_invalid_wire_failure(const trezor_session_t* const session)
{
    uint8_t bad_request[TREZOR_WIRE_CHUNK_SIZE] = { 0 };
    uint8_t response_chunks[TREZOR_WIRE_CHUNK_SIZE];
    size_t response_chunks_len = 0;
    uint8_t response_payload[128];
    size_t response_payload_len = 0;
    uint16_t response_type = 0;

    bad_request[0] = TREZOR_WIRE_MARKER;
    bad_request[1] = 0;
    bad_request[2] = TREZOR_WIRE_MAGIC;
    if (!session
        || !trezor_session_handle_wire(
            session, bad_request, sizeof(bad_request), response_chunks, sizeof(response_chunks), &response_chunks_len)
        || !trezor_wire_decode_message(
            response_chunks, response_chunks_len, &response_type, response_payload, sizeof(response_payload),
            &response_payload_len)) {
        return false;
    }
    return response_type == TREZOR_MSG_FAILURE
        && trezor_payload_has_varint(response_payload, response_payload_len, 1, TREZOR_FAILURE_INVALID_PROTOCOL);
}

static bool trezor_test_handle_wire_payload_event(const trezor_session_t* const session, const uint16_t request_type,
    const uint8_t* const request_payload, const size_t request_payload_len, uint16_t* const response_type,
    uint8_t* const response_payload, const size_t response_payload_len, size_t* const response_payload_written,
    trezor_session_response_event_t* const response_event)
{
    uint8_t request_chunks[2304];
    uint8_t response_chunks[2304];
    size_t request_chunks_len = 0;
    size_t response_chunks_len = 0;
    if (!session || !response_type || !response_payload || !response_payload_written
        || (!request_payload && request_payload_len)
        || !trezor_wire_encode_message(
            request_type, request_payload, request_payload_len, request_chunks, sizeof(request_chunks),
            &request_chunks_len)
        || !trezor_session_handle_wire_ex(session, request_chunks, request_chunks_len, response_chunks,
            sizeof(response_chunks), &response_chunks_len, response_event)
        || !trezor_wire_decode_message(response_chunks, response_chunks_len, response_type, response_payload,
            response_payload_len, response_payload_written)) {
        return false;
    }
    return true;
}

static bool trezor_payload_contains_bytes(const uint8_t* const payload, const size_t payload_len,
    const uint8_t* const needle, const size_t needle_len)
{
    if (!payload || !needle || needle_len == 0 || needle_len > payload_len) {
        return false;
    }
    for (size_t i = 0; i <= payload_len - needle_len; ++i) {
        if (memcmp(payload + i, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

static bool trezor_public_key_payload_has_private_key_field(const uint8_t* const payload, const size_t payload_len)
{
    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    while (reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            return true;
        }
        if (field_number != 1 || wire_type != TREZOR_PROTOBUF_WIRE_LEN) {
            continue;
        }

        trezor_protobuf_reader_t node_reader;
        trezor_protobuf_reader_init(&node_reader, value, value_len);
        while (node_reader.pos < node_reader.len) {
            uint32_t node_field = 0;
            uint8_t node_wire_type = 0;
            const uint8_t* node_value = NULL;
            size_t node_value_len = 0;
            if (!trezor_protobuf_reader_next(
                    &node_reader, &node_field, &node_wire_type, &node_value, &node_value_len)) {
                return true;
            }
            if (node_field == 5) {
                return true;
            }
        }
    }
    return false;
}

static void make_erc20_address_uint256_call(uint8_t selector0, uint8_t selector1, uint8_t selector2, uint8_t selector3,
    const uint8_t address[EVM_ABI_ADDRESS_LEN], const uint8_t amount[EVM_ABI_WORD_LEN],
    uint8_t output[EVM_ABI_ADDRESS_UINT256_CALL_LEN])
{
    memset(output, 0, EVM_ABI_ADDRESS_UINT256_CALL_LEN);
    output[0] = selector0;
    output[1] = selector1;
    output[2] = selector2;
    output[3] = selector3;
    memcpy(output + EVM_ABI_SELECTOR_LEN + EVM_ABI_ADDRESS_PAD_LEN, address, EVM_ABI_ADDRESS_LEN);
    memcpy(output + EVM_ABI_SELECTOR_LEN + EVM_ABI_WORD_LEN, amount, EVM_ABI_WORD_LEN);
}

static void write_u16_le(uint8_t output[2], const uint16_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
}

static void write_u32_le(uint8_t output[4], const uint32_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
    output[2] = (uint8_t)(value >> 16);
    output[3] = (uint8_t)(value >> 24);
}

static void write_u32_be(uint8_t output[4], const uint32_t value)
{
    output[0] = (uint8_t)(value >> 24);
    output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8);
    output[3] = (uint8_t)value;
}

static void write_u256_u64(uint8_t output[EVM_ABI_WORD_LEN], uint64_t value)
{
    memset(output, 0, EVM_ABI_WORD_LEN);
    for (size_t i = 0; i < sizeof(value); ++i) {
        output[EVM_ABI_WORD_LEN - 1U - i] = (uint8_t)value;
        value >>= 8;
    }
}

static ethereum_safe_tx_t make_safe_usdt_transfer(uint8_t data[EVM_ABI_ADDRESS_UINT256_CALL_LEN])
{
    uint8_t amount[EVM_ABI_WORD_LEN];
    write_u256_u64(amount, 1234567);
    make_erc20_address_uint256_call(0xa9, 0x05, 0x9c, 0xbb, SAFE_TEST_RECIPIENT, amount, data);

    ethereum_safe_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.chain_id = 1;
    memcpy(tx.verifying_contract, SAFE_TEST_ADDRESS, sizeof(tx.verifying_contract));
    memcpy(tx.to, SAFE_TEST_USDT_ADDRESS, sizeof(tx.to));
    tx.data = data;
    tx.data_len = EVM_ABI_ADDRESS_UINT256_CALL_LEN;
    tx.operation = ETHEREUM_SAFE_TX_OPERATION_CALL;
    write_u256_u64(tx.safe_tx_gas, 50000);
    write_u256_u64(tx.base_gas, 21000);
    write_u256_u64(tx.gas_price, 1000000000ULL);
    write_u256_u64(tx.nonce, 7);
    return tx;
}

static bool make_trezor_safe_tx_ack_payload(const uint8_t* const data, const size_t data_len, uint8_t* const output,
    const size_t output_len, size_t* const written)
{
    static const char safe_to[] = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
    static const char zero_address[] = "0x0000000000000000000000000000000000000000";
    static const char safe_address[] = "0x1234567890abcdef1234567890abcdef12345678";
    static const uint8_t safe_tx_gas[] = { 0xc3, 0x50 };
    static const uint8_t base_gas[] = { 0x52, 0x08 };
    static const uint8_t gas_price[] = { 0x3b, 0x9a, 0xca, 0x00 };
    static const uint8_t nonce[] = { 0x07 };

    if (!output || !written || (!data && data_len)) {
        return false;
    }

    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, output, output_len);
    if (!trezor_protobuf_write_string_field(&writer, 1, safe_to)
        || !trezor_protobuf_write_bytes_field(&writer, 2, NULL, 0)
        || !trezor_protobuf_write_bytes_field(&writer, 3, data, data_len)
        || !trezor_protobuf_write_varint_field(&writer, 4, ETHEREUM_SAFE_TX_OPERATION_CALL)
        || !trezor_protobuf_write_bytes_field(&writer, 5, safe_tx_gas, sizeof(safe_tx_gas))
        || !trezor_protobuf_write_bytes_field(&writer, 6, base_gas, sizeof(base_gas))
        || !trezor_protobuf_write_bytes_field(&writer, 7, gas_price, sizeof(gas_price))
        || !trezor_protobuf_write_string_field(&writer, 8, zero_address)
        || !trezor_protobuf_write_string_field(&writer, 9, zero_address)
        || !trezor_protobuf_write_bytes_field(&writer, 10, nonce, sizeof(nonce))
        || !trezor_protobuf_write_varint_field(&writer, 11, 1)
        || !trezor_protobuf_write_string_field(&writer, 12, safe_address)) {
        wally_bzero(output, output_len);
        return false;
    }

    *written = writer.len;
    return true;
}

static bool make_signed_eth_token_definition(const uint8_t address[ETHEREUM_ADDRESS_LEN], const uint64_t chain_id,
    const char* const symbol, const uint32_t decimals, const char* const name, const bool valid_signature,
    uint8_t* const output, const size_t output_len, size_t* const written)
{
    if (!address || !symbol || !name || !output || !written || output_len < 128) {
        return false;
    }

    uint8_t payload[128];
    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, payload, sizeof(payload));
    if (!trezor_protobuf_write_bytes_field(&writer, 1, address, ETHEREUM_ADDRESS_LEN)
        || !trezor_protobuf_write_varint_field(&writer, 2, chain_id)
        || !trezor_protobuf_write_string_field(&writer, 3, symbol)
        || !trezor_protobuf_write_varint_field(&writer, 4, decimals)
        || !trezor_protobuf_write_string_field(&writer, 5, name)) {
        return false;
    }

    size_t pos = 0;
    const uint8_t magic[] = { 't', 'r', 'z', 'd', '1' };
    memcpy(output + pos, magic, sizeof(magic));
    pos += sizeof(magic);
    output[pos++] = 1;
    write_u32_le(output + pos, 0xffffffffU);
    pos += 4;
    write_u16_le(output + pos, (uint16_t)writer.len);
    pos += 2;
    memcpy(output + pos, payload, writer.len);
    pos += writer.len;
    output[pos++] = 0;
    output[pos++] = valid_signature ? 0x03 : 0x01;
    memset(output + pos, 0x5a, 64);
    output[pos] = valid_signature ? 0xa5 : 0x00;
    pos += 64;
    *written = pos;
    return true;
}

static bool make_eth_definitions_with_token(const uint8_t* const token_definition, const size_t token_definition_len,
    uint8_t* const output, const size_t output_len, size_t* const written)
{
    if (!token_definition || !token_definition_len || !output || !written) {
        return false;
    }

    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, output, output_len);
    if (!trezor_protobuf_write_bytes_field(&writer, 2, token_definition, token_definition_len)) {
        return false;
    }
    *written = writer.len;
    return true;
}

bool wallet_core_path_valid(const wallet_core_path_t* path)
{
    return path && path->len > 0 && path->len <= WALLET_CORE_MAX_PATH_LEN;
}

bool wallet_core_get_public_key(
    const wallet_core_path_t* path, wallet_core_pubkey_format_t format, uint8_t* output, size_t output_len)
{
    if (!g_wallet_pubkey_ok || !path || path->len == 0 || !output) {
        return false;
    }

    if (format == WALLET_CORE_PUBKEY_UNCOMPRESSED && output_len == sizeof(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY)) {
        memcpy(output, PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY));
        return true;
    }
    if (format == WALLET_CORE_PUBKEY_COMPRESSED && output_len == sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY)) {
        memcpy(output, PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY));
        return true;
    }
    return false;
}

bool wallet_core_sign_digest_ecdsa_recoverable(
    const wallet_core_path_t* path, const uint8_t* digest, size_t digest_len, uint8_t* signature, size_t signature_len)
{
    if (!g_wallet_sign_ok || !wallet_core_path_valid(path) || !digest || digest_len != CHAIN_AUTHORIZED_DIGEST_LEN
        || !signature || signature_len != EC_SIGNATURE_RECOVERABLE_LEN) {
        return false;
    }

    if (g_test_btc_compact_signatures_len > 0) {
        if (g_test_btc_compact_signature_index >= g_test_btc_compact_signatures_len) {
            return false;
        }
        memcpy(signature, g_test_btc_compact_signatures[g_test_btc_compact_signature_index++], signature_len);
        return true;
    }
    if (g_test_eth_compact_signature_has_value) {
        memcpy(signature, g_test_eth_compact_signature, signature_len);
        return true;
    }

    signature[0] = g_wallet_signature_header;
    memset(signature + 1, 0xaa, ETHEREUM_SIGNATURE_R_LEN);
    memset(signature + 1 + ETHEREUM_SIGNATURE_R_LEN, 0xbb, ETHEREUM_SIGNATURE_S_LEN);
    return true;
}

bool show_chain_confirm_summary_activity(const chain_confirm_summary_t* summary)
{
    return show_chain_confirm_summary_activity_ex(summary, false);
}

bool show_chain_confirm_summary_activity_ex(
    const chain_confirm_summary_t* summary, const bool free_managed_activities)
{
    if (!summary || (summary->flags & CHAIN_CONFIRM_FLAG_USER_CONFIRM) == 0) {
        return false;
    }

    (void)free_managed_activities;
    ++g_ui_calls;
    memcpy(&g_last_ui_summary, summary, sizeof(g_last_ui_summary));
    return g_ui_accept && test_confirm_summary_fits_tdisplay_s3(summary);
}

int wally_ec_public_key_verify(const unsigned char* pub_key, size_t pub_key_len)
{
    if (pub_key && pub_key_len == EC_PUBLIC_KEY_LEN && (pub_key[0] == 0x02 || pub_key[0] == 0x03)) {
        return WALLY_OK;
    }
    if (pub_key && pub_key_len == sizeof(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY)
        && memcmp(pub_key, PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY)) == 0) {
        return WALLY_OK;
    }
    return WALLY_EINVAL;
}

void jade_abort(const char* const file, const int line_n)
{
    (void)file;
    (void)line_n;
    abort();
}

bool is_multisig(const script_variant_t variant)
{
    return variant == MULTI_P2WSH || variant == MULTI_P2SH || variant == MULTI_P2WSH_P2SH;
}

int bip32_key_unserialize(const unsigned char* bytes, size_t bytes_len, struct ext_key* output)
{
    if (!bytes || bytes_len != BIP32_SERIALIZED_LEN || !output) {
        return WALLY_EINVAL;
    }
    memset(output, 0, sizeof(*output));
    output->version
        = ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
    output->depth = bytes[4];
    output->child_num
        = ((uint32_t)bytes[9] << 24) | ((uint32_t)bytes[10] << 16) | ((uint32_t)bytes[11] << 8) | (uint32_t)bytes[12];
    memcpy(output->chain_code, bytes + 13, sizeof(output->chain_code));
    memcpy(output->pub_key, bytes + 45, sizeof(output->pub_key));
    return (output->pub_key[0] == 0x02 || output->pub_key[0] == 0x03) ? WALLY_OK : WALLY_EINVAL;
}

int bip32_key_from_parent_path(
    const struct ext_key* hdkey, const uint32_t* child_path, size_t child_path_len, uint32_t flags, struct ext_key* output)
{
    if (!hdkey || (!child_path && child_path_len) || flags != BIP32_FLAG_KEY_PUBLIC || !output) {
        return WALLY_EINVAL;
    }
    // Host gate deliberately refuses to fake public-child derivation. The oracle
    // uses already-derived xpub nodes with an empty suffix for this C-only path.
    if (child_path_len != 0) {
        return WALLY_EINVAL;
    }
    memcpy(output, hdkey, sizeof(*output));
    return WALLY_OK;
}

int wally_base58_from_bytes(const unsigned char* bytes, size_t bytes_len, uint32_t flags, char** output)
{
    if (!bytes || flags != BASE58_FLAG_CHECKSUM || !output) {
        return WALLY_EINVAL;
    }

    const char* expected = NULL;
    size_t expected_len = 0;
    if (bytes_len == sizeof(EXPECTED_TRON_ADDRESS)
        && memcmp(bytes, EXPECTED_TRON_ADDRESS, sizeof(EXPECTED_TRON_ADDRESS)) == 0) {
        expected = "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC";
        expected_len = strlen(expected) + 1;
    } else if (bytes_len == sizeof(EXPECTED_BTC_TESTNET_ADDRESS_BYTES)
        && memcmp(bytes, EXPECTED_BTC_TESTNET_ADDRESS_BYTES, sizeof(EXPECTED_BTC_TESTNET_ADDRESS_BYTES)) == 0) {
        expected = "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r";
        expected_len = strlen(expected) + 1;
    } else if (bytes_len == sizeof(EXPECTED_BTC_MAINNET_ADDRESS_BYTES)
        && memcmp(bytes, EXPECTED_BTC_MAINNET_ADDRESS_BYTES, sizeof(EXPECTED_BTC_MAINNET_ADDRESS_BYTES)) == 0) {
        expected = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
        expected_len = strlen(expected) + 1;
    } else if (bytes_len == sizeof(EXPECTED_BTC_P2SH_P2WPKH_ADDRESS_BYTES)
        && memcmp(bytes, EXPECTED_BTC_P2SH_P2WPKH_ADDRESS_BYTES,
               sizeof(EXPECTED_BTC_P2SH_P2WPKH_ADDRESS_BYTES))
            == 0) {
        expected = "2NAUYAHhujozruyzpsFRP63mbrdaU5wnEpN";
        expected_len = strlen(expected) + 1;
    } else if (bytes_len == sizeof(EXPECTED_BTC_P2SH_P2WPKH_MAINNET_ADDRESS_BYTES)
        && memcmp(bytes, EXPECTED_BTC_P2SH_P2WPKH_MAINNET_ADDRESS_BYTES,
               sizeof(EXPECTED_BTC_P2SH_P2WPKH_MAINNET_ADDRESS_BYTES))
            == 0) {
        expected = "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN";
        expected_len = strlen(expected) + 1;
    } else if (bytes_len == BIP32_SERIALIZED_LEN) {
        const uint32_t public_version = ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16)
            | ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
        if (public_version == BIP32_VER_MAIN_PUBLIC) {
            expected = "xpub6DfD3wCmNAGmk7FfeunsNRvzrikag12f6usX8wDy91889E87nqMW26t83q3FBu5KWWikMJRys2RgavhDet2whTtys3VVYrCf5rU8VUGtdw1";
        } else if (public_version == BIP32_VER_TEST_PUBLIC) {
            expected = "tpubDE2qaB2T5SEE1uSX76mxaMGNBqrEfPXieYTpVVH7Uut1tWnps4CbAYYxHs82iQ2ZJRFexswrQ8FjH7Bq3jtBauMGveEoENrtfp4YFS629sg";
        } else if (public_version == 0x049D7CB2U) {
            expected = "ypub6YVUMbsgWqpFbQSnVGaVaX2W2gu2cd2A22PjvL7rX1W1CKwM3VX4eAYG52zqBojEv9qZ6n2YKgnEUDJnNaSxVhaajPBv8m29MaXmsyQYM4n";
        } else if (public_version == 0x044A5262U) {
            expected = "upub5FAR8wC1v7eLCDgK9qRzkAeVLpKEr94AMaJrnkYJzyzUyvgS2rrp9uuhzDAVCB7ZHbNL6seJV3N2w4rXVnnuJkrBG2QDo7kCGgHCKhfWsK8";
        } else if (public_version == 0x04B24746U) {
            expected = "zpub6sKjfGYbfXMjShduKdN7nc81Cf3UZF1ew8uxhj1ju1stFRkaJ9gdGECQ6ExRBiPAKnxMrFd6nM8nMVvM6GryHwGBbitLifqddJbRGa32Jcz";
        } else if (public_version == 0x045F1CF6U) {
            expected = "vpub5ZzgSbrw4oBp3WsRzCDcxFjzWnTgnm3fGgq5a9SCNzNN32VfHX2NmyZr1R85C5mUhEV8rMErwhiapMU6DVCv6zXn8N6eP2ZgYQLqiFuYj8G";
        } else if (public_version == 0x0295B43FU) {
            expected = "Ypub6jPZUqc85oNd1ycARw3UQbNJkUwHpyhkLJ3QqbPPtnLQpWWFotuLjHQBsjxJkEx99cuXyN2fCuAjbNvYfobueBhFZrJKYAV9FJoeTujaT5k";
        } else if (public_version == 0x02AA7ED3U) {
            expected = "Zpub74DpnWH3EUv6sGoHGHq6cgTovT5jmbhFFQZdczHHGniHscKV4Z4uMM4Ktwutk9c4ZG2LiqdDfZXHUfY7PW1vSRNrSBzk85JdX2sHrUqSLZN";
        } else if (public_version == 0x024289EFU) {
            expected = "Upub5S4WGAvTV5Chcnqh6VtyaEzJ4cMW4VjkfqxXi1orNkptc7FLoGF6F2mdnv7xkcLTX4SJyTeRNFkY4EUHo1wrTExr6VWdCXDCAQZ4ub8xNrb";
        } else if (public_version == 0x02575483U) {
            expected = "Vpub5ktmZqbNdkkBU62ovrgbnL5oEaVx17jFaxUkVQhjkmCmfD4a3vQes6Rmp85YkWzNvhZ7iwEypv75wX5rWiMsFUeSxqD3nS2gS8ciJEEU6M9";
        }
        if (!expected) {
            return WALLY_EINVAL;
        }
        expected_len = strlen(expected) + 1;
    } else {
        return WALLY_EINVAL;
    }

    *output = malloc(expected_len);
    if (!*output) {
        return WALLY_ENOMEM;
    }
    memcpy(*output, expected, expected_len);
    return WALLY_OK;
}

int wally_addr_segwit_from_bytes(
    const unsigned char* bytes, size_t bytes_len, const char* addr_family, uint32_t flags, char** output)
{
    const char expected_testnet[] = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    const char expected_mainnet[] = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const char expected_p2wsh_testnet[] = "tb1qgatemultisigp2wsh000000000000000000000000000000000";
    const char expected_p2wsh_mainnet[] = "bc1qgatemultisigp2wsh000000000000000000000000000000000";
    if (bytes && bytes_len == WALLY_SCRIPTPUBKEY_P2WSH_LEN && addr_family && flags == 0 && output
        && bytes[0] == 0x00 && bytes[1] == SHA256_LEN) {
        const char* const expected = strcmp(addr_family, "bc") == 0 ? expected_p2wsh_mainnet
            : strcmp(addr_family, "tb") == 0                         ? expected_p2wsh_testnet
                                                                     : NULL;
        if (!expected) {
            return WALLY_EINVAL;
        }
        const size_t expected_len = strlen(expected) + 1;
        *output = malloc(expected_len);
        if (!*output) {
            return WALLY_ENOMEM;
        }
        memcpy(*output, expected, expected_len);
        return WALLY_OK;
    }
    if (!bytes || bytes_len != sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY) || !addr_family || flags != 0 || !output
        || memcmp(bytes, EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY, sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY)) != 0) {
        return WALLY_EINVAL;
    }

    const char* const expected = strcmp(addr_family, "bc") == 0 ? expected_mainnet
        : strcmp(addr_family, "tb") == 0                         ? expected_testnet
                                                                 : NULL;
    if (!expected) {
        return WALLY_EINVAL;
    }

    const size_t expected_len = strlen(expected) + 1;
    *output = malloc(expected_len);
    if (!*output) {
        return WALLY_ENOMEM;
    }
    memcpy(*output, expected, expected_len);
    return WALLY_OK;
}

int wally_addr_segwit_to_bytes(
    const char* addr, const char* addr_family, uint32_t flags, unsigned char* bytes_out, size_t len, size_t* written)
{
    const char expected_testnet[] = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    const char expected_mainnet[] = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const bool ok_testnet = addr_family && strcmp(addr_family, "tb") == 0 && addr && strcmp(addr, expected_testnet) == 0;
    const bool ok_mainnet = addr_family && strcmp(addr_family, "bc") == 0 && addr && strcmp(addr, expected_mainnet) == 0;
    if ((!ok_testnet && !ok_mainnet) || flags != 0 || !bytes_out
        || len < sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY) || !written) {
        return WALLY_EINVAL;
    }
    memcpy(bytes_out, EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY, sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY));
    *written = sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY);
    return WALLY_OK;
}

int wally_address_to_scriptpubkey(
    const char* addr, uint32_t network, unsigned char* bytes_out, size_t len, size_t* written)
{
    const bool ok_testnet_p2pkh = addr && strcmp(addr, "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r") == 0
        && network == WALLY_NETWORK_BITCOIN_TESTNET;
    const bool ok_mainnet_p2pkh = addr && strcmp(addr, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH") == 0
        && network == WALLY_NETWORK_BITCOIN_MAINNET;
    const bool ok_testnet_p2sh = addr && strcmp(addr, "2NAUYAHhujozruyzpsFRP63mbrdaU5wnEpN") == 0
        && network == WALLY_NETWORK_BITCOIN_TESTNET;
    const bool ok_mainnet_p2sh = addr && strcmp(addr, "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN") == 0
        && network == WALLY_NETWORK_BITCOIN_MAINNET;
    if (!bytes_out || !written
        || ((ok_testnet_p2pkh || ok_mainnet_p2pkh) && len < WALLY_SCRIPTPUBKEY_P2PKH_LEN)
        || ((ok_testnet_p2sh || ok_mainnet_p2sh) && len < WALLY_SCRIPTPUBKEY_P2SH_LEN)) {
        return WALLY_EINVAL;
    }

    if (ok_testnet_p2pkh || ok_mainnet_p2pkh) {
        bytes_out[0] = 0x76;
        bytes_out[1] = 0xa9;
        bytes_out[2] = HASH160_LEN;
        memcpy(bytes_out + 3, EXPECTED_BTC_TESTNET_HASH160, sizeof(EXPECTED_BTC_TESTNET_HASH160));
        bytes_out[3 + HASH160_LEN] = 0x88;
        bytes_out[4 + HASH160_LEN] = 0xac;
        *written = WALLY_SCRIPTPUBKEY_P2PKH_LEN;
        return WALLY_OK;
    }
    if (ok_testnet_p2sh || ok_mainnet_p2sh) {
        bytes_out[0] = 0xa9;
        bytes_out[1] = HASH160_LEN;
        memcpy(bytes_out + 2, EXPECTED_BTC_P2SH_P2WPKH_HASH160, sizeof(EXPECTED_BTC_P2SH_P2WPKH_HASH160));
        bytes_out[2 + HASH160_LEN] = 0x87;
        *written = WALLY_SCRIPTPUBKEY_P2SH_LEN;
        return WALLY_OK;
    }
    return WALLY_EINVAL;
}

int wally_scriptpubkey_to_address(
    const unsigned char* scriptpubkey, size_t scriptpubkey_len, uint32_t network, char** output)
{
    if (!scriptpubkey || scriptpubkey_len != WALLY_SCRIPTPUBKEY_P2SH_LEN || !output || scriptpubkey[0] != 0xa9
        || scriptpubkey[1] != HASH160_LEN || scriptpubkey[2 + HASH160_LEN] != 0x87) {
        return WALLY_EINVAL;
    }

    const char* expected = NULL;
    if (network == WALLY_NETWORK_BITCOIN_TESTNET) {
        expected = "2NGateMultisigP2SHTestnet1111111";
    } else if (network == WALLY_NETWORK_BITCOIN_MAINNET) {
        expected = "3GateMultisigP2SHMainnet1111111";
    } else {
        return WALLY_EINVAL;
    }

    const size_t expected_len = strlen(expected) + 1;
    *output = malloc(expected_len);
    if (!*output) {
        return WALLY_ENOMEM;
    }
    memcpy(*output, expected, expected_len);
    return WALLY_OK;
}

static void sort_compressed_pubkeys(uint8_t* const keys, const size_t num_keys)
{
    uint8_t tmp[EC_PUBLIC_KEY_LEN];
    for (size_t i = 0; i < num_keys; ++i) {
        for (size_t j = i + 1; j < num_keys; ++j) {
            if (memcmp(keys + (i * EC_PUBLIC_KEY_LEN), keys + (j * EC_PUBLIC_KEY_LEN), EC_PUBLIC_KEY_LEN) > 0) {
                memcpy(tmp, keys + (i * EC_PUBLIC_KEY_LEN), sizeof(tmp));
                memcpy(keys + (i * EC_PUBLIC_KEY_LEN), keys + (j * EC_PUBLIC_KEY_LEN), sizeof(tmp));
                memcpy(keys + (j * EC_PUBLIC_KEY_LEN), tmp, sizeof(tmp));
            }
        }
    }
    memset(tmp, 0, sizeof(tmp));
}

int wally_scriptpubkey_multisig_from_bytes(const unsigned char* bytes, size_t bytes_len, uint32_t threshold,
    uint32_t flags, unsigned char* bytes_out, size_t len, size_t* written)
{
    if (!bytes || bytes_len == 0 || bytes_len % EC_PUBLIC_KEY_LEN != 0 || !bytes_out || !written
        || (flags != 0 && flags != WALLY_SCRIPT_MULTISIG_SORTED)) {
        return WALLY_EINVAL;
    }
    const size_t num_keys = bytes_len / EC_PUBLIC_KEY_LEN;
    const size_t script_len = 1U + num_keys * (1U + EC_PUBLIC_KEY_LEN) + 2U;
    if (num_keys == 0 || num_keys > TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS || threshold == 0 || threshold > num_keys
        || threshold > 16 || num_keys > 16 || len < script_len) {
        return WALLY_EINVAL;
    }

    uint8_t keys[TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS * EC_PUBLIC_KEY_LEN];
    memcpy(keys, bytes, bytes_len);
    if (flags == WALLY_SCRIPT_MULTISIG_SORTED) {
        sort_compressed_pubkeys(keys, num_keys);
    }

    size_t pos = 0;
    bytes_out[pos++] = (uint8_t)(0x50U + threshold);
    for (size_t i = 0; i < num_keys; ++i) {
        bytes_out[pos++] = EC_PUBLIC_KEY_LEN;
        memcpy(bytes_out + pos, keys + (i * EC_PUBLIC_KEY_LEN), EC_PUBLIC_KEY_LEN);
        pos += EC_PUBLIC_KEY_LEN;
    }
    bytes_out[pos++] = (uint8_t)(0x50U + num_keys);
    bytes_out[pos++] = 0xae;
    *written = pos;
    memset(keys, 0, sizeof(keys));
    return pos == script_len ? WALLY_OK : WALLY_EINVAL;
}

int wally_scriptpubkey_p2sh_from_bytes(
    const unsigned char* bytes, size_t bytes_len, uint32_t flags, unsigned char* bytes_out, size_t len, size_t* written)
{
    if (!bytes || !bytes_out || !written || len < WALLY_SCRIPTPUBKEY_P2SH_LEN
        || (flags != 0 && flags != WALLY_SCRIPT_HASH160)) {
        return WALLY_EINVAL;
    }

    uint8_t hash[HASH160_LEN];
    if (flags == WALLY_SCRIPT_HASH160) {
        if (wally_hash160(bytes, bytes_len, hash, sizeof(hash)) != WALLY_OK) {
            return WALLY_EINVAL;
        }
    } else {
        if (bytes_len != sizeof(hash)) {
            return WALLY_EINVAL;
        }
        memcpy(hash, bytes, sizeof(hash));
    }

    bytes_out[0] = 0xa9;
    bytes_out[1] = HASH160_LEN;
    memcpy(bytes_out + 2, hash, sizeof(hash));
    bytes_out[2 + HASH160_LEN] = 0x87;
    *written = WALLY_SCRIPTPUBKEY_P2SH_LEN;
    memset(hash, 0, sizeof(hash));
    return WALLY_OK;
}

int wally_scriptpubkey_p2pkh_from_bytes(
    const unsigned char* bytes, size_t bytes_len, uint32_t flags, unsigned char* bytes_out, size_t len, size_t* written)
{
    if (!bytes || !bytes_out || !written || len < WALLY_SCRIPTPUBKEY_P2PKH_LEN
        || (flags != 0 && flags != WALLY_SCRIPT_HASH160)) {
        return WALLY_EINVAL;
    }

    uint8_t hash[HASH160_LEN];
    if (flags == WALLY_SCRIPT_HASH160) {
        if (wally_hash160(bytes, bytes_len, hash, sizeof(hash)) != WALLY_OK) {
            return WALLY_EINVAL;
        }
    } else {
        if (bytes_len != sizeof(hash)) {
            return WALLY_EINVAL;
        }
        memcpy(hash, bytes, sizeof(hash));
    }

    bytes_out[0] = 0x76;
    bytes_out[1] = 0xa9;
    bytes_out[2] = HASH160_LEN;
    memcpy(bytes_out + 3, hash, sizeof(hash));
    bytes_out[3 + HASH160_LEN] = 0x88;
    bytes_out[4 + HASH160_LEN] = 0xac;
    *written = WALLY_SCRIPTPUBKEY_P2PKH_LEN;
    memset(hash, 0, sizeof(hash));
    return WALLY_OK;
}

int wally_witness_program_from_bytes(const unsigned char* bytes, size_t bytes_len, uint32_t flags,
    unsigned char* bytes_out, size_t len, size_t* written)
{
    if (bytes && bytes_len > 0 && flags == WALLY_SCRIPT_SHA256 && bytes_out && len >= WALLY_SCRIPTPUBKEY_P2WSH_LEN
        && written) {
        bytes_out[0] = 0x00;
        bytes_out[1] = SHA256_LEN;
        if (wally_sha256(bytes, bytes_len, bytes_out + 2, SHA256_LEN) != WALLY_OK) {
            return WALLY_EINVAL;
        }
        *written = WALLY_SCRIPTPUBKEY_P2WSH_LEN;
        return WALLY_OK;
    }

    if (bytes && bytes_len == HASH160_LEN && flags == 0 && bytes_out
        && len >= sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY) && written) {
        bytes_out[0] = 0x00;
        bytes_out[1] = HASH160_LEN;
        memcpy(bytes_out + 2, bytes, HASH160_LEN);
        *written = sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY);
        return WALLY_OK;
    }

    if (!bytes || bytes_len != sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY)
        || memcmp(bytes, PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY)) != 0
        || flags != WALLY_SCRIPT_HASH160 || !bytes_out || len < sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY)
        || !written) {
        return WALLY_EINVAL;
    }
    memcpy(bytes_out, EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY, sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY));
    *written = sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY);
    return WALLY_OK;
}

int wally_hash160(const unsigned char* bytes, size_t bytes_len, unsigned char* bytes_out, size_t len)
{
    if (!bytes || !bytes_out || len != HASH160_LEN) {
        return WALLY_EINVAL;
    }

    if (g_host_real_multisig_hashes) {
        uint8_t sha256[SHA256_LEN];
        struct ripemd160 digest;
        sha256_Raw(bytes, bytes_len, sha256);
        ripemd160(&digest, sha256, sizeof(sha256));
        memcpy(bytes_out, digest.u.u8, len);
        memset(sha256, 0, sizeof(sha256));
        memset(&digest, 0, sizeof(digest));
    } else if (bytes_len == sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY)
        && memcmp(bytes, PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY)) == 0) {
        memcpy(bytes_out, EXPECTED_BTC_TESTNET_HASH160, sizeof(EXPECTED_BTC_TESTNET_HASH160));
    } else if (bytes_len == sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY)
        && memcmp(bytes, EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY, sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY)) == 0) {
        memcpy(bytes_out, EXPECTED_BTC_P2SH_P2WPKH_HASH160, sizeof(EXPECTED_BTC_P2SH_P2WPKH_HASH160));
    } else {
        memset(bytes_out, 0, len);
        for (size_t i = 0; i < bytes_len; ++i) {
            bytes_out[i % len] ^= bytes[i];
            bytes_out[(i * 5 + 1) % len] = (uint8_t)(bytes_out[(i * 5 + 1) % len] + bytes[i] + (uint8_t)i);
        }
        bytes_out[0] ^= (uint8_t)bytes_len;
        bytes_out[1] ^= (uint8_t)(bytes_len >> 8);
    }
    return WALLY_OK;
}

int wally_sha256(const unsigned char* bytes, size_t bytes_len, unsigned char* bytes_out, size_t len)
{
    if ((!bytes && bytes_len) || !bytes_out || len != SHA256_LEN) {
        return WALLY_EINVAL;
    }

    if (g_host_real_multisig_hashes) {
        sha256_Raw(bytes, bytes_len, bytes_out);
        return WALLY_OK;
    }

    memset(bytes_out, 0, len);
    for (size_t i = 0; i < bytes_len; ++i) {
        bytes_out[i % len] ^= bytes[i];
        bytes_out[(i * 7 + 3) % len] = (uint8_t)(bytes_out[(i * 7 + 3) % len] + bytes[i] + (uint8_t)i);
    }
    bytes_out[0] ^= (uint8_t)bytes_len;
    bytes_out[1] ^= (uint8_t)(bytes_len >> 8);
    bytes_out[2] ^= (uint8_t)(bytes_len >> 16);
    bytes_out[3] ^= (uint8_t)(bytes_len >> 24);
    return WALLY_OK;
}

int wally_free_string(char* str)
{
    free(str);
    return WALLY_OK;
}

int wally_bzero(void* bytes, size_t bytes_len)
{
    if (!bytes && bytes_len) {
        return WALLY_EINVAL;
    }
    if (bytes) {
        memset(bytes, 0, bytes_len);
    }
    return WALLY_OK;
}

void wally_clear(void* bytes, size_t bytes_len)
{
    if (bytes) {
        memzero(bytes, bytes_len);
    }
}

int wally_ec_sig_to_der(
    const unsigned char* sig, size_t sig_len, unsigned char* bytes_out, size_t len, size_t* written)
{
    if (!sig || sig_len != EC_SIGNATURE_LEN || !bytes_out || len < EC_SIGNATURE_DER_MAX_LEN || !written) {
        return WALLY_EINVAL;
    }

    const uint8_t* values[2] = { sig, sig + ETHEREUM_SIGNATURE_R_LEN };
    uint8_t encoded[2][ETHEREUM_SIGNATURE_R_LEN + 1U];
    size_t encoded_len[2] = { 0, 0 };
    memset(encoded, 0, sizeof(encoded));
    for (size_t i = 0; i < 2; ++i) {
        size_t first = 0;
        while (first < ETHEREUM_SIGNATURE_R_LEN - 1U && values[i][first] == 0) {
            ++first;
        }
        const size_t value_len = ETHEREUM_SIGNATURE_R_LEN - first;
        if ((values[i][first] & 0x80U) != 0) {
            encoded[i][0] = 0;
            memcpy(encoded[i] + 1, values[i] + first, value_len);
            encoded_len[i] = value_len + 1U;
        } else {
            memcpy(encoded[i], values[i] + first, value_len);
            encoded_len[i] = value_len;
        }
    }

    const size_t total_len = 2U + encoded_len[0] + 2U + encoded_len[1];
    if (total_len + 2U > len || total_len > UINT8_MAX) {
        return WALLY_EINVAL;
    }
    size_t pos = 0;
    bytes_out[pos++] = 0x30;
    bytes_out[pos++] = (uint8_t)total_len;
    for (size_t i = 0; i < 2; ++i) {
        bytes_out[pos++] = 0x02;
        bytes_out[pos++] = (uint8_t)encoded_len[i];
        memcpy(bytes_out + pos, encoded[i], encoded_len[i]);
        pos += encoded_len[i];
    }
    *written = pos;
    memset(encoded, 0, sizeof(encoded));
    return WALLY_OK;
}

static bool host_der_integer_to_fixed32(
    const uint8_t* const value, const size_t value_len, uint8_t output[ETHEREUM_SIGNATURE_R_LEN])
{
    if (!value || !output || value_len == 0 || value_len > ETHEREUM_SIGNATURE_R_LEN + 1U
        || (value[0] & 0x80U) != 0) {
        return false;
    }
    size_t offset = 0;
    size_t len = value_len;
    if (value_len > 1U && value[0] == 0) {
        if ((value[1] & 0x80U) == 0) {
            return false;
        }
        offset = 1U;
        len = value_len - 1U;
    }
    if (len > ETHEREUM_SIGNATURE_R_LEN) {
        return false;
    }
    memset(output, 0, ETHEREUM_SIGNATURE_R_LEN);
    memcpy(output + (ETHEREUM_SIGNATURE_R_LEN - len), value + offset, len);
    return true;
}

int wally_ec_sig_from_der(
    const unsigned char* bytes, size_t bytes_len, unsigned char* bytes_out, size_t len)
{
    if (!bytes || !bytes_out || len != EC_SIGNATURE_LEN || bytes_len < 8U || bytes_len > EC_SIGNATURE_DER_MAX_LEN
        || bytes[0] != 0x30 || bytes[1] != bytes_len - 2U) {
        return WALLY_EINVAL;
    }
    size_t pos = 2U;
    for (size_t i = 0; i < 2; ++i) {
        if (pos + 2U > bytes_len || bytes[pos++] != 0x02) {
            return WALLY_EINVAL;
        }
        const size_t value_len = bytes[pos++];
        if (value_len == 0 || value_len > bytes_len - pos
            || !host_der_integer_to_fixed32(bytes + pos, value_len, bytes_out + (i * ETHEREUM_SIGNATURE_R_LEN))) {
            memset(bytes_out, 0, len);
            return WALLY_EINVAL;
        }
        pos += value_len;
    }
    if (pos != bytes_len) {
        memset(bytes_out, 0, len);
        return WALLY_EINVAL;
    }
    return WALLY_OK;
}

static bool host_script_push(const uint8_t* const value, const size_t value_len, uint8_t* const output,
    const size_t output_len, size_t* const written)
{
    if (!value || value_len == 0 || !output || !written) {
        return false;
    }
    size_t prefix_len = 0;
    if (value_len <= 75U) {
        prefix_len = 1U;
    } else if (value_len <= UINT8_MAX) {
        prefix_len = 2U;
    } else if (value_len <= UINT16_MAX) {
        prefix_len = 3U;
    } else {
        return false;
    }
    if (prefix_len > output_len || value_len > output_len - prefix_len) {
        *written = prefix_len + value_len;
        return false;
    }
    size_t pos = 0;
    if (prefix_len == 1U) {
        output[pos++] = (uint8_t)value_len;
    } else if (prefix_len == 2U) {
        output[pos++] = 0x4c;
        output[pos++] = (uint8_t)value_len;
    } else {
        output[pos++] = 0x4d;
        output[pos++] = (uint8_t)value_len;
        output[pos++] = (uint8_t)(value_len >> 8);
    }
    memcpy(output + pos, value, value_len);
    *written = pos + value_len;
    return true;
}

int wally_scriptsig_multisig_from_bytes(const unsigned char* script, size_t script_len, const unsigned char* bytes,
    size_t bytes_len, const uint32_t* sighash, size_t sighash_len, uint32_t flags, unsigned char* bytes_out, size_t len,
    size_t* written)
{
    if (written) {
        *written = 0;
    }
    const size_t signatures_count = bytes_len / EC_SIGNATURE_LEN;
    if (!script || script_len == 0 || !bytes || bytes_len == 0 || bytes_len % EC_SIGNATURE_LEN != 0
        || signatures_count == 0 || signatures_count > TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS || !sighash
        || sighash_len != signatures_count || flags != 0 || !bytes_out || !written) {
        return WALLY_EINVAL;
    }

    uint8_t der[TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS][EC_SIGNATURE_DER_MAX_LEN + 1U];
    size_t der_lens[TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS] = { 0 };
    size_t required = 1U;
    memset(der, 0, sizeof(der));
    for (size_t i = 0; i < signatures_count; ++i) {
        if (sighash[i] > UINT8_MAX
            || wally_ec_sig_to_der(
                   bytes + (i * EC_SIGNATURE_LEN), EC_SIGNATURE_LEN, der[i], EC_SIGNATURE_DER_MAX_LEN, &der_lens[i])
                != WALLY_OK
            || der_lens[i] >= sizeof(der[i])) {
            memset(der, 0, sizeof(der));
            return WALLY_EINVAL;
        }
        der[i][der_lens[i]++] = (uint8_t)sighash[i];
        required += (der_lens[i] <= 75U ? 1U : 2U) + der_lens[i];
    }
    required += (script_len <= 75U ? 1U : script_len <= UINT8_MAX ? 2U : 3U) + script_len;
    if (len < required) {
        *written = required;
        memset(der, 0, sizeof(der));
        return WALLY_OK;
    }

    size_t pos = 0;
    bytes_out[pos++] = 0;
    for (size_t i = 0; i < signatures_count; ++i) {
        size_t pushed = 0;
        if (!host_script_push(der[i], der_lens[i], bytes_out + pos, len - pos, &pushed)) {
            memset(der, 0, sizeof(der));
            return WALLY_EINVAL;
        }
        pos += pushed;
    }
    size_t pushed = 0;
    if (!host_script_push(script, script_len, bytes_out + pos, len - pos, &pushed)) {
        memset(der, 0, sizeof(der));
        return WALLY_EINVAL;
    }
    pos += pushed;
    *written = pos;
    memset(der, 0, sizeof(der));
    return pos == required ? WALLY_OK : WALLY_EINVAL;
}

int wally_witness_multisig_from_bytes(const unsigned char* script, size_t script_len, const unsigned char* bytes,
    size_t bytes_len, const uint32_t* sighash, size_t sighash_len, uint32_t flags,
    struct wally_tx_witness_stack** witness)
{
    const size_t signatures_count = bytes_len / EC_SIGNATURE_LEN;
    if (witness) {
        *witness = NULL;
    }
    if (!script || script_len == 0 || !bytes || bytes_len == 0 || bytes_len % EC_SIGNATURE_LEN != 0
        || signatures_count == 0 || signatures_count > TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS || !sighash
        || sighash_len != signatures_count || flags != 0 || !witness
        || wally_tx_witness_stack_init_alloc(signatures_count + 2U, witness) != WALLY_OK || !*witness) {
        return WALLY_EINVAL;
    }

    (*witness)->items = calloc((*witness)->items_allocation_len, sizeof(*(*witness)->items));
    if (!(*witness)->items) {
        wally_tx_witness_stack_free(*witness);
        *witness = NULL;
        return WALLY_ENOMEM;
    }
    (*witness)->num_items = 1U;
    uint8_t der[EC_SIGNATURE_DER_MAX_LEN + 1U];
    for (size_t i = 0; i < signatures_count; ++i) {
        size_t der_len = 0;
        memset(der, 0, sizeof(der));
        if (sighash[i] > UINT8_MAX
            || wally_ec_sig_to_der(
                   bytes + (i * EC_SIGNATURE_LEN), EC_SIGNATURE_LEN, der, EC_SIGNATURE_DER_MAX_LEN, &der_len)
                != WALLY_OK
            || der_len >= sizeof(der)) {
            memset(der, 0, sizeof(der));
            wally_tx_witness_stack_free(*witness);
            *witness = NULL;
            return WALLY_EINVAL;
        }
        der[der_len++] = (uint8_t)sighash[i];
        if (wally_tx_witness_stack_add(*witness, der, der_len) != WALLY_OK) {
            memset(der, 0, sizeof(der));
            wally_tx_witness_stack_free(*witness);
            *witness = NULL;
            return WALLY_EINVAL;
        }
    }
    memset(der, 0, sizeof(der));
    if (wally_tx_witness_stack_add(*witness, script, script_len) != WALLY_OK) {
        wally_tx_witness_stack_free(*witness);
        *witness = NULL;
        return WALLY_EINVAL;
    }
    return WALLY_OK;
}

int wally_map_init(size_t allocation_len, wally_map_verify_fn_t verify_fn, struct wally_map* output)
{
    if (!output) {
        return WALLY_EINVAL;
    }
    output->items = allocation_len ? calloc(allocation_len, sizeof(*output->items)) : NULL;
    if (allocation_len && !output->items) {
        return WALLY_ENOMEM;
    }
    output->num_items = 0;
    output->items_allocation_len = allocation_len;
    output->verify_fn = verify_fn;
    return WALLY_OK;
}

int wally_map_add_integer(struct wally_map* map_in, uint32_t key, const unsigned char* value, size_t value_len)
{
    if (!map_in || !value || value_len == 0 || map_in->num_items >= map_in->items_allocation_len) {
        return WALLY_EINVAL;
    }
    struct wally_map_item* const item = &map_in->items[map_in->num_items];
    item->key = NULL;
    item->key_len = key;
    item->value = malloc(value_len);
    if (!item->value) {
        return WALLY_ENOMEM;
    }
    memcpy(item->value, value, value_len);
    item->value_len = value_len;
    ++map_in->num_items;
    return WALLY_OK;
}

int wally_map_clear(struct wally_map* map_in)
{
    if (!map_in) {
        return WALLY_EINVAL;
    }
    for (size_t i = 0; i < map_in->num_items; ++i) {
        free(map_in->items[i].key);
        free(map_in->items[i].value);
    }
    free(map_in->items);
    memset(map_in, 0, sizeof(*map_in));
    return WALLY_OK;
}

int wally_tx_init_alloc(uint32_t version, uint32_t locktime, size_t inputs_allocation_len,
    size_t outputs_allocation_len, struct wally_tx** output)
{
    if (!output || inputs_allocation_len == 0 || outputs_allocation_len == 0
        || inputs_allocation_len > TREZOR_BITCOIN_TX_INPUTS_MAX
        || outputs_allocation_len > TREZOR_BITCOIN_TX_OUTPUTS_MAX) {
        return WALLY_EINVAL;
    }
    struct wally_tx* tx = calloc(1, sizeof(*tx));
    if (!tx) {
        return WALLY_ENOMEM;
    }
    tx->version = version;
    tx->locktime = locktime;
    tx->inputs_allocation_len = inputs_allocation_len;
    tx->outputs_allocation_len = outputs_allocation_len;
    tx->inputs = calloc(inputs_allocation_len, sizeof(*tx->inputs));
    tx->outputs = calloc(outputs_allocation_len, sizeof(*tx->outputs));
    if (!tx->inputs || !tx->outputs) {
        free(tx->inputs);
        free(tx->outputs);
        free(tx);
        return WALLY_ENOMEM;
    }
    *output = tx;
    return WALLY_OK;
}

int wally_tx_free(struct wally_tx* tx)
{
    if (tx) {
        for (size_t i = 0; i < tx->num_inputs; ++i) {
            free(tx->inputs[i].script);
            if (tx->inputs[i].witness) {
                wally_tx_witness_stack_free(tx->inputs[i].witness);
            }
        }
        for (size_t i = 0; i < tx->num_outputs; ++i) {
            free(tx->outputs[i].script);
        }
        free(tx->inputs);
        free(tx->outputs);
    }
    free(tx);
    return WALLY_OK;
}

int wally_tx_add_raw_input(struct wally_tx* tx, const unsigned char* txhash, size_t txhash_len, uint32_t utxo_index,
    uint32_t sequence, const unsigned char* script, size_t script_len, const struct wally_tx_witness_stack* witness,
    uint32_t flags)
{
    if (!tx || !txhash || txhash_len != WALLY_TXHASH_LEN || flags != 0) {
        return WALLY_EINVAL;
    }
    if (tx->num_inputs >= tx->inputs_allocation_len) {
        return WALLY_EINVAL;
    }
    struct wally_tx_input* const input = &tx->inputs[tx->num_inputs];
    memcpy(input->txhash, txhash, WALLY_TXHASH_LEN);
    input->index = utxo_index;
    input->sequence = sequence;
    if (script_len) {
        if (!script) {
            return WALLY_EINVAL;
        }
        input->script = malloc(script_len);
        if (!input->script) {
            return WALLY_ENOMEM;
        }
        memcpy(input->script, script, script_len);
        input->script_len = script_len;
    }
    if (witness) {
        input->witness = calloc(1, sizeof(*input->witness));
        if (!input->witness) {
            return WALLY_ENOMEM;
        }
        input->witness->items_allocation_len = witness->items_allocation_len;
        input->witness->num_items = witness->num_items;
        input->witness->items = calloc(witness->num_items, sizeof(*input->witness->items));
        if (!input->witness->items) {
            return WALLY_ENOMEM;
        }
        for (size_t i = 0; i < witness->num_items; ++i) {
            input->witness->items[i].witness = malloc(witness->items[i].witness_len);
            if (!input->witness->items[i].witness) {
                return WALLY_ENOMEM;
            }
            memcpy(input->witness->items[i].witness, witness->items[i].witness, witness->items[i].witness_len);
            input->witness->items[i].witness_len = witness->items[i].witness_len;
        }
    }
    ++tx->num_inputs;
    return WALLY_OK;
}

int wally_tx_add_raw_output(
    struct wally_tx* tx, uint64_t satoshi, const unsigned char* script, size_t script_len, uint32_t flags)
{
    if (!tx || !script || script_len == 0 || flags != 0) {
        return WALLY_EINVAL;
    }
    if (tx->num_outputs >= tx->outputs_allocation_len) {
        return WALLY_EINVAL;
    }
    struct wally_tx_output* const output = &tx->outputs[tx->num_outputs];
    output->satoshi = satoshi;
    output->script = malloc(script_len);
    if (!output->script) {
        return WALLY_ENOMEM;
    }
    memcpy(output->script, script, script_len);
    output->script_len = script_len;
    ++tx->num_outputs;
    return WALLY_OK;
}

typedef struct {
    uint8_t bytes[8192];
    size_t len;
} host_tx_hash_writer_t;

static bool host_hash_write(host_tx_hash_writer_t* const writer, const void* const bytes, const size_t bytes_len)
{
    if (!writer || (!bytes && bytes_len) || bytes_len > sizeof(writer->bytes) - writer->len) {
        return false;
    }
    memcpy(writer->bytes + writer->len, bytes, bytes_len);
    writer->len += bytes_len;
    return true;
}

static bool host_hash_write_u32(host_tx_hash_writer_t* const writer, const uint32_t value)
{
    const uint8_t encoded[] = { (uint8_t)value, (uint8_t)(value >> 8), (uint8_t)(value >> 16), (uint8_t)(value >> 24) };
    return host_hash_write(writer, encoded, sizeof(encoded));
}

static bool host_hash_write_u64(host_tx_hash_writer_t* const writer, const uint64_t value)
{
    uint8_t encoded[sizeof(value)];
    for (size_t i = 0; i < sizeof(encoded); ++i) {
        encoded[i] = (uint8_t)(value >> (8U * i));
    }
    return host_hash_write(writer, encoded, sizeof(encoded));
}

static bool host_hash_write_compact(host_tx_hash_writer_t* const writer, const uint64_t value)
{
    if (value < 0xfdU) {
        const uint8_t encoded = (uint8_t)value;
        return host_hash_write(writer, &encoded, sizeof(encoded));
    }
    if (value <= UINT16_MAX) {
        const uint8_t encoded[] = { 0xfd, (uint8_t)value, (uint8_t)(value >> 8) };
        return host_hash_write(writer, encoded, sizeof(encoded));
    }
    if (value <= UINT32_MAX) {
        const uint8_t prefix = 0xfe;
        return host_hash_write(writer, &prefix, sizeof(prefix)) && host_hash_write_u32(writer, (uint32_t)value);
    }
    const uint8_t prefix = 0xff;
    return host_hash_write(writer, &prefix, sizeof(prefix)) && host_hash_write_u64(writer, value);
}

static void host_sha256d(const uint8_t* const bytes, const size_t bytes_len, uint8_t output[SHA256_LEN])
{
    uint8_t first[SHA256_LEN];
    sha256_Raw(bytes, bytes_len, first);
    sha256_Raw(first, sizeof(first), output);
    memset(first, 0, sizeof(first));
}

static bool host_hash_write_output(host_tx_hash_writer_t* const writer, const struct wally_tx_output* const output)
{
    return writer && output && host_hash_write_u64(writer, output->satoshi)
        && host_hash_write_compact(writer, output->script_len)
        && host_hash_write(writer, output->script, output->script_len);
}

static bool host_map_get_u64(const struct wally_map* const map, const uint32_t key, uint64_t* const output)
{
    if (!map || !output) {
        return false;
    }
    for (size_t i = 0; i < map->num_items; ++i) {
        if (!map->items[i].key && map->items[i].key_len == key && map->items[i].value_len == sizeof(*output)) {
            memcpy(output, map->items[i].value, sizeof(*output));
            return true;
        }
    }
    return false;
}

static bool host_multisig_legacy_sighash(const struct wally_tx* const tx, const size_t index,
    const uint8_t* const script, const size_t script_len, uint8_t digest[SHA256_LEN])
{
    host_tx_hash_writer_t writer = { 0 };
    bool ok = host_hash_write_u32(&writer, tx->version) && host_hash_write_compact(&writer, tx->num_inputs);
    for (size_t i = 0; ok && i < tx->num_inputs; ++i) {
        ok = host_hash_write(&writer, tx->inputs[i].txhash, sizeof(tx->inputs[i].txhash))
            && host_hash_write_u32(&writer, tx->inputs[i].index)
            && host_hash_write_compact(&writer, i == index ? script_len : 0)
            && (i != index || host_hash_write(&writer, script, script_len))
            && host_hash_write_u32(&writer, tx->inputs[i].sequence);
    }
    ok = ok && host_hash_write_compact(&writer, tx->num_outputs);
    for (size_t i = 0; ok && i < tx->num_outputs; ++i) {
        ok = host_hash_write_output(&writer, &tx->outputs[i]);
    }
    ok = ok && host_hash_write_u32(&writer, tx->locktime) && host_hash_write_u32(&writer, 1U);
    if (ok) {
        host_sha256d(writer.bytes, writer.len, digest);
    }
    memset(&writer, 0, sizeof(writer));
    return ok;
}

static bool host_multisig_segwit_sighash(const struct wally_tx* const tx, const size_t index,
    const struct wally_map* const values, const uint8_t* const script, const size_t script_len,
    uint8_t digest[SHA256_LEN])
{
    host_tx_hash_writer_t prevouts = { 0 };
    host_tx_hash_writer_t sequences = { 0 };
    host_tx_hash_writer_t outputs = { 0 };
    host_tx_hash_writer_t writer = { 0 };
    uint8_t prevouts_hash[SHA256_LEN];
    uint8_t sequences_hash[SHA256_LEN];
    uint8_t outputs_hash[SHA256_LEN];
    uint64_t amount = 0;
    bool ok = host_map_get_u64(values, (uint32_t)index, &amount);
    for (size_t i = 0; ok && i < tx->num_inputs; ++i) {
        ok = host_hash_write(&prevouts, tx->inputs[i].txhash, sizeof(tx->inputs[i].txhash))
            && host_hash_write_u32(&prevouts, tx->inputs[i].index)
            && host_hash_write_u32(&sequences, tx->inputs[i].sequence);
    }
    for (size_t i = 0; ok && i < tx->num_outputs; ++i) {
        ok = host_hash_write_output(&outputs, &tx->outputs[i]);
    }
    if (ok) {
        host_sha256d(prevouts.bytes, prevouts.len, prevouts_hash);
        host_sha256d(sequences.bytes, sequences.len, sequences_hash);
        host_sha256d(outputs.bytes, outputs.len, outputs_hash);
        ok = host_hash_write_u32(&writer, tx->version) && host_hash_write(&writer, prevouts_hash, sizeof(prevouts_hash))
            && host_hash_write(&writer, sequences_hash, sizeof(sequences_hash))
            && host_hash_write(&writer, tx->inputs[index].txhash, sizeof(tx->inputs[index].txhash))
            && host_hash_write_u32(&writer, tx->inputs[index].index) && host_hash_write_compact(&writer, script_len)
            && host_hash_write(&writer, script, script_len) && host_hash_write_u64(&writer, amount)
            && host_hash_write_u32(&writer, tx->inputs[index].sequence)
            && host_hash_write(&writer, outputs_hash, sizeof(outputs_hash))
            && host_hash_write_u32(&writer, tx->locktime) && host_hash_write_u32(&writer, 1U);
    }
    if (ok) {
        host_sha256d(writer.bytes, writer.len, digest);
    }
    memset(&prevouts, 0, sizeof(prevouts));
    memset(&sequences, 0, sizeof(sequences));
    memset(&outputs, 0, sizeof(outputs));
    memset(&writer, 0, sizeof(writer));
    memset(prevouts_hash, 0, sizeof(prevouts_hash));
    memset(sequences_hash, 0, sizeof(sequences_hash));
    memset(outputs_hash, 0, sizeof(outputs_hash));
    return ok;
}

int wally_tx_get_input_signature_hash(const struct wally_tx* tx, size_t index, const struct wally_map* scripts,
    const struct wally_map* assets, const struct wally_map* values, const unsigned char* script, size_t script_len,
    uint32_t key_version, uint32_t codesep_position, const unsigned char* annex, size_t annex_len,
    const unsigned char* genesis_blockhash, size_t genesis_blockhash_len, uint32_t sighash, uint32_t flags,
    struct wally_map* cache, unsigned char* bytes_out, size_t len)
{
    (void)scripts;
    (void)assets;
    (void)values;
    (void)key_version;
    (void)codesep_position;
    (void)annex;
    (void)annex_len;
    (void)genesis_blockhash;
    (void)genesis_blockhash_len;
    (void)cache;
    if (!tx || index >= tx->num_inputs || !script || script_len == 0 || sighash != 1
        || (flags != WALLY_SIGTYPE_SW_V0 && flags != WALLY_SIGTYPE_PRE_SW) || !bytes_out
        || len != sizeof(EXPECTED_BTC_TEST_DIGEST)) {
        return WALLY_EINVAL;
    }
    if (script_len > WALLY_SCRIPTPUBKEY_P2PKH_LEN) {
        return (flags == WALLY_SIGTYPE_PRE_SW
                       ? host_multisig_legacy_sighash(tx, index, script, script_len, bytes_out)
                       : host_multisig_segwit_sighash(tx, index, values, script, script_len, bytes_out))
            ? WALLY_OK
            : WALLY_EINVAL;
    }
    if (script_len != sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY) && script_len != WALLY_SCRIPTPUBKEY_P2PKH_LEN) {
        return WALLY_EINVAL;
    }
    memcpy(bytes_out, EXPECTED_BTC_TEST_DIGEST, sizeof(EXPECTED_BTC_TEST_DIGEST));
    bytes_out[0] ^= (uint8_t)index;
    return WALLY_OK;
}

int wally_tx_to_bytes(const struct wally_tx* tx, uint32_t flags, unsigned char* bytes_out, size_t len, size_t* written)
{
    if (!tx || (flags != WALLY_TX_FLAG_USE_WITNESS && flags != 0) || !bytes_out || !written || tx->num_inputs == 0
        || tx->num_outputs == 0) {
        return WALLY_EINVAL;
    }
    size_t pos = 0;
#define WRITE_BYTE(value)                                                                                              \
    do {                                                                                                               \
        if (pos >= len) {                                                                                              \
            return WALLY_EINVAL;                                                                                       \
        }                                                                                                              \
        bytes_out[pos++] = (uint8_t)(value);                                                                           \
    } while (false)
#define WRITE_BYTES(bytes, bytes_len)                                                                                  \
    do {                                                                                                               \
        if ((bytes_len) > len - pos) {                                                                                 \
            return WALLY_EINVAL;                                                                                       \
        }                                                                                                              \
        memcpy(bytes_out + pos, (bytes), (bytes_len));                                                                 \
        pos += (bytes_len);                                                                                            \
    } while (false)
#define WRITE_U32_LE(value)                                                                                            \
    do {                                                                                                               \
        uint32_t local_value = (uint32_t)(value);                                                                      \
        WRITE_BYTE(local_value & 0xffU);                                                                               \
        WRITE_BYTE((local_value >> 8) & 0xffU);                                                                        \
        WRITE_BYTE((local_value >> 16) & 0xffU);                                                                       \
        WRITE_BYTE((local_value >> 24) & 0xffU);                                                                       \
    } while (false)
#define WRITE_U64_LE(value)                                                                                            \
    do {                                                                                                               \
        uint64_t local_value = (uint64_t)(value);                                                                      \
        for (size_t local_i = 0; local_i < 8; ++local_i) {                                                             \
            WRITE_BYTE((local_value >> (8U * local_i)) & 0xffU);                                                       \
        }                                                                                                              \
    } while (false)
#define WRITE_COMPACT(value)                                                                                           \
    do {                                                                                                               \
        size_t local_value = (size_t)(value);                                                                          \
        if (local_value >= 0xfdU) {                                                                                    \
            return WALLY_EINVAL;                                                                                       \
        }                                                                                                              \
        WRITE_BYTE(local_value);                                                                                       \
    } while (false)

    WRITE_U32_LE(tx->version);
    if (flags == WALLY_TX_FLAG_USE_WITNESS) {
        WRITE_BYTE(0);
        WRITE_BYTE(1);
    }
    WRITE_COMPACT(tx->num_inputs);
    for (size_t i = 0; i < tx->num_inputs; ++i) {
        const struct wally_tx_input* const input = &tx->inputs[i];
        WRITE_BYTES(input->txhash, sizeof(input->txhash));
        WRITE_U32_LE(input->index);
        WRITE_COMPACT(input->script_len);
        if (input->script_len) {
            WRITE_BYTES(input->script, input->script_len);
        }
        WRITE_U32_LE(input->sequence);
    }
    WRITE_COMPACT(tx->num_outputs);
    for (size_t i = 0; i < tx->num_outputs; ++i) {
        const struct wally_tx_output* const output = &tx->outputs[i];
        WRITE_U64_LE(output->satoshi);
        WRITE_COMPACT(output->script_len);
        WRITE_BYTES(output->script, output->script_len);
    }
    if (flags == WALLY_TX_FLAG_USE_WITNESS) {
        for (size_t i = 0; i < tx->num_inputs; ++i) {
            const struct wally_tx_witness_stack* const witness = tx->inputs[i].witness;
            if (!witness || witness->num_items == 0) {
                return WALLY_EINVAL;
            }
            WRITE_COMPACT(witness->num_items);
            for (size_t j = 0; j < witness->num_items; ++j) {
                WRITE_COMPACT(witness->items[j].witness_len);
                WRITE_BYTES(witness->items[j].witness, witness->items[j].witness_len);
            }
        }
    }
    WRITE_U32_LE(tx->locktime);
    *written = pos;
#undef WRITE_COMPACT
#undef WRITE_U64_LE
#undef WRITE_U32_LE
#undef WRITE_BYTES
#undef WRITE_BYTE
    return WALLY_OK;
}

int wally_tx_get_txid(const struct wally_tx* tx, unsigned char* bytes_out, size_t len)
{
    if (!tx || !bytes_out || len != SHA256_LEN || tx->num_inputs == 0 || tx->num_outputs == 0) {
        return WALLY_EINVAL;
    }
    uint8_t serialized[2048];
    size_t pos = 0;
#define WRITE_BYTE(value)                                                                                              \
    do {                                                                                                               \
        if (pos >= sizeof(serialized)) {                                                                               \
            return WALLY_EINVAL;                                                                                       \
        }                                                                                                              \
        serialized[pos++] = (uint8_t)(value);                                                                          \
    } while (false)
#define WRITE_BYTES(bytes, bytes_len)                                                                                  \
    do {                                                                                                               \
        if ((bytes_len) > sizeof(serialized) - pos) {                                                                  \
            return WALLY_EINVAL;                                                                                       \
        }                                                                                                              \
        memcpy(serialized + pos, (bytes), (bytes_len));                                                                \
        pos += (bytes_len);                                                                                            \
    } while (false)
#define WRITE_U32_LE(value)                                                                                            \
    do {                                                                                                               \
        uint32_t local_value = (uint32_t)(value);                                                                      \
        WRITE_BYTE(local_value & 0xffU);                                                                               \
        WRITE_BYTE((local_value >> 8) & 0xffU);                                                                        \
        WRITE_BYTE((local_value >> 16) & 0xffU);                                                                       \
        WRITE_BYTE((local_value >> 24) & 0xffU);                                                                       \
    } while (false)
#define WRITE_U64_LE(value)                                                                                            \
    do {                                                                                                               \
        uint64_t local_value = (uint64_t)(value);                                                                      \
        for (size_t local_i = 0; local_i < 8; ++local_i) {                                                             \
            WRITE_BYTE((local_value >> (8U * local_i)) & 0xffU);                                                       \
        }                                                                                                              \
    } while (false)
#define WRITE_COMPACT(value)                                                                                           \
    do {                                                                                                               \
        size_t local_value = (size_t)(value);                                                                          \
        if (local_value >= 0xfdU) {                                                                                    \
            return WALLY_EINVAL;                                                                                       \
        }                                                                                                              \
        WRITE_BYTE(local_value);                                                                                       \
    } while (false)

    WRITE_U32_LE(tx->version);
    WRITE_COMPACT(tx->num_inputs);
    for (size_t i = 0; i < tx->num_inputs; ++i) {
        const struct wally_tx_input* const input = &tx->inputs[i];
        WRITE_BYTES(input->txhash, sizeof(input->txhash));
        WRITE_U32_LE(input->index);
        WRITE_COMPACT(input->script_len);
        if (input->script_len) {
            WRITE_BYTES(input->script, input->script_len);
        }
        WRITE_U32_LE(input->sequence);
    }
    WRITE_COMPACT(tx->num_outputs);
    for (size_t i = 0; i < tx->num_outputs; ++i) {
        const struct wally_tx_output* const output = &tx->outputs[i];
        WRITE_U64_LE(output->satoshi);
        WRITE_COMPACT(output->script_len);
        WRITE_BYTES(output->script, output->script_len);
    }
    WRITE_U32_LE(tx->locktime);
    uint8_t first_hash[SHA256_LEN];
    const bool ok = wally_sha256(serialized, pos, first_hash, sizeof(first_hash)) == WALLY_OK
        && wally_sha256(first_hash, sizeof(first_hash), bytes_out, len) == WALLY_OK;
    memset(serialized, 0, sizeof(serialized));
    memset(first_hash, 0, sizeof(first_hash));
#undef WRITE_COMPACT
#undef WRITE_U64_LE
#undef WRITE_U32_LE
#undef WRITE_BYTES
#undef WRITE_BYTE
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_tx_witness_stack_init_alloc(size_t allocation_len, struct wally_tx_witness_stack** output)
{
    if (allocation_len == 0 || allocation_len > TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS + 2U || !output) {
        return WALLY_EINVAL;
    }
    struct wally_tx_witness_stack* stack = calloc(1, sizeof(*stack));
    if (!stack) {
        return WALLY_ENOMEM;
    }
    stack->items_allocation_len = allocation_len;
    *output = stack;
    return WALLY_OK;
}

int wally_tx_witness_stack_add(
    struct wally_tx_witness_stack* stack, const unsigned char* witness, size_t witness_len)
{
    if (!stack || !witness || witness_len == 0 || stack->num_items >= stack->items_allocation_len) {
        return WALLY_EINVAL;
    }
    if (!stack->items) {
        stack->items = calloc(stack->items_allocation_len, sizeof(*stack->items));
        if (!stack->items) {
            return WALLY_ENOMEM;
        }
    }
    stack->items[stack->num_items].witness = malloc(witness_len);
    if (!stack->items[stack->num_items].witness) {
        return WALLY_ENOMEM;
    }
    memcpy(stack->items[stack->num_items].witness, witness, witness_len);
    stack->items[stack->num_items].witness_len = witness_len;
    ++stack->num_items;
    return WALLY_OK;
}

int wally_tx_witness_stack_free(struct wally_tx_witness_stack* stack)
{
    if (stack) {
        for (size_t i = 0; i < stack->num_items; ++i) {
            free(stack->items[i].witness);
        }
        free(stack->items);
    }
    free(stack);
    return WALLY_OK;
}

static void print_hex_value(const char* const key, const uint8_t* const bytes, const size_t bytes_len)
{
    static const char hex[] = "0123456789abcdef";
    printf("%s=", key);
    for (size_t i = 0; i < bytes_len; ++i) {
        putchar(hex[bytes[i] >> 4]);
        putchar(hex[bytes[i] & 0x0f]);
    }
    putchar('\n');
}

static bool parse_hex_bytes(const char* const hex, uint8_t* const output, const size_t output_len, size_t* const written)
{
    if (!hex || !output || !written) {
        return false;
    }
    const size_t hex_len = strlen(hex);
    if ((hex_len & 1U) != 0 || hex_len / 2U > output_len) {
        return false;
    }
    for (size_t i = 0; i < hex_len / 2U; ++i) {
        uint8_t high = 0;
        uint8_t low = 0;
        if (!hex_char_to_nibble(hex[2U * i], &high) || !hex_char_to_nibble(hex[(2U * i) + 1U], &low)) {
            return false;
        }
        output[i] = (uint8_t)((high << 4) | low);
    }
    *written = hex_len / 2U;
    return true;
}

static bool load_test_btc_compact_signatures_from_env(void)
{
    const char* const env = getenv("TREZOR_TEST_BTC_COMPACT_SIGNATURES");
    g_test_btc_compact_signatures_len = 0;
    g_test_btc_compact_signature_index = 0;
    memset(g_test_btc_compact_signatures, 0, sizeof(g_test_btc_compact_signatures));
    if (!env || env[0] == '\0') {
        return true;
    }

    char buffer[(TREZOR_BITCOIN_TX_INPUTS_MAX * ((2U * EC_SIGNATURE_RECOVERABLE_LEN) + 1U)) + 1U];
    const size_t env_len = strlen(env);
    if (env_len >= sizeof(buffer)) {
        return false;
    }
    memcpy(buffer, env, env_len + 1U);

    char* cursor = buffer;
    while (cursor && *cursor) {
        char* const comma = strchr(cursor, ',');
        if (comma) {
            *comma = '\0';
        }
        if (g_test_btc_compact_signatures_len >= TREZOR_BITCOIN_TX_INPUTS_MAX) {
            return false;
        }
        size_t written = 0;
        if (!parse_hex_bytes(cursor, g_test_btc_compact_signatures[g_test_btc_compact_signatures_len],
                sizeof(g_test_btc_compact_signatures[g_test_btc_compact_signatures_len]), &written)
            || written != EC_SIGNATURE_RECOVERABLE_LEN) {
            return false;
        }
        ++g_test_btc_compact_signatures_len;
        cursor = comma ? comma + 1 : NULL;
    }
    return true;
}

static bool load_test_eth_compact_signature_from_env(void)
{
    const char* const env = getenv("TREZOR_TEST_ETH_COMPACT_SIGNATURE");
    g_test_eth_compact_signature_has_value = false;
    memset(g_test_eth_compact_signature, 0, sizeof(g_test_eth_compact_signature));
    if (!env || env[0] == '\0') {
        return true;
    }

    size_t written = 0;
    if (!parse_hex_bytes(env, g_test_eth_compact_signature, sizeof(g_test_eth_compact_signature), &written)
        || written != sizeof(g_test_eth_compact_signature)) {
        return false;
    }
    g_test_eth_compact_signature_has_value = true;
    return true;
}

static bool test_wallet_entropy_modes(void)
{
    uint8_t system_entropy[WALLET_ENTROPY_256_LEN];
    uint8_t final_entropy[WALLET_ENTROPY_256_LEN];
    uint8_t user_entropy[WALLET_ENTROPY_256_LEN];
    uint8_t expected_user_entropy[WALLET_ENTROPY_256_LEN];
    uint8_t dice_rolls[WALLET_ENTROPY_DICE_MAX_ROLLS];
    uint8_t encoded[sizeof("WALLET_DICE_V1") - 1U + 1U + WALLET_ENTROPY_DICE_MAX_ROLLS];
    bool ok = false;

    for (size_t i = 0; i < sizeof(system_entropy); ++i) {
        system_entropy[i] = (uint8_t)(0xa0U + i);
    }
    for (size_t i = 0; i < sizeof(dice_rolls); ++i) {
        dice_rolls[i] = (uint8_t)(i % 6U);
    }

    bool previous_real_hashes = g_host_real_multisig_hashes;
    g_host_real_multisig_hashes = true;

    if (wallet_entropy_system_256(final_entropy)) {
        goto cleanup;
    }
    if (!wallet_entropy_standard(final_entropy, system_entropy)
        || memcmp(final_entropy, system_entropy, sizeof(final_entropy)) != 0) {
        goto cleanup;
    }
    if (wallet_entropy_dice_hash(user_entropy, dice_rolls, WALLET_ENTROPY_DICE_RECOMMENDED_ROLLS - 1U)) {
        goto cleanup;
    }
    dice_rolls[0] = 6U;
    if (wallet_entropy_dice_hash(user_entropy, dice_rolls, WALLET_ENTROPY_DICE_RECOMMENDED_ROLLS)) {
        goto cleanup;
    }
    dice_rolls[0] = 0U;

    size_t pos = 0;
    memcpy(encoded + pos, "WALLET_DICE_V1", sizeof("WALLET_DICE_V1") - 1U);
    pos += sizeof("WALLET_DICE_V1") - 1U;
    encoded[pos++] = WALLET_ENTROPY_DICE_RECOMMENDED_ROLLS;
    memcpy(encoded + pos, dice_rolls, WALLET_ENTROPY_DICE_RECOMMENDED_ROLLS);
    pos += WALLET_ENTROPY_DICE_RECOMMENDED_ROLLS;
    sha256_Raw(encoded, pos, expected_user_entropy);

    if (!wallet_entropy_dice_hash(user_entropy, dice_rolls, WALLET_ENTROPY_DICE_RECOMMENDED_ROLLS)
        || memcmp(user_entropy, expected_user_entropy, sizeof(user_entropy)) != 0) {
        goto cleanup;
    }
    if (!wallet_entropy_enhanced(
            final_entropy, system_entropy, dice_rolls, WALLET_ENTROPY_DICE_RECOMMENDED_ROLLS)) {
        goto cleanup;
    }
    for (size_t i = 0; i < sizeof(final_entropy); ++i) {
        if (final_entropy[i] != (uint8_t)(system_entropy[i] ^ expected_user_entropy[i])) {
            goto cleanup;
        }
    }

    pos = 0;
    memcpy(encoded + pos, "WALLET_DICE_V1", sizeof("WALLET_DICE_V1") - 1U);
    pos += sizeof("WALLET_DICE_V1") - 1U;
    encoded[pos++] = WALLET_ENTROPY_DICE_MAX_ROLLS;
    memcpy(encoded + pos, dice_rolls, WALLET_ENTROPY_DICE_MAX_ROLLS);
    pos += WALLET_ENTROPY_DICE_MAX_ROLLS;
    sha256_Raw(encoded, pos, expected_user_entropy);

    if (!wallet_entropy_dice_hash(user_entropy, dice_rolls, WALLET_ENTROPY_DICE_MAX_ROLLS)
        || memcmp(user_entropy, expected_user_entropy, sizeof(user_entropy)) != 0) {
        goto cleanup;
    }

    ok = true;

cleanup:
    g_host_real_multisig_hashes = previous_real_hashes;
    memset(system_entropy, 0, sizeof(system_entropy));
    memset(final_entropy, 0, sizeof(final_entropy));
    memset(user_entropy, 0, sizeof(user_entropy));
    memset(expected_user_entropy, 0, sizeof(expected_user_entropy));
    memset(dice_rolls, 0, sizeof(dice_rolls));
    memset(encoded, 0, sizeof(encoded));
    return ok;
}

static void make_oracle_test_session(trezor_session_t* const session, trezor_session_state_t* const state)
{
    static const uint8_t trezor_session_id[TREZOR_FEATURES_SESSION_ID_LEN]
        = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
              0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

    wally_bzero(state, sizeof(*state));
    wally_bzero(session, sizeof(*session));
    session->features = (trezor_features_t) { .vendor = "trezor.io",
        .fw_vendor = "Jade T-Display-S3",
        .device_id = "jade-test",
        .language = "en-US",
        .model = "Safe 5",
        .internal_model = "T3T1",
        .session_id = trezor_session_id,
        .session_id_len = sizeof(trezor_session_id),
        .major_version = 2,
        .minor_version = 1,
        .patch_version = 0,
        .initialized = true,
        .has_unlocked = true,
        .unlocked = false,
        .pin_protection = true,
        .expose_private_fields = true,
        .passphrase_protection = false,
        .capabilities = { TREZOR_CAPABILITY_BITCOIN, TREZOR_CAPABILITY_BITCOIN_LIKE, TREZOR_CAPABILITY_ETHEREUM },
        .capabilities_len = 3 };
    session->state = state;
    session->initialize_session = trezor_test_initialize_session;
    session->needs_local_unlock = trezor_test_needs_local_unlock;
    session->perform_local_unlock = trezor_test_perform_local_unlock;
    session->get_bitcoin_address = trezor_test_get_bitcoin_address;
    session->get_eth_address = trezor_test_get_eth_address;
    session->get_public_key = trezor_test_get_public_key;
    session->sign_eth_tx = trezor_test_sign_eth_tx;
    session->sign_eth_safe_tx = trezor_test_sign_eth_safe_tx;
    session->confirm_btc_tx = trezor_test_confirm_btc_tx;
    session->sign_btc_digest = trezor_test_sign_btc_digest;
}

static int run_trezor_wire_oracle(const char* const request_hex)
{
    uint8_t request_chunks[2304];
    size_t request_chunks_len = 0;
    uint8_t response_chunks[2304];
    size_t response_chunks_len = 0;
    uint8_t response_payload[TREZOR_SESSION_MAX_RESPONSE_PAYLOAD_LEN];
    size_t response_payload_len = 0;
    uint16_t response_type = 0;
    trezor_session_state_t state;
    trezor_session_t session;

    if (!parse_hex_bytes(request_hex, request_chunks, sizeof(request_chunks), &request_chunks_len)) {
        return 1;
    }

    if (!load_test_btc_compact_signatures_from_env() || !load_test_eth_compact_signature_from_env()) {
        return 1;
    }
    make_oracle_test_session(&session, &state);
    if (!trezor_session_handle_wire(
            &session, request_chunks, request_chunks_len, response_chunks, sizeof(response_chunks), &response_chunks_len)
        || !trezor_wire_decode_message(response_chunks, response_chunks_len, &response_type, response_payload,
            sizeof(response_payload), &response_payload_len)) {
        return 1;
    }

    printf("response_type=%u\n", (unsigned int)response_type);
    print_hex_value("response_payload", response_payload, response_payload_len);
    return 0;
}

static int run_trezor_wire_script(const int request_count, char** const request_hexes)
{
    uint8_t request_chunks[2304];
    size_t request_chunks_len = 0;
    uint8_t response_chunks[2304];
    size_t response_chunks_len = 0;
    uint8_t response_payload[TREZOR_SESSION_MAX_RESPONSE_PAYLOAD_LEN];
    size_t response_payload_len = 0;
    uint16_t response_type = 0;
    trezor_session_state_t state;
    trezor_session_t session;

    if (request_count <= 0 || !request_hexes) {
        return 1;
    }

    if (!load_test_btc_compact_signatures_from_env() || !load_test_eth_compact_signature_from_env()) {
        return 1;
    }
    make_oracle_test_session(&session, &state);
    printf("response_count=%d\n", request_count);
    for (int i = 0; i < request_count; ++i) {
        char key[32];
        request_chunks_len = 0;
        response_chunks_len = 0;
        response_payload_len = 0;
        response_type = 0;
        wally_bzero(request_chunks, sizeof(request_chunks));
        wally_bzero(response_chunks, sizeof(response_chunks));
        wally_bzero(response_payload, sizeof(response_payload));

        if (!parse_hex_bytes(request_hexes[i], request_chunks, sizeof(request_chunks), &request_chunks_len)
            || !trezor_session_handle_wire(&session, request_chunks, request_chunks_len, response_chunks,
                sizeof(response_chunks), &response_chunks_len)
            || !trezor_wire_decode_message(response_chunks, response_chunks_len, &response_type, response_payload,
                sizeof(response_payload), &response_payload_len)) {
            return 1;
        }

        printf("response_type_%d=%u\n", i, (unsigned int)response_type);
        if (snprintf(key, sizeof(key), "response_payload_%d", i) <= 0) {
            return 1;
        }
        print_hex_value(key, response_payload, response_payload_len);
    }
    return 0;
}

static int run_trezor_multisig_normalizer(
    const char* const multisig_hex, const char* const script_type_str, const char* const expected_script_hex)
{
    uint8_t multisig_payload[2048];
    size_t multisig_payload_len = 0;
    uint8_t expected_script[TREZOR_BITCOIN_PREV_SCRIPT_MAX_LEN];
    size_t expected_script_len = 0;
    uint32_t script_type = 0;
    unsigned int parsed_script_type = 0;
    trezor_bitcoin_multisig_t multisig;
    trezor_bitcoin_multisig_policy_t policy;
    trezor_bitcoin_multisig_descriptor_t descriptor;
    wally_bzero(&multisig, sizeof(multisig));
    wally_bzero(&policy, sizeof(policy));
    wally_bzero(&descriptor, sizeof(descriptor));

    if (!multisig_hex || !script_type_str || !expected_script_hex
        || !parse_hex_bytes(multisig_hex, multisig_payload, sizeof(multisig_payload), &multisig_payload_len)
        || !parse_hex_bytes(expected_script_hex, expected_script, sizeof(expected_script), &expected_script_len)
        || sscanf(script_type_str, "%u", &parsed_script_type) != 1 || parsed_script_type > UINT32_MAX) {
        return 1;
    }
    script_type = (uint32_t)parsed_script_type;

    const bool decoded = trezor_bitcoin_multisig_decode(multisig_payload, multisig_payload_len, &multisig);
    const bool normalized = decoded && trezor_bitcoin_multisig_normalize(&multisig, script_type, &policy);
    const bool matched = normalized
        && trezor_bitcoin_multisig_script_pubkey_matches(&policy, expected_script, expected_script_len);
    const bool descriptor_ok = normalized
        && trezor_bitcoin_multisig_policy_to_descriptor(&policy, PRIVATE_KEY_ONE_COMPRESSED_PUBKEY,
            sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), &descriptor);

    printf("decoded=%u\n", decoded ? 1U : 0U);
    printf("normalized=%u\n", normalized ? 1U : 0U);
    printf("matched=%u\n", matched ? 1U : 0U);
    printf("variant=%u\n", normalized ? (unsigned int)policy.variant : 0U);
    printf("threshold=%u\n", normalized ? (unsigned int)policy.threshold : 0U);
    printf("num_pubkeys=%u\n", normalized ? (unsigned int)policy.num_pubkeys : 0U);
    printf("sorted=%u\n", normalized && policy.sorted ? 1U : 0U);
    printf("redeem_script_len=%u\n", normalized ? (unsigned int)policy.redeem_script_len : 0U);
    printf("script_pubkey_len=%u\n", normalized ? (unsigned int)policy.script_pubkey_len : 0U);
    printf("descriptor_ok=%u\n", descriptor_ok ? 1U : 0U);
    printf("descriptor_variant=%u\n", descriptor_ok ? (unsigned int)descriptor.variant : 0U);
    printf("descriptor_threshold=%u\n", descriptor_ok ? (unsigned int)descriptor.threshold : 0U);
    printf("descriptor_num_pubkeys=%u\n", descriptor_ok ? (unsigned int)descriptor.num_pubkeys : 0U);
    printf("descriptor_sorted=%u\n", descriptor_ok && descriptor.sorted ? 1U : 0U);
    printf("descriptor_has_shared_path=%u\n", descriptor_ok && descriptor.has_shared_path ? 1U : 0U);
    printf("descriptor_has_local_pubkey=%u\n", descriptor_ok && descriptor.has_local_pubkey ? 1U : 0U);
    printf("descriptor_redeem_script_len=%u\n", descriptor_ok ? (unsigned int)descriptor.redeem_script_len : 0U);
    printf("descriptor_script_pubkey_len=%u\n", descriptor_ok ? (unsigned int)descriptor.script_pubkey_len : 0U);
    if (normalized) {
        print_hex_value("fingerprint", policy.fingerprint, sizeof(policy.fingerprint));
        print_hex_value("redeem_script", policy.redeem_script, policy.redeem_script_len);
        print_hex_value("script_pubkey", policy.script_pubkey, policy.script_pubkey_len);
    }
    if (descriptor_ok) {
        print_hex_value("descriptor_fingerprint", descriptor.fingerprint, sizeof(descriptor.fingerprint));
    }

    wally_bzero(multisig_payload, sizeof(multisig_payload));
    wally_bzero(expected_script, sizeof(expected_script));
    wally_bzero(&multisig, sizeof(multisig));
    wally_bzero(&policy, sizeof(policy));
    wally_bzero(&descriptor, sizeof(descriptor));
    return matched ? 0 : 2;
}

static int run_trezor_multisig_partial_gate(
    const char* const multisig_hex, const char* const script_type_str, const char* const local_compact_signature_hex)
{
    uint8_t multisig_payload[2048];
    size_t multisig_payload_len = 0;
    uint8_t local_compact_signature[EC_SIGNATURE_LEN];
    size_t local_compact_signature_len = 0;
    uint8_t local_der_signature[EC_SIGNATURE_DER_MAX_LEN];
    size_t local_der_signature_len = 0;
    uint8_t final_compact_signatures[TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS * EC_SIGNATURE_LEN];
    size_t final_compact_signatures_len = 0;
    size_t final_signatures_count = 0;
    unsigned int parsed_script_type = 0;
    trezor_bitcoin_multisig_t multisig;
    trezor_bitcoin_multisig_partial_t partial;
    wally_bzero(multisig_payload, sizeof(multisig_payload));
    wally_bzero(local_compact_signature, sizeof(local_compact_signature));
    wally_bzero(local_der_signature, sizeof(local_der_signature));
    wally_bzero(final_compact_signatures, sizeof(final_compact_signatures));
    wally_bzero(&multisig, sizeof(multisig));
    wally_bzero(&partial, sizeof(partial));

    const bool args_ok = multisig_hex && script_type_str && local_compact_signature_hex
        && parse_hex_bytes(multisig_hex, multisig_payload, sizeof(multisig_payload), &multisig_payload_len)
        && parse_hex_bytes(local_compact_signature_hex, local_compact_signature, sizeof(local_compact_signature),
            &local_compact_signature_len)
        && local_compact_signature_len == sizeof(local_compact_signature)
        && sscanf(script_type_str, "%u", &parsed_script_type) == 1 && parsed_script_type <= UINT32_MAX;
    const bool der_ok = args_ok
        && wally_ec_sig_to_der(local_compact_signature, sizeof(local_compact_signature), local_der_signature,
               sizeof(local_der_signature), &local_der_signature_len)
            == WALLY_OK;
    const bool decoded = der_ok && trezor_bitcoin_multisig_decode(multisig_payload, multisig_payload_len, &multisig);
    const bool prepared = decoded
        && trezor_bitcoin_multisig_partial_prepare(&multisig, (uint32_t)parsed_script_type,
            PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), &partial);
    const bool added = prepared
        && trezor_bitcoin_multisig_partial_add_local_signature(&partial, local_der_signature, local_der_signature_len);
    const bool compacted = added
        && trezor_bitcoin_multisig_partial_compact_signatures(&partial, final_compact_signatures,
            sizeof(final_compact_signatures), &final_compact_signatures_len, &final_signatures_count);
    if (!compacted) {
        printf("args_ok=%u\n", args_ok ? 1U : 0U);
        printf("der_ok=%u\n", der_ok ? 1U : 0U);
        printf("decoded=%u\n", decoded ? 1U : 0U);
        printf("prepared=%u\n", prepared ? 1U : 0U);
        printf("added=%u\n", added ? 1U : 0U);
        printf("compacted=%u\n", compacted ? 1U : 0U);
        wally_bzero(multisig_payload, sizeof(multisig_payload));
        wally_bzero(local_compact_signature, sizeof(local_compact_signature));
        wally_bzero(local_der_signature, sizeof(local_der_signature));
        wally_bzero(final_compact_signatures, sizeof(final_compact_signatures));
        wally_bzero(&multisig, sizeof(multisig));
        wally_bzero(&partial, sizeof(partial));
        return 1;
    }

    printf("partial_ok=1\n");
    printf("local_slot=%u\n", (unsigned int)partial.local_slot);
    printf("existing_signatures=%u\n", (unsigned int)(partial.existing_signatures - 1U));
    printf("final_signatures=%u\n", (unsigned int)final_signatures_count);
    printf("threshold=%u\n", (unsigned int)partial.policy.threshold);
    printf("num_pubkeys=%u\n", (unsigned int)partial.policy.num_pubkeys);
    print_hex_value("local_der_signature", local_der_signature, local_der_signature_len);
    print_hex_value("final_compact_signatures", final_compact_signatures, final_compact_signatures_len);

    wally_bzero(multisig_payload, sizeof(multisig_payload));
    wally_bzero(local_compact_signature, sizeof(local_compact_signature));
    wally_bzero(local_der_signature, sizeof(local_der_signature));
    wally_bzero(final_compact_signatures, sizeof(final_compact_signatures));
    wally_bzero(&multisig, sizeof(multisig));
    wally_bzero(&partial, sizeof(partial));
    return 0;
}

static void host_multisig_policy_to_summary(
    const trezor_bitcoin_multisig_policy_t* const policy, trezor_bitcoin_multisig_summary_t* const summary)
{
    wally_bzero(summary, sizeof(*summary));
    summary->variant = policy->variant;
    summary->threshold = policy->threshold;
    summary->num_pubkeys = (uint8_t)policy->num_pubkeys;
    summary->sorted = policy->sorted;
    summary->script_pubkey_len = policy->script_pubkey_len;
    memcpy(summary->script_pubkey, policy->script_pubkey, policy->script_pubkey_len);
}

static int run_trezor_multisig_tx_gate(const char* const multisig_hex, const char* const script_type_str,
    const char* const prevout_script_hex, const char* const witness_program_hex,
    const char* const compact_signatures_hex, const char* const path_case)
{
    uint8_t multisig_payload[2048];
    size_t multisig_payload_len = 0;
    uint8_t prevout_script[TREZOR_BITCOIN_MULTISIG_SCRIPT_PUBKEY_MAX_LEN];
    size_t prevout_script_len = 0;
    uint8_t witness_program[WALLY_SCRIPTPUBKEY_P2WSH_LEN];
    size_t witness_program_len = 0;
    uint8_t compact_signatures[TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS * EC_SIGNATURE_LEN];
    size_t compact_signatures_len = 0;
    unsigned int parsed_script_type = 0;
    trezor_bitcoin_multisig_t multisig;
    trezor_bitcoin_multisig_policy_t policy;
    trezor_bitcoin_signing_state_t state;
    bitcoin_confirm_request_t confirm;
    wallet_core_path_t path;
    uint8_t digest[SHA256_LEN];
    uint8_t serialized_tx[TREZOR_BITCOIN_SIGNED_TX_MAX_LEN];
    size_t serialized_tx_len = 0;
    wally_bzero(&multisig, sizeof(multisig));
    wally_bzero(&policy, sizeof(policy));
    wally_bzero(&state, sizeof(state));
    wally_bzero(&confirm, sizeof(confirm));
    wally_bzero(&path, sizeof(path));
    wally_bzero(digest, sizeof(digest));
    wally_bzero(serialized_tx, sizeof(serialized_tx));

    const bool witness_arg_ok = witness_program_hex && strcmp(witness_program_hex, "-") == 0
        ? true
        : parse_hex_bytes(witness_program_hex, witness_program, sizeof(witness_program), &witness_program_len);
    if (!multisig_hex || !script_type_str || !prevout_script_hex || !compact_signatures_hex
        || !parse_hex_bytes(multisig_hex, multisig_payload, sizeof(multisig_payload), &multisig_payload_len)
        || !parse_hex_bytes(prevout_script_hex, prevout_script, sizeof(prevout_script), &prevout_script_len)
        || !witness_arg_ok
        || !parse_hex_bytes(
            compact_signatures_hex, compact_signatures, sizeof(compact_signatures), &compact_signatures_len)
        || sscanf(script_type_str, "%u", &parsed_script_type) != 1 || parsed_script_type > UINT32_MAX
        || !trezor_bitcoin_multisig_decode(multisig_payload, multisig_payload_len, &multisig)) {
        return 1;
    }
    const bool mainnet_path_case = path_case && strcmp(path_case, "mainnet-valid") == 0;

    uint32_t path_type = UINT32_MAX;
    if (parsed_script_type == BITCOIN_MULTISIG_SPENDMULTISIG) {
        path_type = BITCOIN_MULTISIG_PATH_P2SH;
    } else if (parsed_script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS) {
        path_type = BITCOIN_MULTISIG_PATH_P2SH_P2WSH;
    } else if (parsed_script_type == BITCOIN_P2WPKH_SPENDWITNESS) {
        path_type = BITCOIN_MULTISIG_PATH_P2WSH;
    } else {
        return 1;
    }

    g_host_real_multisig_hashes = true;
    const bool normalized = trezor_bitcoin_multisig_normalize(&multisig, (uint32_t)parsed_script_type, &policy);
    g_host_real_multisig_hashes = false;
    if (!normalized || prevout_script_len == 0 || prevout_script_len != policy.script_pubkey_len
        || memcmp(prevout_script, policy.script_pubkey, prevout_script_len) != 0
        || witness_program_len != policy.witness_program_len
        || (witness_program_len && memcmp(witness_program, policy.witness_program, witness_program_len) != 0)
        || compact_signatures_len != policy.threshold * EC_SIGNATURE_LEN) {
        return 1;
    }

    g_host_real_multisig_hashes = true;

    state.request.inputs_count = 1;
    state.request.outputs_count = 2;
    state.request.has_coin_name = true;
    const char* const coin_name = mainnet_path_case ? "Bitcoin" : "Testnet";
    memcpy(state.request.coin_name, coin_name, strlen(coin_name) + 1U);
    state.request.version = 2;
    state.request.lock_time = 0;
    state.request.serialize = true;
    state.inputs_len = 1;
    state.outputs_len = 2;
    state.phase = TREZOR_BITCOIN_SIGNING_PHASE_READY;
    state.total_input = 100000;
    state.total_output = 95000;
    state.fee = 5000;
    state.fee_rate_sats_per_vbyte = 10;

    trezor_bitcoin_tx_input_t* const input = &state.inputs[0];
    uint32_t input_path[] = { 0x80000030U, mainnet_path_case ? 0x80000000U : 0x80000001U, 0x80000000U, 0, 0, 0 };
    uint32_t change_path[]
        = { 0x80000030U, mainnet_path_case ? 0x80000000U : 0x80000001U, 0x80000000U, 0, 1, 0 };
    size_t input_path_len = ARRAY_LEN(input_path);
    size_t change_path_len = ARRAY_LEN(change_path);
    input_path[3] = 0x80000000U | path_type;
    change_path[3] = 0x80000000U | path_type;
    if (!path_case || strcmp(path_case, "valid") == 0 || mainnet_path_case) {
        /* Valid BIP48 testnet account/change pair. */
    } else if (strcmp(path_case, "bip45-valid") == 0 && path_type == BITCOIN_MULTISIG_PATH_P2SH) {
        const uint32_t bip45_input[] = { 0x8000002dU, 0, 0, 0 };
        const uint32_t bip45_change[] = { 0x8000002dU, 0, 1, 0 };
        memcpy(input_path, bip45_input, sizeof(bip45_input));
        memcpy(change_path, bip45_change, sizeof(bip45_change));
        input_path_len = ARRAY_LEN(bip45_input);
        change_path_len = ARRAY_LEN(bip45_change);
    } else if (strcmp(path_case, "external-change") == 0) {
        change_path[4] = 0;
    } else if (strcmp(path_case, "wrong-account") == 0) {
        change_path[2] = 0x80000001U;
    } else if (strcmp(path_case, "wrong-coin") == 0) {
        change_path[1] = 0x80000000U;
    } else if (strcmp(path_case, "wrong-script") == 0) {
        change_path[3] = 0x80000000U | ((path_type + 1U) % 3U);
    } else if (strcmp(path_case, "wrong-input-script") == 0) {
        input_path[3] = 0x80000000U | ((path_type + 1U) % 3U);
    } else if (strcmp(path_case, "oversized-index") == 0) {
        change_path[5] = 1000001U;
    } else {
        return 1;
    }
    memcpy(input->address_n, input_path, input_path_len * sizeof(input_path[0]));
    input->address_n_len = input_path_len;
    input->has_prev_hash = true;
    for (size_t i = 0; i < sizeof(input->prev_hash); ++i) {
        input->prev_hash[i] = (uint8_t)i;
    }
    input->has_prev_index = true;
    input->prev_index = 1;
    input->sequence = 0xfffffffdU;
    input->script_type = (uint32_t)parsed_script_type;
    input->has_amount = true;
    input->amount = state.total_input;
    input->has_verified_prevout_script = true;
    memcpy(input->verified_prevout_script, prevout_script, prevout_script_len);
    input->verified_prevout_script_len = prevout_script_len;
    input->has_multisig = true;
    host_multisig_policy_to_summary(&policy, &input->multisig);
    state.input_has_multisig_fingerprint[0] = true;
    memcpy(state.input_multisig_fingerprints[0], policy.fingerprint, SHA256_LEN);

    trezor_bitcoin_tx_output_t* const external = &state.outputs[0];
    external->has_address = true;
    const char* const external_address = mainnet_path_case ? "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
                                                           : "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    memcpy(external->address, external_address, strlen(external_address) + 1U);
    external->has_amount = true;
    external->amount = 90000;
    external->script_type = BITCOIN_PAYTOADDRESS;

    trezor_bitcoin_tx_output_t* const change = &state.outputs[1];
    memcpy(change->address_n, change_path, change_path_len * sizeof(change_path[0]));
    change->address_n_len = change_path_len;
    change->has_amount = true;
    change->amount = 5000;
    change->script_type = BITCOIN_PAYTOMULTISIG;
    change->has_multisig = true;
    host_multisig_policy_to_summary(&policy, &change->multisig);
    state.output_has_multisig_fingerprint[1] = true;
    memcpy(state.output_multisig_fingerprints[1], policy.fingerprint, SHA256_LEN);

    const trezor_bitcoin_multisig_policy_t* policies[] = { &policy };
    const trezor_bitcoin_multisig_unlock_t unlock = { .policy = &policy,
        .compact_signatures = compact_signatures,
        .compact_signatures_len = compact_signatures_len,
        .signatures_count = policy.threshold };
    const bool summary_ok = trezor_bitcoin_signing_to_multisig_confirm_request(&state, &confirm);
    const bool digest_ok
        = trezor_bitcoin_multisig_build_hash(&state, policies, ARRAY_LEN(policies), 0, &path, digest, sizeof(digest));
    const bool tx_ok = trezor_bitcoin_multisig_build_signed_tx(
        &state, &unlock, 1, serialized_tx, sizeof(serialized_tx), &serialized_tx_len);

    printf("summary_ok=%u\n", summary_ok ? 1U : 0U);
    printf("digest_ok=%u\n", digest_ok ? 1U : 0U);
    printf("tx_ok=%u\n", tx_ok ? 1U : 0U);
    printf("summary_to=%s\n", summary_ok ? confirm.to : "");
    printf("summary_policy=%s\n", summary_ok ? confirm.policy : "");
    printf("summary_amount=%llu\n", (unsigned long long)(summary_ok ? confirm.amount : 0));
    printf("summary_change=%llu\n", (unsigned long long)(summary_ok ? confirm.change : 0));
    printf("summary_fee=%llu\n", (unsigned long long)(summary_ok ? confirm.fee : 0));
    printf("summary_fee_rate=%llu\n", (unsigned long long)(summary_ok ? confirm.fee_rate_sats_per_vbyte : 0));
    printf("path_len=%u\n", digest_ok ? (unsigned int)path.len : 0U);
    printf("path=");
    for (size_t i = 0; digest_ok && i < path.len; ++i) {
        printf("%s%u", i ? "/" : "", (unsigned int)path.parts[i]);
    }
    printf("\n");
    if (digest_ok) {
        print_hex_value("digest", digest, sizeof(digest));
    }
    if (tx_ok) {
        print_hex_value("raw_tx", serialized_tx, serialized_tx_len);
    }

    wally_bzero(multisig_payload, sizeof(multisig_payload));
    wally_bzero(prevout_script, sizeof(prevout_script));
    wally_bzero(witness_program, sizeof(witness_program));
    wally_bzero(compact_signatures, sizeof(compact_signatures));
    wally_bzero(&multisig, sizeof(multisig));
    wally_bzero(&policy, sizeof(policy));
    wally_bzero(&state, sizeof(state));
    wally_bzero(&confirm, sizeof(confirm));
    wally_bzero(&path, sizeof(path));
    wally_bzero(digest, sizeof(digest));
    wally_bzero(serialized_tx, sizeof(serialized_tx));
    g_host_real_multisig_hashes = false;
    return summary_ok && digest_ok && tx_ok ? 0 : 2;
}

static int dump_oracle_vectors(void)
{
    uint8_t eth_address[ETHEREUM_ADDRESS_LEN];
    char eth_checksum[ETHEREUM_CHECKSUM_ADDRESS_STRING_LEN];
    uint8_t tron_address[TRON_ADDRESS_LEN];
    char tron_base58[TRON_BASE58_ADDRESS_MAX_LEN];
    char btc_address[BITCOIN_P2PKH_ADDRESS_MAX_LEN];

    if (!ethereum_address_from_uncompressed_pubkey(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY,
            sizeof(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY), eth_address, sizeof(eth_address))
        || !ethereum_address_to_checksum_string(eth_address, sizeof(eth_address), eth_checksum, sizeof(eth_checksum))
        || !tron_address_from_uncompressed_pubkey(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY,
            sizeof(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY), tron_address, sizeof(tron_address))
        || !tron_address_to_base58(tron_address, sizeof(tron_address), tron_base58, sizeof(tron_base58))
        || !bitcoin_p2pkh_testnet_address_from_compressed_pubkey(
            PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), btc_address,
            sizeof(btc_address))) {
        return 1;
    }

    printf("eth_checksum_address=%s\n", eth_checksum);
    printf("tron_base58_address=%s\n", tron_base58);
    printf("btc_testnet_p2pkh_address=%s\n", btc_address);
    if (!bitcoin_p2pkh_mainnet_address_from_compressed_pubkey(
            PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), btc_address,
            sizeof(btc_address))) {
        return 1;
    }
    printf("btc_mainnet_p2pkh_address=%s\n", btc_address);
    if (!bitcoin_p2wpkh_testnet_address_from_compressed_pubkey(
            PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), btc_address,
            sizeof(btc_address))) {
        return 1;
    }
    printf("btc_testnet_p2wpkh_address=%s\n", btc_address);
    if (!bitcoin_p2wpkh_mainnet_address_from_compressed_pubkey(
            PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), btc_address,
            sizeof(btc_address))) {
        return 1;
    }
    printf("btc_mainnet_p2wpkh_address=%s\n", btc_address);
    if (!bitcoin_p2sh_p2wpkh_testnet_address_from_compressed_pubkey(
            PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), btc_address,
            sizeof(btc_address))) {
        return 1;
    }
    printf("btc_testnet_p2sh_p2wpkh_address=%s\n", btc_address);
    if (!bitcoin_p2sh_p2wpkh_mainnet_address_from_compressed_pubkey(
            PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), btc_address,
            sizeof(btc_address))) {
        return 1;
    }
    printf("btc_mainnet_p2sh_p2wpkh_address=%s\n", btc_address);

    uint8_t system_entropy[WALLET_ENTROPY_256_LEN];
    uint8_t dice_rolls[WALLET_ENTROPY_DICE_MAX_ROLLS];
    uint8_t user_entropy[WALLET_ENTROPY_256_LEN];
    uint8_t final_entropy[WALLET_ENTROPY_256_LEN];
    for (size_t i = 0; i < sizeof(system_entropy); ++i) {
        system_entropy[i] = (uint8_t)(0xa0U + i);
    }
    for (size_t i = 0; i < sizeof(dice_rolls); ++i) {
        dice_rolls[i] = (uint8_t)(i % 6U);
    }
    const bool previous_real_hashes = g_host_real_multisig_hashes;
    g_host_real_multisig_hashes = true;
    if (!wallet_entropy_standard(final_entropy, system_entropy)
        || !wallet_entropy_dice_hash(user_entropy, dice_rolls, WALLET_ENTROPY_DICE_RECOMMENDED_ROLLS)
        || !wallet_entropy_enhanced(
            final_entropy, system_entropy, dice_rolls, WALLET_ENTROPY_DICE_RECOMMENDED_ROLLS)) {
        g_host_real_multisig_hashes = previous_real_hashes;
        return 1;
    }
    print_hex_value("wallet_entropy_dice_50_hash", user_entropy, sizeof(user_entropy));
    print_hex_value("wallet_entropy_final_50", final_entropy, sizeof(final_entropy));
    if (!wallet_entropy_dice_hash(user_entropy, dice_rolls, WALLET_ENTROPY_DICE_MAX_ROLLS)
        || !wallet_entropy_enhanced(final_entropy, system_entropy, dice_rolls, WALLET_ENTROPY_DICE_MAX_ROLLS)) {
        g_host_real_multisig_hashes = previous_real_hashes;
        return 1;
    }
    print_hex_value("wallet_entropy_dice_99_hash", user_entropy, sizeof(user_entropy));
    print_hex_value("wallet_entropy_final_99", final_entropy, sizeof(final_entropy));
    g_host_real_multisig_hashes = previous_real_hashes;
    wally_bzero(system_entropy, sizeof(system_entropy));
    wally_bzero(dice_rolls, sizeof(dice_rolls));
    wally_bzero(user_entropy, sizeof(user_entropy));
    wally_bzero(final_entropy, sizeof(final_entropy));

    uint8_t signing_payload[ETHEREUM_TX_MAX_SIGNING_PAYLOAD_LEN];
    size_t signing_payload_len = 0;
    uint8_t signing_hash[ETHEREUM_TX_SIGNING_HASH_LEN];
    uint8_t eip155_value[] = { 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00 };
    const uint32_t eth_bip44[] = { chain_path_harden(44), chain_path_harden(60), chain_path_harden(0), 0, 0 };
    ethereum_tx_preflight_request_t eip155_req = {
        .path = eth_bip44,
        .path_len = ARRAY_LEN(eth_bip44),
        .tx_type = ETHEREUM_TX_TYPE_LEGACY,
        .chain_id = 1,
        .nonce = 9,
        .gas_price = 20000000000ULL,
        .gas_limit = 21000,
        .has_to = true,
        .value = eip155_value,
        .value_len = sizeof(eip155_value),
        .sender_address = eth_address,
        .sender_address_len = sizeof(eth_address),
    };
    memset(eip155_req.to, 0x35, sizeof(eip155_req.to));
    if (!ethereum_tx_signing_payload(&eip155_req, signing_payload, sizeof(signing_payload), &signing_payload_len)
        || !ethereum_tx_signing_hash(&eip155_req, signing_hash, sizeof(signing_hash))) {
        return 1;
    }
    print_hex_value("eth_eip155_signing_payload", signing_payload, signing_payload_len);
    print_hex_value("eth_eip155_signing_hash", signing_hash, sizeof(signing_hash));

    ethereum_tx_preflight_request_t type2_req = {
        .path = eth_bip44,
        .path_len = ARRAY_LEN(eth_bip44),
        .tx_type = ETHEREUM_TX_TYPE_EIP1559,
        .chain_id = 1,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 2,
        .gas_limit = 21000,
        .has_to = true,
        .sender_address = eth_address,
        .sender_address_len = sizeof(eth_address),
    };
    memset(type2_req.to, 0x35, sizeof(type2_req.to));
    if (!ethereum_tx_signing_payload(&type2_req, signing_payload, sizeof(signing_payload), &signing_payload_len)) {
        return 1;
    }
    print_hex_value("eth_eip1559_signing_payload", signing_payload, signing_payload_len);

    uint8_t token_amount[EVM_ABI_WORD_LEN] = { 0 };
    token_amount[EVM_ABI_WORD_LEN - 1] = 50;
    uint8_t erc20_transfer_data[EVM_ABI_ADDRESS_UINT256_CALL_LEN];
    uint8_t erc20_approve_data[EVM_ABI_ADDRESS_UINT256_CALL_LEN];
    make_erc20_address_uint256_call(0xa9, 0x05, 0x9c, 0xbb, EXPECTED_ETH_ADDRESS, token_amount, erc20_transfer_data);
    make_erc20_address_uint256_call(0x09, 0x5e, 0xa7, 0xb3, EXPECTED_ETH_ADDRESS, token_amount, erc20_approve_data);
    print_hex_value("erc20_transfer_call", erc20_transfer_data, sizeof(erc20_transfer_data));
    print_hex_value("erc20_approve_call", erc20_approve_data, sizeof(erc20_approve_data));

    uint8_t safe_transfer_data[EVM_ABI_ADDRESS_UINT256_CALL_LEN];
    ethereum_safe_tx_t safe_tx = make_safe_usdt_transfer(safe_transfer_data);
    uint8_t safe_hash[KECCAK256_LEN];
    if (!ethereum_safe_tx_domain_separator_hash(safe_tx.chain_id, safe_tx.verifying_contract, safe_hash)) {
        return 1;
    }
    print_hex_value("safe_domain_hash", safe_hash, sizeof(safe_hash));
    if (!ethereum_safe_tx_message_hash(&safe_tx, safe_hash)) {
        return 1;
    }
    print_hex_value("safe_message_hash", safe_hash, sizeof(safe_hash));
    if (!ethereum_safe_tx_signing_hash(&safe_tx, safe_hash)) {
        return 1;
    }
    print_hex_value("safe_signing_hash", safe_hash, sizeof(safe_hash));
    print_hex_value("safe_usdt_transfer_call", safe_transfer_data, sizeof(safe_transfer_data));

    uint8_t token_contract[ETHEREUM_ADDRESS_LEN];
    memset(token_contract, 0x11, sizeof(token_contract));
    uint8_t signed_token_definition[256];
    size_t signed_token_definition_len = 0;
    uint8_t eth_definitions[512];
    size_t eth_definitions_len = 0;
    if (!make_signed_eth_token_definition(token_contract, 1, "USDT", 6, "Tether USD", true,
            signed_token_definition, sizeof(signed_token_definition), &signed_token_definition_len)
        || !make_eth_definitions_with_token(signed_token_definition, signed_token_definition_len, eth_definitions,
            sizeof(eth_definitions), &eth_definitions_len)) {
        return 1;
    }
    print_hex_value("trezor_usdt_signed_token_definition", signed_token_definition, signed_token_definition_len);
    print_hex_value("trezor_usdt_token_definitions", eth_definitions, eth_definitions_len);
    return 0;
}

int main(int argc, char** argv)
{
    if (argc == 2 && argv && argv[1] && strcmp(argv[1], "--dump-oracle-vectors") == 0) {
        return dump_oracle_vectors();
    }
    if (argc == 3 && argv && argv[1] && strcmp(argv[1], "--trezor-wire-oracle") == 0) {
        return run_trezor_wire_oracle(argv[2]);
    }
    if (argc >= 3 && argv && argv[1] && strcmp(argv[1], "--trezor-wire-script") == 0) {
        return run_trezor_wire_script(argc - 2, &argv[2]);
    }
    if (argc == 5 && argv && argv[1] && strcmp(argv[1], "--trezor-multisig-normalizer") == 0) {
        return run_trezor_multisig_normalizer(argv[2], argv[3], argv[4]);
    }
    if (argc == 5 && argv && argv[1] && strcmp(argv[1], "--trezor-multisig-partial") == 0) {
        return run_trezor_multisig_partial_gate(argv[2], argv[3], argv[4]);
    }
    if ((argc == 7 || argc == 8) && argv && argv[1] && strcmp(argv[1], "--trezor-multisig-tx") == 0) {
        return run_trezor_multisig_tx_gate(argv[2], argv[3], argv[4], argv[5], argv[6], argc == 8 ? argv[7] : "valid");
    }

    CHECK(PRIVATE_KEY_ONE[EC_PRIVATE_KEY_LEN - 1] == 1);
    CHECK(CHAIN_CONFIRM_UI_HEX_LINE_CHARS + 1U <= CHAIN_CONFIRM_UI_DISPLAY_LINE_MAX);
    CHECK(CHAIN_CONFIRM_UI_MAX_HEX_LINES <= CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES);
    CHECK(HEX_UI_LINES_FOR_BYTES(ETHEREUM_ADDRESS_LEN) <= CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES);
    CHECK(HEX_UI_LINES_FOR_BYTES(TRON_ADDRESS_LEN) <= CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES);
    CHECK(HEX_UI_LINES_FOR_BYTES(EVM_ABI_WORD_LEN) <= CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES);
    CHECK(HEX_UI_LINES_FOR_BYTES(CHAIN_CONFIRM_MAX_BYTES) <= CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES);
    CHECK(test_chain_confirm_ui_pagination_stops_at_nul());
    CHECK(sizeof(trezor_bitcoin_tx_input_t) <= 512);
    CHECK(sizeof(trezor_bitcoin_tx_output_t) <= 256);
    CHECK(sizeof(trezor_bitcoin_signing_state_t) <= 8192);
    CHECK(test_protobuf_rejects_malformed_inputs());
    CHECK(test_fake_ui_rejects_unrenderable_summary());
    CHECK(test_wallet_entropy_modes());
    CHECK(test_trezor_bitcoin_multisig_matcher());
    CHECK(test_trezor_bitcoin_multisig_signing_stays_rejected());

    trezor_protobuf_reader_t eof_reader;
    uint32_t eof_field_number = 1;
    uint8_t eof_wire_type = 1;
    const uint8_t* eof_value = (const uint8_t*)1;
    size_t eof_value_len = 1;
    trezor_protobuf_reader_init(&eof_reader, NULL, 0);
    CHECK(!trezor_protobuf_reader_next(
        &eof_reader, &eof_field_number, &eof_wire_type, &eof_value, &eof_value_len));

    const uint32_t eth_bip44[] = { chain_path_harden(44), chain_path_harden(60), chain_path_harden(0), 0, 0 };
    const uint32_t eth_bip44_change[] = { chain_path_harden(44), chain_path_harden(60), chain_path_harden(0), 1, 0 };
    const uint32_t eth_bip44_account[] = { chain_path_harden(44), chain_path_harden(60), chain_path_harden(0), 0, 7 };
    const uint32_t eth_sep5[] = { chain_path_harden(44), chain_path_harden(60), chain_path_harden(7) };
    const uint32_t eth_ledger_live_legacy[] = { chain_path_harden(44), chain_path_harden(60), chain_path_harden(0), 7 };
    const uint32_t eth_wrong_coin[] = { chain_path_harden(44), chain_path_harden(1), chain_path_harden(0), 0, 0 };
    const uint32_t eth_account_too_high[]
        = { chain_path_harden(44), chain_path_harden(60), chain_path_harden(CHAIN_PATH_MAX_ACCOUNT + 1), 0, 0 };
    const uint32_t eth_index_too_high[]
        = { chain_path_harden(44), chain_path_harden(60), chain_path_harden(0), 0, CHAIN_PATH_MAX_ADDRESS_INDEX + 1 };

    CHECK(ethereum_path_classify(eth_bip44, sizeof(eth_bip44) / sizeof(eth_bip44[0])) == ETHEREUM_PATH_BIP44_ACCOUNT);
    CHECK(ethereum_path_classify(eth_bip44_change, sizeof(eth_bip44_change) / sizeof(eth_bip44_change[0]))
        == ETHEREUM_PATH_BIP44);
    CHECK(ethereum_path_classify(eth_bip44_account, sizeof(eth_bip44_account) / sizeof(eth_bip44_account[0]))
        == ETHEREUM_PATH_BIP44_ACCOUNT);
    CHECK(ethereum_path_classify(eth_sep5, sizeof(eth_sep5) / sizeof(eth_sep5[0])) == ETHEREUM_PATH_SEP5);
    CHECK(ethereum_path_classify(
              eth_ledger_live_legacy, sizeof(eth_ledger_live_legacy) / sizeof(eth_ledger_live_legacy[0]))
        == ETHEREUM_PATH_LEDGER_LIVE_LEGACY);
    CHECK(ethereum_path_is_standard_external(eth_bip44, sizeof(eth_bip44) / sizeof(eth_bip44[0])));
    CHECK(
        !ethereum_path_is_standard_external(eth_bip44_change, sizeof(eth_bip44_change) / sizeof(eth_bip44_change[0])));
    CHECK(ethereum_path_is_public_key_export_supported(eth_bip44, ARRAY_LEN(eth_bip44)));
    CHECK(!ethereum_path_is_public_key_export_supported(eth_bip44_account, ARRAY_LEN(eth_bip44_account)));
    CHECK(ethereum_path_is_public_key_export_supported(eth_sep5, ARRAY_LEN(eth_sep5)));
    CHECK(ethereum_path_is_public_key_export_supported(eth_ledger_live_legacy, ARRAY_LEN(eth_ledger_live_legacy)));
    CHECK(!ethereum_path_is_supported(eth_wrong_coin, sizeof(eth_wrong_coin) / sizeof(eth_wrong_coin[0])));
    CHECK(!ethereum_path_is_supported(
        eth_account_too_high, sizeof(eth_account_too_high) / sizeof(eth_account_too_high[0])));
    CHECK(!ethereum_path_is_supported(eth_index_too_high, sizeof(eth_index_too_high) / sizeof(eth_index_too_high[0])));

    uint8_t safe_transfer_data[EVM_ABI_ADDRESS_UINT256_CALL_LEN];
    ethereum_safe_tx_t safe_tx = make_safe_usdt_transfer(safe_transfer_data);
    uint8_t safe_hash[KECCAK256_LEN];
    ethereum_safe_tx_summary_t safe_summary;
    CHECK(ethereum_safe_tx_validate(&safe_tx));
    CHECK(ethereum_safe_tx_domain_separator_hash(safe_tx.chain_id, safe_tx.verifying_contract, safe_hash));
    CHECK(memcmp(safe_hash, EXPECTED_SAFE_DOMAIN_HASH, sizeof(safe_hash)) == 0);
    CHECK(ethereum_safe_tx_message_hash(&safe_tx, safe_hash));
    CHECK(memcmp(safe_hash, EXPECTED_SAFE_MESSAGE_HASH, sizeof(safe_hash)) == 0);
    CHECK(ethereum_safe_tx_signing_hash(&safe_tx, safe_hash));
    CHECK(memcmp(safe_hash, EXPECTED_SAFE_SIGNING_HASH, sizeof(safe_hash)) == 0);
    CHECK(ethereum_safe_tx_preflight(&safe_tx, &safe_summary));
    CHECK(safe_summary.type == ETHEREUM_SAFE_TX_SUMMARY_ERC20_TRANSFER);
    CHECK(memcmp(safe_summary.safe_address, SAFE_TEST_ADDRESS, sizeof(SAFE_TEST_ADDRESS)) == 0);
    CHECK(memcmp(safe_summary.token_contract, SAFE_TEST_USDT_ADDRESS, sizeof(SAFE_TEST_USDT_ADDRESS)) == 0);
    CHECK(memcmp(safe_summary.token_recipient, SAFE_TEST_RECIPIENT, sizeof(SAFE_TEST_RECIPIENT)) == 0);
    CHECK(memcmp(safe_summary.calldata_hash, EXPECTED_SAFE_CALLDATA_HASH, sizeof(EXPECTED_SAFE_CALLDATA_HASH)) == 0);

    uint8_t safe_ack_payload[512];
    size_t safe_ack_payload_len = 0;
    trezor_ethereum_safe_tx_ack_t safe_ack;
    CHECK(make_trezor_safe_tx_ack_payload(
        safe_transfer_data, sizeof(safe_transfer_data), safe_ack_payload, sizeof(safe_ack_payload), &safe_ack_payload_len));
    CHECK(trezor_ethereum_safe_tx_ack_decode(safe_ack_payload, safe_ack_payload_len, &safe_ack));
    CHECK(safe_ack.tx.chain_id == safe_tx.chain_id);
    CHECK(memcmp(safe_ack.tx.verifying_contract, safe_tx.verifying_contract, sizeof(safe_tx.verifying_contract)) == 0);
    CHECK(memcmp(safe_ack.tx.to, safe_tx.to, sizeof(safe_tx.to)) == 0);
    CHECK(safe_ack.tx.data_len == safe_tx.data_len);
    CHECK(memcmp(safe_ack.data, safe_transfer_data, sizeof(safe_transfer_data)) == 0);
    CHECK(memcmp(safe_ack.tx.safe_tx_gas, safe_tx.safe_tx_gas, sizeof(safe_tx.safe_tx_gas)) == 0);
    CHECK(memcmp(safe_ack.tx.base_gas, safe_tx.base_gas, sizeof(safe_tx.base_gas)) == 0);
    CHECK(memcmp(safe_ack.tx.gas_price, safe_tx.gas_price, sizeof(safe_tx.gas_price)) == 0);
    CHECK(memcmp(safe_ack.tx.nonce, safe_tx.nonce, sizeof(safe_tx.nonce)) == 0);

    uint8_t bad_safe_ack_payload[512];
    trezor_protobuf_writer_t safe_ack_writer;
    trezor_protobuf_writer_init(&safe_ack_writer, bad_safe_ack_payload, sizeof(bad_safe_ack_payload));
    CHECK(trezor_protobuf_write_string_field(&safe_ack_writer, 1, "0x1234"));
    CHECK(!trezor_ethereum_safe_tx_ack_decode(bad_safe_ack_payload, safe_ack_writer.len, &safe_ack));

    trezor_protobuf_writer_init(&safe_ack_writer, bad_safe_ack_payload, sizeof(bad_safe_ack_payload));
    CHECK(trezor_protobuf_write_string_field(&safe_ack_writer, 1, "0xdAC17F958D2ee523a2206206994597C13D831ec7"));
    CHECK(trezor_protobuf_write_string_field(&safe_ack_writer, 1, "0xdAC17F958D2ee523a2206206994597C13D831ec7"));
    CHECK(!trezor_ethereum_safe_tx_ack_decode(bad_safe_ack_payload, safe_ack_writer.len, &safe_ack));

    static const uint8_t leading_zero_u256[] = { 0x00, 0x01 };
    trezor_protobuf_writer_init(&safe_ack_writer, bad_safe_ack_payload, sizeof(bad_safe_ack_payload));
    CHECK(trezor_protobuf_write_string_field(&safe_ack_writer, 1, "0xdAC17F958D2ee523a2206206994597C13D831ec7"));
    CHECK(trezor_protobuf_write_bytes_field(&safe_ack_writer, 2, leading_zero_u256, sizeof(leading_zero_u256)));
    CHECK(!trezor_ethereum_safe_tx_ack_decode(bad_safe_ack_payload, safe_ack_writer.len, &safe_ack));

    trezor_ethereum_sign_typed_hash_t safe_typed_hash;
    wally_bzero(&safe_typed_hash, sizeof(safe_typed_hash));
    memcpy(safe_typed_hash.address_n, eth_bip44, sizeof(eth_bip44));
    safe_typed_hash.address_n_len = ARRAY_LEN(eth_bip44);
    memcpy(safe_typed_hash.domain_separator_hash, EXPECTED_SAFE_DOMAIN_HASH, sizeof(EXPECTED_SAFE_DOMAIN_HASH));
    safe_typed_hash.has_domain_separator_hash = true;
    memcpy(safe_typed_hash.message_hash, EXPECTED_SAFE_MESSAGE_HASH, sizeof(EXPECTED_SAFE_MESSAGE_HASH));
    safe_typed_hash.has_message_hash = true;
    uint8_t safe_signing_hash[ETHEREUM_TX_SIGNING_HASH_LEN];
    CHECK(trezor_ethereum_safe_typed_hash_bind(&safe_typed_hash, &safe_tx, safe_signing_hash, &safe_summary));
    CHECK(memcmp(safe_signing_hash, EXPECTED_SAFE_SIGNING_HASH, sizeof(EXPECTED_SAFE_SIGNING_HASH)) == 0);
    CHECK(safe_summary.type == ETHEREUM_SAFE_TX_SUMMARY_ERC20_TRANSFER);

    chain_confirm_summary_t safe_confirm_summary;
    CHECK(ethereum_safe_tx_confirm_summary_from_preflight(
        eth_bip44, ARRAY_LEN(eth_bip44), &safe_tx, &safe_summary, safe_signing_hash, &safe_confirm_summary));
    CHECK(test_confirm_summary_fits_tdisplay_s3(&safe_confirm_summary));
    CHECK(ethereum_safe_tx_confirm_summary_matches_preflight(
        eth_bip44, ARRAY_LEN(eth_bip44), &safe_tx, &safe_summary, safe_signing_hash, &safe_confirm_summary));

    safe_confirm_summary.fields[safe_confirm_summary.num_fields - 1U].value.bytes.bytes[0] ^= 0x01;
    CHECK(!ethereum_safe_tx_confirm_summary_matches_preflight(
        eth_bip44, ARRAY_LEN(eth_bip44), &safe_tx, &safe_summary, safe_signing_hash, &safe_confirm_summary));
    safe_confirm_summary.fields[safe_confirm_summary.num_fields - 1U].value.bytes.bytes[0] ^= 0x01;

    size_t safe_token_amount_index = CHAIN_CONFIRM_MAX_FIELDS;
    for (size_t i = 0; i < safe_confirm_summary.num_fields; ++i) {
        if (safe_confirm_summary.fields[i].kind == CHAIN_CONFIRM_FIELD_TOKEN_AMOUNT) {
            safe_token_amount_index = i;
            break;
        }
    }
    CHECK(safe_token_amount_index < safe_confirm_summary.num_fields);
    CHECK(safe_confirm_summary.fields[safe_token_amount_index].value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(safe_confirm_summary.fields[safe_token_amount_index].value.text[0] != '\0');
    safe_confirm_summary.fields[safe_token_amount_index].value.text[0]
        = (char)(safe_confirm_summary.fields[safe_token_amount_index].value.text[0] == '1' ? '2' : '1');
    CHECK(!ethereum_safe_tx_confirm_summary_matches_preflight(
        eth_bip44, ARRAY_LEN(eth_bip44), &safe_tx, &safe_summary, safe_signing_hash, &safe_confirm_summary));
    CHECK(ethereum_safe_tx_confirm_summary_from_preflight(
        eth_bip44, ARRAY_LEN(eth_bip44), &safe_tx, &safe_summary, safe_signing_hash, &safe_confirm_summary));

    const uint32_t wrong_safe_path[]
        = { chain_path_harden(44), chain_path_harden(60), chain_path_harden(0), 0, 1 };
    CHECK(!ethereum_safe_tx_confirm_summary_matches_preflight(wrong_safe_path, ARRAY_LEN(wrong_safe_path), &safe_tx,
        &safe_summary, safe_signing_hash, &safe_confirm_summary));

    safe_typed_hash.message_hash[0] ^= 0x01;
    CHECK(!trezor_ethereum_safe_typed_hash_bind(&safe_typed_hash, &safe_tx, safe_signing_hash, &safe_summary));
    safe_typed_hash.message_hash[0] ^= 0x01;

    safe_tx.chain_id = 2;
    CHECK(!trezor_ethereum_safe_typed_hash_bind(&safe_typed_hash, &safe_tx, safe_signing_hash, &safe_summary));
    safe_tx.chain_id = 1;

    safe_typed_hash.has_encoded_network = true;
    CHECK(!trezor_ethereum_safe_typed_hash_bind(&safe_typed_hash, &safe_tx, safe_signing_hash, &safe_summary));
    safe_typed_hash.has_encoded_network = false;

    safe_tx.operation = ETHEREUM_SAFE_TX_OPERATION_DELEGATE_CALL;
    CHECK(ethereum_safe_tx_validate(&safe_tx));
    CHECK(!ethereum_safe_tx_preflight(&safe_tx, &safe_summary));
    CHECK(!trezor_ethereum_safe_typed_hash_bind(&safe_typed_hash, &safe_tx, safe_signing_hash, &safe_summary));
    safe_tx.operation = ETHEREUM_SAFE_TX_OPERATION_CALL;
    safe_tx.gas_token[ETHEREUM_ADDRESS_LEN - 1U] = 1;
    CHECK(!ethereum_safe_tx_preflight(&safe_tx, &safe_summary));
    CHECK(!trezor_ethereum_safe_typed_hash_bind(&safe_typed_hash, &safe_tx, safe_signing_hash, &safe_summary));
    safe_tx.gas_token[ETHEREUM_ADDRESS_LEN - 1U] = 0;
    safe_tx.refund_receiver[ETHEREUM_ADDRESS_LEN - 1U] = 1;
    CHECK(!ethereum_safe_tx_preflight(&safe_tx, &safe_summary));
    CHECK(!trezor_ethereum_safe_typed_hash_bind(&safe_typed_hash, &safe_tx, safe_signing_hash, &safe_summary));
    safe_tx.refund_receiver[ETHEREUM_ADDRESS_LEN - 1U] = 0;
    safe_tx.data_len = ETHEREUM_SAFE_TX_MAX_DATA_LEN + 1U;
    CHECK(!ethereum_safe_tx_validate(&safe_tx));
    CHECK(!trezor_ethereum_safe_typed_hash_bind(&safe_typed_hash, &safe_tx, safe_signing_hash, &safe_summary));

    const uint32_t btc_state_path[]
        = { chain_path_harden(44), chain_path_harden(1), chain_path_harden(0), 0, 0 };
    const uint32_t btc_signing_path[]
        = { chain_path_harden(84), chain_path_harden(1), chain_path_harden(0), 0, 0 };
    const uint32_t btc_mainnet_signing_path[]
        = { chain_path_harden(84), chain_path_harden(0), chain_path_harden(0), 0, 0 };
    const uint32_t btc_mainnet_p2pkh_path[]
        = { chain_path_harden(44), chain_path_harden(0), chain_path_harden(0), 0, 0 };
    const uint32_t btc_mainnet_p2sh_p2wpkh_path[]
        = { chain_path_harden(49), chain_path_harden(0), chain_path_harden(0), 0, 0 };
    const uint32_t btc_signing_path_1[]
        = { chain_path_harden(84), chain_path_harden(1), chain_path_harden(0), 0, 1 };
    const uint32_t btc_p2sh_p2wpkh_path[]
        = { chain_path_harden(49), chain_path_harden(1), chain_path_harden(0), 0, 0 };
    const uint32_t btc_self_path[]
        = { chain_path_harden(84), chain_path_harden(1), chain_path_harden(0), 0, 0 };
    const uint32_t btc_self_path_2[]
        = { chain_path_harden(84), chain_path_harden(1), chain_path_harden(0), 0, 2 };
    const uint32_t btc_change_path[]
        = { chain_path_harden(84), chain_path_harden(1), chain_path_harden(0), 1, 0 };
    const uint32_t btc_account_path[] = { chain_path_harden(44), chain_path_harden(1), chain_path_harden(0) };
    const uint32_t btc_p2wpkh_account_path[] = { chain_path_harden(84), chain_path_harden(1), chain_path_harden(0) };
    const uint32_t btc_mainnet_p2wpkh_account_path[]
        = { chain_path_harden(84), chain_path_harden(0), chain_path_harden(0) };
    const uint32_t btc_mainnet_p2sh_p2wpkh_account_path[]
        = { chain_path_harden(49), chain_path_harden(0), chain_path_harden(0) };
    const uint32_t btc_legacy_multisig_account_path[] = { chain_path_harden(45) };
    const uint32_t btc_p2sh_p2wsh_account_path[]
        = { chain_path_harden(48), chain_path_harden(1), chain_path_harden(0), chain_path_harden(1) };
    const uint32_t btc_p2wsh_account_path[]
        = { chain_path_harden(48), chain_path_harden(1), chain_path_harden(0), chain_path_harden(2) };
    const uint32_t btc_mainnet_p2sh_p2wsh_account_path[]
        = { chain_path_harden(48), chain_path_harden(0), chain_path_harden(0), chain_path_harden(1) };
    const uint32_t btc_mainnet_p2wsh_account_path[]
        = { chain_path_harden(48), chain_path_harden(0), chain_path_harden(0), chain_path_harden(2) };
    const uint32_t btc_bip48_wrong_script_type_path[]
        = { chain_path_harden(48), chain_path_harden(1), chain_path_harden(0), chain_path_harden(3) };
    const uint32_t btc_wrong_coin[]
        = { chain_path_harden(44), chain_path_harden(0), chain_path_harden(0), 0, 0 };
    CHECK(bitcoin_path_is_trezor_connect_state_testnet_p2pkh(btc_state_path, ARRAY_LEN(btc_state_path)));
    CHECK(!bitcoin_path_is_trezor_connect_state_testnet_p2pkh(btc_wrong_coin, ARRAY_LEN(btc_wrong_coin)));
    CHECK(bitcoin_path_is_testnet_p2pkh_account_public_node(btc_account_path, ARRAY_LEN(btc_account_path)));
    CHECK(!bitcoin_path_is_testnet_p2pkh_account_public_node(btc_state_path, ARRAY_LEN(btc_state_path)));
    CHECK(!bitcoin_path_is_testnet_p2pkh_account_public_node(btc_wrong_coin, 3));
    CHECK(bitcoin_path_is_p2wpkh_account_public_node(
        btc_p2wpkh_account_path, ARRAY_LEN(btc_p2wpkh_account_path), true));
    CHECK(bitcoin_path_is_p2wpkh_account_public_node(
        btc_mainnet_p2wpkh_account_path, ARRAY_LEN(btc_mainnet_p2wpkh_account_path), false));
    CHECK(bitcoin_path_is_p2sh_p2wpkh_account_public_node(
        btc_mainnet_p2sh_p2wpkh_account_path, ARRAY_LEN(btc_mainnet_p2sh_p2wpkh_account_path), false));
    CHECK(bitcoin_path_is_legacy_multisig_account_public_node(
        btc_legacy_multisig_account_path, ARRAY_LEN(btc_legacy_multisig_account_path)));
    CHECK(bitcoin_path_is_p2sh_p2wsh_account_public_node(
        btc_p2sh_p2wsh_account_path, ARRAY_LEN(btc_p2sh_p2wsh_account_path), true));
    CHECK(bitcoin_path_is_p2wsh_account_public_node(btc_p2wsh_account_path, ARRAY_LEN(btc_p2wsh_account_path), true));
    CHECK(bitcoin_path_is_p2sh_p2wsh_account_public_node(
        btc_mainnet_p2sh_p2wsh_account_path, ARRAY_LEN(btc_mainnet_p2sh_p2wsh_account_path), false));
    CHECK(bitcoin_path_is_p2wsh_account_public_node(
        btc_mainnet_p2wsh_account_path, ARRAY_LEN(btc_mainnet_p2wsh_account_path), false));
    CHECK(!bitcoin_path_is_p2wsh_account_public_node(
        btc_bip48_wrong_script_type_path, ARRAY_LEN(btc_bip48_wrong_script_type_path), true));
    CHECK(!bitcoin_path_is_p2wpkh_account_public_node(btc_account_path, ARRAY_LEN(btc_account_path), true));
    CHECK(bitcoin_path_is_p2pkh_signing(btc_state_path, ARRAY_LEN(btc_state_path), true));
    CHECK(bitcoin_path_is_testnet_p2wpkh_signing(btc_signing_path, ARRAY_LEN(btc_signing_path)));
    CHECK(bitcoin_path_is_p2wpkh_signing(
        btc_mainnet_signing_path, ARRAY_LEN(btc_mainnet_signing_path), false));
    CHECK(bitcoin_path_is_testnet_p2sh_p2wpkh_signing(
        btc_p2sh_p2wpkh_path, ARRAY_LEN(btc_p2sh_p2wpkh_path)));
    CHECK(bitcoin_path_is_p2wpkh_signing(btc_signing_path_1, ARRAY_LEN(btc_signing_path_1), true));
    CHECK(bitcoin_path_is_p2wpkh_internal(
        btc_self_path, ARRAY_LEN(btc_self_path), true, chain_path_harden(0)));
    CHECK(bitcoin_path_is_p2wpkh_change(
        btc_change_path, ARRAY_LEN(btc_change_path), true, chain_path_harden(0)));

    trezor_public_key_request_t btc_public_node_request;
    uint32_t btc_public_node_version = 0;
    wally_bzero(&btc_public_node_request, sizeof(btc_public_node_request));
    btc_public_node_request.kind = TREZOR_PUBLIC_KEY_REQUEST_GENERIC;
    btc_public_node_request.has_coin_name = true;
    memcpy(btc_public_node_request.coin_name, "Bitcoin", sizeof("Bitcoin"));
    btc_public_node_request.address_n_len = ARRAY_LEN(btc_mainnet_p2wpkh_account_path);
    memcpy(btc_public_node_request.address_n, btc_mainnet_p2wpkh_account_path, sizeof(btc_mainnet_p2wpkh_account_path));
    CHECK(trezor_bitcoin_public_node_version(&btc_public_node_request, &btc_public_node_version));
    CHECK(btc_public_node_version == 0x04B24746U);
    btc_public_node_request.has_ignore_xpub_magic = true;
    btc_public_node_request.ignore_xpub_magic = true;
    CHECK(trezor_bitcoin_public_node_version(&btc_public_node_request, &btc_public_node_version));
    CHECK(btc_public_node_version == BIP32_VER_MAIN_PUBLIC);
    btc_public_node_request.has_script_type = true;
    btc_public_node_request.script_type = BITCOIN_P2PKH_SPENDADDRESS;
    CHECK(trezor_bitcoin_public_node_version(&btc_public_node_request, &btc_public_node_version));
    CHECK(btc_public_node_version == BIP32_VER_MAIN_PUBLIC);
    btc_public_node_request.has_ignore_xpub_magic = false;
    btc_public_node_request.ignore_xpub_magic = false;
    CHECK(trezor_bitcoin_public_node_version(&btc_public_node_request, &btc_public_node_version));
    CHECK(btc_public_node_version == 0x04B24746U);
    btc_public_node_request.script_type = BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS;
    CHECK(!trezor_bitcoin_public_node_version(&btc_public_node_request, &btc_public_node_version));

    wally_bzero(&btc_public_node_request, sizeof(btc_public_node_request));
    btc_public_node_request.kind = TREZOR_PUBLIC_KEY_REQUEST_GENERIC;
    btc_public_node_request.has_coin_name = true;
    memcpy(btc_public_node_request.coin_name, "Testnet", sizeof("Testnet"));
    btc_public_node_request.address_n_len = ARRAY_LEN(btc_p2wpkh_account_path);
    memcpy(btc_public_node_request.address_n, btc_p2wpkh_account_path, sizeof(btc_p2wpkh_account_path));
    CHECK(trezor_bitcoin_public_node_version(&btc_public_node_request, &btc_public_node_version));
    CHECK(btc_public_node_version == 0x045F1CF6U);

    wally_bzero(&btc_public_node_request, sizeof(btc_public_node_request));
    btc_public_node_request.kind = TREZOR_PUBLIC_KEY_REQUEST_GENERIC;
    btc_public_node_request.has_coin_name = true;
    memcpy(btc_public_node_request.coin_name, "Bitcoin", sizeof("Bitcoin"));
    btc_public_node_request.address_n_len = ARRAY_LEN(btc_mainnet_p2sh_p2wpkh_account_path);
    memcpy(btc_public_node_request.address_n, btc_mainnet_p2sh_p2wpkh_account_path,
        sizeof(btc_mainnet_p2sh_p2wpkh_account_path));
    CHECK(trezor_bitcoin_public_node_version(&btc_public_node_request, &btc_public_node_version));
    CHECK(btc_public_node_version == 0x049D7CB2U);
    btc_public_node_request.has_script_type = true;
    btc_public_node_request.script_type = BITCOIN_P2PKH_SPENDADDRESS;
    CHECK(trezor_bitcoin_public_node_version(&btc_public_node_request, &btc_public_node_version));
    CHECK(btc_public_node_version == 0x049D7CB2U);
    btc_public_node_request.script_type = BITCOIN_P2WPKH_SPENDWITNESS;
    CHECK(!trezor_bitcoin_public_node_version(&btc_public_node_request, &btc_public_node_version));

    wally_bzero(&btc_public_node_request, sizeof(btc_public_node_request));
    btc_public_node_request.kind = TREZOR_PUBLIC_KEY_REQUEST_GENERIC;
    btc_public_node_request.has_coin_name = true;
    memcpy(btc_public_node_request.coin_name, "Bitcoin", sizeof("Bitcoin"));
    btc_public_node_request.address_n_len = ARRAY_LEN(btc_legacy_multisig_account_path);
    memcpy(btc_public_node_request.address_n, btc_legacy_multisig_account_path, sizeof(btc_legacy_multisig_account_path));
    CHECK(trezor_bitcoin_public_node_version(&btc_public_node_request, &btc_public_node_version));
    CHECK(btc_public_node_version == BIP32_VER_MAIN_PUBLIC);
    btc_public_node_request.has_coin_name = true;
    memcpy(btc_public_node_request.coin_name, "Testnet", sizeof("Testnet"));
    CHECK(trezor_bitcoin_public_node_version(&btc_public_node_request, &btc_public_node_version));
    CHECK(btc_public_node_version == BIP32_VER_TEST_PUBLIC);

    wally_bzero(&btc_public_node_request, sizeof(btc_public_node_request));
    btc_public_node_request.kind = TREZOR_PUBLIC_KEY_REQUEST_GENERIC;
    btc_public_node_request.has_coin_name = true;
    memcpy(btc_public_node_request.coin_name, "Testnet", sizeof("Testnet"));
    btc_public_node_request.address_n_len = ARRAY_LEN(btc_p2sh_p2wsh_account_path);
    memcpy(btc_public_node_request.address_n, btc_p2sh_p2wsh_account_path, sizeof(btc_p2sh_p2wsh_account_path));
    CHECK(trezor_bitcoin_public_node_version(&btc_public_node_request, &btc_public_node_version));
    CHECK(btc_public_node_version == 0x024289EFU);
    btc_public_node_request.has_script_type = true;
    btc_public_node_request.script_type = BITCOIN_MULTISIG_SPENDMULTISIG;
    CHECK(trezor_bitcoin_public_node_version(&btc_public_node_request, &btc_public_node_version));
    CHECK(btc_public_node_version == 0x024289EFU);
    btc_public_node_request.has_ignore_xpub_magic = true;
    btc_public_node_request.ignore_xpub_magic = true;
    CHECK(trezor_bitcoin_public_node_version(&btc_public_node_request, &btc_public_node_version));
    CHECK(btc_public_node_version == BIP32_VER_TEST_PUBLIC);

    wally_bzero(&btc_public_node_request, sizeof(btc_public_node_request));
    btc_public_node_request.kind = TREZOR_PUBLIC_KEY_REQUEST_GENERIC;
    btc_public_node_request.has_coin_name = true;
    memcpy(btc_public_node_request.coin_name, "Bitcoin", sizeof("Bitcoin"));
    btc_public_node_request.address_n_len = ARRAY_LEN(btc_mainnet_p2wsh_account_path);
    memcpy(btc_public_node_request.address_n, btc_mainnet_p2wsh_account_path, sizeof(btc_mainnet_p2wsh_account_path));
    CHECK(trezor_bitcoin_public_node_version(&btc_public_node_request, &btc_public_node_version));
    CHECK(btc_public_node_version == 0x02AA7ED3U);
    btc_public_node_request.has_script_type = true;
    btc_public_node_request.script_type = BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS;
    CHECK(!trezor_bitcoin_public_node_version(&btc_public_node_request, &btc_public_node_version));
    CHECK(!bitcoin_path_is_testnet_p2wpkh_signing(btc_state_path, ARRAY_LEN(btc_state_path)));
    CHECK(!bitcoin_path_is_testnet_p2sh_p2wpkh_signing(btc_signing_path, ARRAY_LEN(btc_signing_path)));

    char btc_address[BITCOIN_P2PKH_ADDRESS_MAX_LEN];
    CHECK(bitcoin_p2pkh_testnet_address_from_compressed_pubkey(
        PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), btc_address, sizeof(btc_address)));
    CHECK(strcmp(btc_address, "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r") == 0);
    CHECK(bitcoin_p2pkh_mainnet_address_from_compressed_pubkey(
        PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), btc_address, sizeof(btc_address)));
    CHECK(strcmp(btc_address, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH") == 0);
    CHECK(bitcoin_p2wpkh_testnet_address_from_compressed_pubkey(
        PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), btc_address, sizeof(btc_address)));
    CHECK(strcmp(btc_address, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx") == 0);
    CHECK(bitcoin_p2wpkh_mainnet_address_from_compressed_pubkey(
        PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), btc_address, sizeof(btc_address)));
    CHECK(strcmp(btc_address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == 0);
    CHECK(bitcoin_p2sh_p2wpkh_testnet_address_from_compressed_pubkey(
        PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), btc_address, sizeof(btc_address)));
    CHECK(strcmp(btc_address, "2NAUYAHhujozruyzpsFRP63mbrdaU5wnEpN") == 0);
    CHECK(bitcoin_p2sh_p2wpkh_mainnet_address_from_compressed_pubkey(
        PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), btc_address, sizeof(btc_address)));
    CHECK(strcmp(btc_address, "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN") == 0);
    wallet_core_path_t btc_wallet_path;
    memset(&btc_wallet_path, 0, sizeof(btc_wallet_path));
    btc_wallet_path.len = ARRAY_LEN(btc_state_path);
    memcpy(btc_wallet_path.parts, btc_state_path, sizeof(btc_state_path));
    CHECK(bitcoin_wallet_p2pkh_testnet_address_from_path(&btc_wallet_path, btc_address, sizeof(btc_address)));
    CHECK(strcmp(btc_address, "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r") == 0);
    memset(&btc_wallet_path, 0, sizeof(btc_wallet_path));
    btc_wallet_path.len = ARRAY_LEN(btc_mainnet_p2pkh_path);
    memcpy(btc_wallet_path.parts, btc_mainnet_p2pkh_path, sizeof(btc_mainnet_p2pkh_path));
    CHECK(bitcoin_wallet_p2pkh_mainnet_address_from_path(&btc_wallet_path, btc_address, sizeof(btc_address)));
    CHECK(strcmp(btc_address, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH") == 0);
    CHECK(!bitcoin_wallet_p2pkh_testnet_address_from_path(&btc_wallet_path, btc_address, sizeof(btc_address)));
    memset(&btc_wallet_path, 0, sizeof(btc_wallet_path));
    btc_wallet_path.len = ARRAY_LEN(btc_signing_path);
    memcpy(btc_wallet_path.parts, btc_signing_path, sizeof(btc_signing_path));
    CHECK(bitcoin_wallet_p2wpkh_testnet_address_from_path(&btc_wallet_path, btc_address, sizeof(btc_address)));
    CHECK(strcmp(btc_address, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx") == 0);
    CHECK(!bitcoin_wallet_p2pkh_testnet_address_from_path(&btc_wallet_path, btc_address, sizeof(btc_address)));
    memset(&btc_wallet_path, 0, sizeof(btc_wallet_path));
    btc_wallet_path.len = ARRAY_LEN(btc_mainnet_signing_path);
    memcpy(btc_wallet_path.parts, btc_mainnet_signing_path, sizeof(btc_mainnet_signing_path));
    CHECK(bitcoin_wallet_p2wpkh_mainnet_address_from_path(&btc_wallet_path, btc_address, sizeof(btc_address)));
    CHECK(strcmp(btc_address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == 0);
    memset(&btc_wallet_path, 0, sizeof(btc_wallet_path));
    btc_wallet_path.len = ARRAY_LEN(btc_p2sh_p2wpkh_path);
    memcpy(btc_wallet_path.parts, btc_p2sh_p2wpkh_path, sizeof(btc_p2sh_p2wpkh_path));
    CHECK(bitcoin_wallet_p2sh_p2wpkh_testnet_address_from_path(&btc_wallet_path, btc_address, sizeof(btc_address)));
    CHECK(strcmp(btc_address, "2NAUYAHhujozruyzpsFRP63mbrdaU5wnEpN") == 0);
    memset(&btc_wallet_path, 0, sizeof(btc_wallet_path));
    btc_wallet_path.len = ARRAY_LEN(btc_mainnet_p2sh_p2wpkh_path);
    memcpy(btc_wallet_path.parts, btc_mainnet_p2sh_p2wpkh_path, sizeof(btc_mainnet_p2sh_p2wpkh_path));
    CHECK(bitcoin_wallet_p2sh_p2wpkh_mainnet_address_from_path(&btc_wallet_path, btc_address, sizeof(btc_address)));
    CHECK(strcmp(btc_address, "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN") == 0);
    CHECK(!bitcoin_wallet_p2sh_p2wpkh_testnet_address_from_path(&btc_wallet_path, btc_address, sizeof(btc_address)));
    memset(&btc_wallet_path, 0, sizeof(btc_wallet_path));

    trezor_bitcoin_tx_input_t script_policy_input;
    memset(&script_policy_input, 0, sizeof(script_policy_input));
    script_policy_input.address_n_len = ARRAY_LEN(btc_state_path);
    memcpy(script_policy_input.address_n, btc_state_path, sizeof(btc_state_path));
    script_policy_input.script_type = BITCOIN_P2PKH_SPENDADDRESS;
    const uint8_t btc_p2pkh_script[] = { 0x76, 0xa9, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4,
        0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6, 0x88, 0xac };
    CHECK(trezor_bitcoin_script_policy_prevout_matches_input(&script_policy_input, TREZOR_BITCOIN_COIN_TESTNET,
        btc_p2pkh_script, sizeof(btc_p2pkh_script)));
    CHECK(!trezor_bitcoin_script_policy_prevout_matches_input(&script_policy_input, TREZOR_BITCOIN_COIN_TESTNET,
        EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY, sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY)));
    memset(&script_policy_input, 0, sizeof(script_policy_input));
    script_policy_input.address_n_len = ARRAY_LEN(btc_p2sh_p2wpkh_path);
    memcpy(script_policy_input.address_n, btc_p2sh_p2wpkh_path, sizeof(btc_p2sh_p2wpkh_path));
    script_policy_input.script_type = BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS;
    const uint8_t btc_p2sh_p2wpkh_script[] = { 0xa9, 0x14, 0xbc, 0xfe, 0xb7, 0x28, 0xb5, 0x84, 0x25,
        0x3d, 0x5f, 0x3f, 0x70, 0xbc, 0xb7, 0x80, 0xe9, 0xef, 0x21, 0x8a, 0x68, 0xf4, 0x87 };
    CHECK(trezor_bitcoin_script_policy_prevout_matches_input(&script_policy_input, TREZOR_BITCOIN_COIN_TESTNET,
        btc_p2sh_p2wpkh_script, sizeof(btc_p2sh_p2wpkh_script)));
    CHECK(!trezor_bitcoin_script_policy_prevout_matches_input(&script_policy_input, TREZOR_BITCOIN_COIN_TESTNET,
        EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY, sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY)));
    memset(&script_policy_input, 0, sizeof(script_policy_input));

    const uint8_t btc_multisig_p2sh_script[] = { 0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x87 };
    script_policy_input.has_multisig = true;
    script_policy_input.script_type = BITCOIN_MULTISIG_SPENDMULTISIG;
    script_policy_input.multisig.variant = MULTI_P2SH;
    script_policy_input.multisig.threshold = 2;
    script_policy_input.multisig.num_pubkeys = 3;
    memcpy(script_policy_input.multisig.script_pubkey, btc_multisig_p2sh_script, sizeof(btc_multisig_p2sh_script));
    script_policy_input.multisig.script_pubkey_len = sizeof(btc_multisig_p2sh_script);
    CHECK(trezor_bitcoin_script_policy_prevout_matches_input(&script_policy_input, TREZOR_BITCOIN_COIN_TESTNET,
        btc_multisig_p2sh_script, sizeof(btc_multisig_p2sh_script)));
    CHECK(!trezor_bitcoin_script_policy_prevout_matches_input(&script_policy_input, TREZOR_BITCOIN_COIN_TESTNET,
        btc_p2sh_p2wpkh_script, sizeof(btc_p2sh_p2wpkh_script)));
    script_policy_input.script_type = BITCOIN_P2WPKH_SPENDWITNESS;
    CHECK(!trezor_bitcoin_script_policy_prevout_matches_input(&script_policy_input, TREZOR_BITCOIN_COIN_TESTNET,
        btc_multisig_p2sh_script, sizeof(btc_multisig_p2sh_script)));
    memset(&script_policy_input, 0, sizeof(script_policy_input));

    uint8_t btc_multisig_p2wsh_script[WALLY_SCRIPTPUBKEY_P2WSH_LEN];
    memset(btc_multisig_p2wsh_script, 0x22, sizeof(btc_multisig_p2wsh_script));
    btc_multisig_p2wsh_script[0] = 0x00;
    btc_multisig_p2wsh_script[1] = SHA256_LEN;
    script_policy_input.has_multisig = true;
    script_policy_input.script_type = BITCOIN_P2WPKH_SPENDWITNESS;
    script_policy_input.multisig.variant = MULTI_P2WSH;
    script_policy_input.multisig.threshold = 2;
    script_policy_input.multisig.num_pubkeys = 3;
    memcpy(script_policy_input.multisig.script_pubkey, btc_multisig_p2wsh_script, sizeof(btc_multisig_p2wsh_script));
    script_policy_input.multisig.script_pubkey_len = sizeof(btc_multisig_p2wsh_script);
    CHECK(trezor_bitcoin_script_policy_prevout_matches_input(&script_policy_input, TREZOR_BITCOIN_COIN_TESTNET,
        btc_multisig_p2wsh_script, sizeof(btc_multisig_p2wsh_script)));
    script_policy_input.multisig.threshold = 4;
    CHECK(!trezor_bitcoin_script_policy_prevout_matches_input(&script_policy_input, TREZOR_BITCOIN_COIN_TESTNET,
        btc_multisig_p2wsh_script, sizeof(btc_multisig_p2wsh_script)));
    memset(&script_policy_input, 0, sizeof(script_policy_input));

    const uint8_t btc_multisig_nested_script[] = { 0xa9, 0x14, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x87 };
    script_policy_input.has_multisig = true;
    script_policy_input.script_type = BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS;
    script_policy_input.multisig.variant = MULTI_P2WSH_P2SH;
    script_policy_input.multisig.threshold = 2;
    script_policy_input.multisig.num_pubkeys = 3;
    memcpy(script_policy_input.multisig.script_pubkey, btc_multisig_nested_script, sizeof(btc_multisig_nested_script));
    script_policy_input.multisig.script_pubkey_len = sizeof(btc_multisig_nested_script);
    CHECK(trezor_bitcoin_script_policy_prevout_matches_input(&script_policy_input, TREZOR_BITCOIN_COIN_TESTNET,
        btc_multisig_nested_script, sizeof(btc_multisig_nested_script)));
    memset(&script_policy_input, 0, sizeof(script_policy_input));

    const uint32_t tron_external[] = { chain_path_harden(44), chain_path_harden(195), chain_path_harden(0), 0, 0 };
    const uint32_t tron_change[] = { chain_path_harden(44), chain_path_harden(195), chain_path_harden(0), 1, 0 };
    const uint32_t tron_wrong_coin[] = { chain_path_harden(44), chain_path_harden(60), chain_path_harden(0), 0, 0 };
    const uint32_t tron_bad_change[] = { chain_path_harden(44), chain_path_harden(195), chain_path_harden(0), 2, 0 };
    const uint32_t tron_index_too_high[]
        = { chain_path_harden(44), chain_path_harden(195), chain_path_harden(0), 0, CHAIN_PATH_MAX_ADDRESS_INDEX + 1 };

    CHECK(tron_path_classify(tron_external, sizeof(tron_external) / sizeof(tron_external[0]))
        == TRON_PATH_BIP44_EXTERNAL);
    CHECK(tron_path_classify(tron_change, sizeof(tron_change) / sizeof(tron_change[0])) == TRON_PATH_BIP44_CHANGE);
    CHECK(tron_path_is_standard_external(tron_external, sizeof(tron_external) / sizeof(tron_external[0])));
    CHECK(!tron_path_is_standard_external(tron_change, sizeof(tron_change) / sizeof(tron_change[0])));
    CHECK(!tron_path_is_supported(tron_wrong_coin, sizeof(tron_wrong_coin) / sizeof(tron_wrong_coin[0])));
    CHECK(!tron_path_is_supported(tron_bad_change, sizeof(tron_bad_change) / sizeof(tron_bad_change[0])));
    CHECK(!tron_path_is_supported(tron_index_too_high, sizeof(tron_index_too_high) / sizeof(tron_index_too_high[0])));

    uint8_t token_contract[ETHEREUM_ADDRESS_LEN];
    memset(token_contract, 0x11, sizeof(token_contract));
    uint8_t token_amount[EVM_ABI_WORD_LEN] = { 0 };
    token_amount[EVM_ABI_WORD_LEN - 1] = 50;
    uint8_t erc20_transfer_data[EVM_ABI_ADDRESS_UINT256_CALL_LEN];
    uint8_t erc20_approve_data[EVM_ABI_ADDRESS_UINT256_CALL_LEN];
    make_erc20_address_uint256_call(0xa9, 0x05, 0x9c, 0xbb, EXPECTED_ETH_ADDRESS, token_amount, erc20_transfer_data);
    make_erc20_address_uint256_call(0x09, 0x5e, 0xa7, 0xb3, EXPECTED_ETH_ADDRESS, token_amount, erc20_approve_data);

    evm_abi_address_uint256_call_t abi_call;
    CHECK(evm_abi_parse_address_uint256_call(erc20_transfer_data, sizeof(erc20_transfer_data), &abi_call));
    CHECK(abi_call.type == EVM_ABI_CALL_ERC20_TRANSFER);
    CHECK(memcmp(abi_call.address, EXPECTED_ETH_ADDRESS, sizeof(EXPECTED_ETH_ADDRESS)) == 0);
    CHECK(memcmp(abi_call.amount, token_amount, sizeof(token_amount)) == 0);
    erc20_transfer_data[EVM_ABI_SELECTOR_LEN] = 1;
    CHECK(!evm_abi_parse_address_uint256_call(erc20_transfer_data, sizeof(erc20_transfer_data), &abi_call));
    erc20_transfer_data[EVM_ABI_SELECTOR_LEN] = 0;

    ethereum_tx_preflight_request_t eth_req = { 0 };
    ethereum_tx_preflight_result_t eth_res = { 0 };
    chain_confirm_summary_t confirm_summary = { 0 };
    eth_req.path = eth_bip44;
    eth_req.path_len = ARRAY_LEN(eth_bip44);
    eth_req.tx_type = ETHEREUM_TX_TYPE_EIP1559;
    eth_req.chain_id = 1;
    eth_req.gas_limit = 21000;
    eth_req.max_priority_fee_per_gas = 1000000000ULL;
    eth_req.max_fee_per_gas = 2000000000ULL;
    eth_req.has_to = true;
    memcpy(eth_req.to, token_contract, sizeof(eth_req.to));
    const uint8_t native_value[] = { 0x01 };
    eth_req.value = native_value;
    eth_req.value_len = sizeof(native_value);
    eth_req.sender_address = EXPECTED_ETH_ADDRESS;
    eth_req.sender_address_len = sizeof(EXPECTED_ETH_ADDRESS);
    eth_req.expected_sender_address = EXPECTED_ETH_ADDRESS;
    eth_req.expected_sender_address_len = sizeof(EXPECTED_ETH_ADDRESS);
    CHECK(ethereum_tx_preflight(&eth_req, &eth_res));
    CHECK(eth_res.type == ETHEREUM_TX_SUMMARY_NATIVE_TRANSFER);
    CHECK(memcmp(eth_res.sender, EXPECTED_ETH_ADDRESS, sizeof(EXPECTED_ETH_ADDRESS)) == 0);
    CHECK(ethereum_confirm_summary_from_preflight(&eth_req, &eth_res, &confirm_summary));
    CHECK(confirm_summary.chain == CHAIN_CONFIRM_CHAIN_ETHEREUM);
    CHECK(confirm_summary.operation == CHAIN_CONFIRM_OPERATION_NATIVE_TRANSFER);
    CHECK(test_confirm_summary_fits_tdisplay_s3(&confirm_summary));
    CHECK((confirm_summary.flags & CHAIN_CONFIRM_FLAG_USER_CONFIRM) != 0);
    CHECK((confirm_summary.flags & CHAIN_CONFIRM_FLAG_EXTRA_CONFIRM) == 0);
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_PATH));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_FROM));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TO));
    const chain_confirm_field_t* const native_amount = find_confirm_field(&confirm_summary, CHAIN_CONFIRM_FIELD_AMOUNT);
    CHECK(native_amount && native_amount->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(native_amount->value.text, "0.000000000000000001 ETH") == 0);
    const chain_confirm_field_t* const native_max_fee
        = find_confirm_field(&confirm_summary, CHAIN_CONFIRM_FIELD_MAX_FEE);
    CHECK(native_max_fee && native_max_fee->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(native_max_fee->value.text, "0.000042 ETH") == 0);

    uint8_t wrong_sender[ETHEREUM_ADDRESS_LEN];
    memcpy(wrong_sender, EXPECTED_ETH_ADDRESS, sizeof(wrong_sender));
    wrong_sender[0] ^= 0x01;
    chain_authorization_t authorization = { 0 };
    eth_req.sender_address = wrong_sender;
    eth_req.expected_sender_address = wrong_sender;
    g_ui_calls = 0;
    CHECK(ethereum_authorize_tx(&eth_req, &authorization));
    CHECK(g_ui_calls == 1);
    CHECK(authorization.summary.chain == CHAIN_CONFIRM_CHAIN_ETHEREUM);
    CHECK(authorization.summary.operation == CHAIN_CONFIRM_OPERATION_NATIVE_TRANSFER);
    CHECK(chain_confirm_summary_has_field(&authorization.summary, CHAIN_CONFIRM_FIELD_FROM));
    const chain_confirm_field_t* const ui_from = find_confirm_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_FROM);
    CHECK(ui_from && ui_from->value_type == CHAIN_CONFIRM_VALUE_BYTES);
    CHECK(memcmp(ui_from->value.bytes.bytes, EXPECTED_ETH_ADDRESS, sizeof(EXPECTED_ETH_ADDRESS)) == 0);
    g_ui_accept = false;
    CHECK(!ethereum_authorize_tx(&eth_req, &authorization));
    g_ui_accept = true;
    g_wallet_pubkey_ok = false;
    CHECK(!ethereum_authorize_tx(&eth_req, &authorization));
    g_wallet_pubkey_ok = true;
    uint8_t tx_digest[CHAIN_AUTHORIZED_DIGEST_LEN];
    memset(tx_digest, 0x5a, sizeof(tx_digest));
    chain_authorized_digest_t authorized_digest = { 0 };
    CHECK(chain_authorized_digest_init(&authorization, tx_digest, sizeof(tx_digest), &authorized_digest));
    CHECK(chain_authorized_digest_matches_authorization(&authorization, &authorized_digest));
    CHECK(memcmp(authorized_digest.tx_digest, tx_digest, sizeof(tx_digest)) == 0);
    tx_digest[0] ^= 0x01;
    chain_authorized_digest_t authorized_digest_2 = { 0 };
    CHECK(chain_authorized_digest_init(&authorization, tx_digest, sizeof(tx_digest), &authorized_digest_2));
    CHECK(memcmp(authorized_digest.signing_binding, authorized_digest_2.signing_binding,
              sizeof(authorized_digest.signing_binding))
        != 0);
    authorization.summary.fields[0].value.path.parts[authorization.summary.fields[0].value.path.len - 1] ^= 1;
    CHECK(!chain_authorized_digest_matches_authorization(&authorization, &authorized_digest));
    authorization.summary.fields[0].value.path.parts[authorization.summary.fields[0].value.path.len - 1] ^= 1;
    eth_req.sender_address = EXPECTED_ETH_ADDRESS;
    eth_req.expected_sender_address = EXPECTED_ETH_ADDRESS;
    chain_authorized_digest_t tx_authorized_digest = { 0 };
    CHECK(ethereum_tx_build_authorized_digest(&eth_req, &authorization, &tx_authorized_digest));
    eth_req.nonce = 1;
    CHECK(!ethereum_tx_build_authorized_digest(&eth_req, &authorization, &tx_authorized_digest));
    eth_req.nonce = 0;
    ethereum_signature_t eth_signature = { 0 };
    eth_req.sender_address = wrong_sender;
    eth_req.expected_sender_address = wrong_sender;
    g_wallet_signature_header = 31;
    CHECK(ethereum_sign_tx(&eth_req, &eth_signature));
    CHECK(eth_signature.v == 0);
    CHECK(eth_signature.r[0] == 0xaa);
    CHECK(eth_signature.s[0] == 0xbb);
    g_wallet_signature_header = 32;
    CHECK(ethereum_sign_tx(&eth_req, &eth_signature));
    CHECK(eth_signature.v == 1);
    g_wallet_signature_header = 42;
    CHECK(!ethereum_sign_tx(&eth_req, &eth_signature));
    g_wallet_signature_header = 31;
    g_wallet_sign_ok = false;
    CHECK(!ethereum_sign_tx(&eth_req, &eth_signature));
    g_wallet_sign_ok = true;
    eth_req.sender_address = EXPECTED_ETH_ADDRESS;
    eth_req.expected_sender_address = EXPECTED_ETH_ADDRESS;

    uint8_t eip155_value[] = { 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00 };
    ethereum_tx_preflight_request_t eip155_req = { 0 };
    eip155_req.path = eth_bip44;
    eip155_req.path_len = ARRAY_LEN(eth_bip44);
    eip155_req.tx_type = ETHEREUM_TX_TYPE_LEGACY;
    eip155_req.chain_id = 1;
    eip155_req.nonce = 9;
    eip155_req.gas_price = 20000000000ULL;
    eip155_req.gas_limit = 21000;
    eip155_req.has_to = true;
    memset(eip155_req.to, 0x35, sizeof(eip155_req.to));
    eip155_req.value = eip155_value;
    eip155_req.value_len = sizeof(eip155_value);
    eip155_req.sender_address = EXPECTED_ETH_ADDRESS;
    eip155_req.sender_address_len = sizeof(EXPECTED_ETH_ADDRESS);
    uint8_t signing_payload[ETHEREUM_TX_MAX_SIGNING_PAYLOAD_LEN];
    size_t signing_payload_len = 0;
    uint8_t expected_eip155_payload[45];
    uint8_t expected_eip155_hash[ETHEREUM_TX_SIGNING_HASH_LEN];
    CHECK(hex_to_bytes("ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080",
        expected_eip155_payload, sizeof(expected_eip155_payload)));
    CHECK(hex_to_bytes("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53", expected_eip155_hash,
        sizeof(expected_eip155_hash)));
    CHECK(ethereum_tx_signing_payload(&eip155_req, signing_payload, sizeof(signing_payload), &signing_payload_len));
    CHECK(signing_payload_len == sizeof(expected_eip155_payload));
    CHECK(memcmp(signing_payload, expected_eip155_payload, sizeof(expected_eip155_payload)) == 0);
    uint8_t signing_hash[ETHEREUM_TX_SIGNING_HASH_LEN];
    CHECK(ethereum_tx_signing_hash(&eip155_req, signing_hash, sizeof(signing_hash)));
    CHECK(memcmp(signing_hash, expected_eip155_hash, sizeof(expected_eip155_hash)) == 0);
    g_wallet_signature_header = 31;
    CHECK(ethereum_sign_tx(&eip155_req, &eth_signature));
    CHECK(eth_signature.v == 37);
    g_wallet_signature_header = 32;
    CHECK(ethereum_sign_tx(&eip155_req, &eth_signature));
    CHECK(eth_signature.v == 38);
    g_wallet_signature_header = 31;
    eip155_req.chain_id = 0;
    CHECK(!ethereum_tx_preflight(&eip155_req, &eth_res));
    eip155_req.chain_id = 1;

    ethereum_tx_preflight_request_t type2_req = { 0 };
    type2_req.path = eth_bip44;
    type2_req.path_len = ARRAY_LEN(eth_bip44);
    type2_req.tx_type = ETHEREUM_TX_TYPE_EIP1559;
    type2_req.chain_id = 1;
    type2_req.max_priority_fee_per_gas = 1;
    type2_req.max_fee_per_gas = 2;
    type2_req.gas_limit = 21000;
    type2_req.has_to = true;
    memset(type2_req.to, 0x35, sizeof(type2_req.to));
    type2_req.sender_address = EXPECTED_ETH_ADDRESS;
    type2_req.sender_address_len = sizeof(EXPECTED_ETH_ADDRESS);
    uint8_t expected_type2_payload[33];
    CHECK(hex_to_bytes("02df018001028252089435353535353535353535353535353535353535358080c0", expected_type2_payload,
        sizeof(expected_type2_payload)));
    CHECK(ethereum_tx_signing_payload(&type2_req, signing_payload, sizeof(signing_payload), &signing_payload_len));
    CHECK(signing_payload_len == sizeof(expected_type2_payload));
    CHECK(memcmp(signing_payload, expected_type2_payload, sizeof(expected_type2_payload)) == 0);
    type2_req.tx_type = ETHEREUM_TX_TYPE_EIP2930;
    CHECK(!ethereum_tx_signing_payload(&type2_req, signing_payload, sizeof(signing_payload), &signing_payload_len));
    uint8_t nonminimal_zero_value[] = { 0x00, 0x01 };
    type2_req.tx_type = ETHEREUM_TX_TYPE_EIP1559;
    type2_req.value = nonminimal_zero_value;
    type2_req.value_len = sizeof(nonminimal_zero_value);
    CHECK(!ethereum_tx_signing_payload(&type2_req, signing_payload, sizeof(signing_payload), &signing_payload_len));
    type2_req.value = NULL;
    type2_req.value_len = 0;

    ethereum_tx_owned_request_t owned_eth_req;
    CHECK(ethereum_tx_owned_request_init(&owned_eth_req, eth_bip44, ARRAY_LEN(eth_bip44), ETHEREUM_TX_TYPE_EIP1559, 1,
        2, 21000, 0, 1, 2, type2_req.to, sizeof(type2_req.to), NULL, 0, erc20_transfer_data,
        sizeof(erc20_transfer_data), false));
    CHECK(owned_eth_req.request.path == owned_eth_req.path);
    CHECK(owned_eth_req.request.value == NULL);
    CHECK(owned_eth_req.request.data == owned_eth_req.data);
    CHECK(owned_eth_req.request.data_len == sizeof(erc20_transfer_data));
    CHECK(ethereum_sign_tx(&owned_eth_req.request, &eth_signature));

    uint8_t max_eth_data[ETHEREUM_TX_MAX_PREFLIGHT_DATA_LEN];
    memset(max_eth_data, 0x11, sizeof(max_eth_data));
    CHECK(ethereum_tx_owned_request_init(&owned_eth_req, eth_bip44, ARRAY_LEN(eth_bip44), ETHEREUM_TX_TYPE_EIP1559, 1,
        2, 21000, 0, 1, 2, type2_req.to, sizeof(type2_req.to), NULL, 0, max_eth_data, sizeof(max_eth_data), true));
    CHECK(!ethereum_tx_owned_request_init(&owned_eth_req, eth_bip44, ARRAY_LEN(eth_bip44), ETHEREUM_TX_TYPE_EIP1559, 1,
        2, 21000, 0, 1, 2, type2_req.to, sizeof(type2_req.to), NULL, 0, max_eth_data, sizeof(max_eth_data) + 1, true));
    uint8_t too_large_value[EVM_ABI_WORD_LEN + 1];
    memset(too_large_value, 1, sizeof(too_large_value));
    CHECK(!ethereum_tx_owned_request_init(&owned_eth_req, eth_bip44, ARRAY_LEN(eth_bip44), ETHEREUM_TX_TYPE_EIP1559, 1,
        2, 21000, 0, 1, 2, type2_req.to, sizeof(type2_req.to), too_large_value, sizeof(too_large_value), NULL, 0,
        false));
    CHECK(!ethereum_tx_owned_request_init(&owned_eth_req, eth_bip44, ARRAY_LEN(eth_bip44), ETHEREUM_TX_TYPE_EIP1559, 1,
        2, 21000, 0, 1, 2, type2_req.to, sizeof(type2_req.to), nonminimal_zero_value, sizeof(nonminimal_zero_value),
        NULL, 0, false));
    uint8_t zero_value[] = { 0 };
    CHECK(!ethereum_tx_owned_request_init(&owned_eth_req, eth_bip44, ARRAY_LEN(eth_bip44), ETHEREUM_TX_TYPE_EIP1559, 1,
        2, 21000, 0, 1, 2, type2_req.to, sizeof(type2_req.to), zero_value, sizeof(zero_value), NULL, 0, false));
    CHECK(!ethereum_tx_owned_request_init(&owned_eth_req, eth_wrong_coin, ARRAY_LEN(eth_wrong_coin),
        ETHEREUM_TX_TYPE_EIP1559, 1, 2, 21000, 0, 1, 2, type2_req.to, sizeof(type2_req.to), NULL, 0, NULL, 0, false));
    CHECK(!ethereum_tx_owned_request_init(&owned_eth_req, eth_bip44, ARRAY_LEN(eth_bip44), ETHEREUM_TX_TYPE_EIP2930, 1,
        2, 21000, 1, 0, 0, type2_req.to, sizeof(type2_req.to), NULL, 0, NULL, 0, false));
    CHECK(!ethereum_tx_owned_request_init(&owned_eth_req, eth_bip44, ARRAY_LEN(eth_bip44), ETHEREUM_TX_TYPE_EIP1559, 1,
        2, 21000, 0, 1, 2, NULL, 0, NULL, 0, NULL, 0, false));

    eth_req.expected_sender_address = wrong_sender;
    CHECK(!ethereum_tx_preflight(&eth_req, &eth_res));
    eth_req.expected_sender_address = EXPECTED_ETH_ADDRESS;

    eth_req.max_priority_fee_per_gas = eth_req.max_fee_per_gas + 1;
    CHECK(!ethereum_tx_preflight(&eth_req, &eth_res));
    eth_req.max_priority_fee_per_gas = 1000000000ULL;

    eth_req.value = NULL;
    eth_req.value_len = 0;
    eth_req.data = erc20_transfer_data;
    eth_req.data_len = sizeof(erc20_transfer_data);
    CHECK(ethereum_tx_preflight(&eth_req, &eth_res));
    CHECK(eth_res.type == ETHEREUM_TX_SUMMARY_ERC20_TRANSFER);
    CHECK(memcmp(eth_res.token_contract, token_contract, sizeof(token_contract)) == 0);
    CHECK(memcmp(eth_res.token_recipient, EXPECTED_ETH_ADDRESS, sizeof(EXPECTED_ETH_ADDRESS)) == 0);
    CHECK(memcmp(eth_res.token_amount, token_amount, sizeof(token_amount)) == 0);
    CHECK(ethereum_confirm_summary_from_preflight(&eth_req, &eth_res, &confirm_summary));
    CHECK(confirm_summary.operation == CHAIN_CONFIRM_OPERATION_TOKEN_TRANSFER);
    CHECK(test_confirm_summary_fits_tdisplay_s3(&confirm_summary));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_CONTRACT));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_RECIPIENT));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_AMOUNT));
    const chain_confirm_field_t* token_amount_field
        = find_confirm_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_AMOUNT);
    CHECK(token_amount_field && token_amount_field->value_type == CHAIN_CONFIRM_VALUE_BYTES);
    CHECK(token_amount_field->value.bytes.len == EVM_ABI_WORD_LEN);
    CHECK(memcmp(token_amount_field->value.bytes.bytes, token_amount, sizeof(token_amount)) == 0);

    ethereum_token_metadata_t usdt_metadata = { 0 };
    memcpy(usdt_metadata.address, token_contract, sizeof(token_contract));
    usdt_metadata.chain_id = 1;
    usdt_metadata.decimals = 6;
    memcpy(usdt_metadata.symbol, "USDT", sizeof("USDT"));
    memcpy(usdt_metadata.name, "Tether USD", sizeof("Tether USD"));
    eth_req.has_token_definition = true;
    memcpy(&eth_req.token_definition, &usdt_metadata, sizeof(eth_req.token_definition));
    CHECK(ethereum_tx_preflight(&eth_req, &eth_res));
    CHECK(ethereum_confirm_summary_from_preflight(&eth_req, &eth_res, &confirm_summary));
    CHECK(confirm_summary.operation == CHAIN_CONFIRM_OPERATION_TOKEN_TRANSFER);
    CHECK(test_confirm_summary_fits_tdisplay_s3(&confirm_summary));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_SYMBOL));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_DECIMALS));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_NAME));
    token_amount_field = find_confirm_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_AMOUNT);
    CHECK(token_amount_field && token_amount_field->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(token_amount_field->value.text, "0.00005 USDT") == 0);
    const chain_confirm_field_t* const token_symbol
        = find_confirm_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_SYMBOL);
    CHECK(token_symbol && token_symbol->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(token_symbol->value.text, "USDT") == 0);
    const chain_confirm_field_t* const token_decimals
        = find_confirm_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_DECIMALS);
    CHECK(token_decimals && token_decimals->value_type == CHAIN_CONFIRM_VALUE_U64 && token_decimals->value.u64 == 6);
    chain_authorization_t token_authorization = { 0 };
    g_ui_calls = 0;
    CHECK(ethereum_authorize_tx(&eth_req, &token_authorization));
    CHECK(g_ui_calls == 1);
    uint8_t token_tx_digest[CHAIN_AUTHORIZED_DIGEST_LEN];
    memset(token_tx_digest, 0x7a, sizeof(token_tx_digest));
    chain_authorized_digest_t token_authorized_digest = { 0 };
    CHECK(chain_authorized_digest_init(
        &token_authorization, token_tx_digest, sizeof(token_tx_digest), &token_authorized_digest));
    CHECK(chain_authorized_digest_matches_authorization(&token_authorization, &token_authorized_digest));
    bool changed_token_text = false;
    for (size_t i = 0; i < token_authorization.summary.num_fields; ++i) {
        if (token_authorization.summary.fields[i].kind == CHAIN_CONFIRM_FIELD_TOKEN_SYMBOL) {
            token_authorization.summary.fields[i].value.text[0] ^= 0x01;
            changed_token_text = true;
            break;
        }
    }
    CHECK(changed_token_text);
    CHECK(!chain_authorized_digest_matches_authorization(&token_authorization, &token_authorized_digest));
    eth_req.token_definition.chain_id = 2;
    CHECK(!ethereum_confirm_summary_from_preflight(&eth_req, &eth_res, &confirm_summary));
    CHECK(!ethereum_tx_preflight(&eth_req, &eth_res));
    eth_req.token_definition.chain_id = 1;
    eth_req.token_definition.address[0] ^= 0x01;
    CHECK(!ethereum_confirm_summary_from_preflight(&eth_req, &eth_res, &confirm_summary));
    CHECK(!ethereum_tx_preflight(&eth_req, &eth_res));
    eth_req.token_definition.address[0] ^= 0x01;
    uint8_t usdt_197_token_amount[EVM_ABI_WORD_LEN] = { 0 };
    usdt_197_token_amount[EVM_ABI_WORD_LEN - 4] = 0x01;
    usdt_197_token_amount[EVM_ABI_WORD_LEN - 3] = 0x2c;
    usdt_197_token_amount[EVM_ABI_WORD_LEN - 2] = 0x99;
    usdt_197_token_amount[EVM_ABI_WORD_LEN - 1] = 0x20;
    uint8_t usdt_197_transfer_data[EVM_ABI_ADDRESS_UINT256_CALL_LEN];
    make_erc20_address_uint256_call(
        0xa9, 0x05, 0x9c, 0xbb, EXPECTED_ETH_ADDRESS, usdt_197_token_amount, usdt_197_transfer_data);
    eth_req.data = usdt_197_transfer_data;
    eth_req.data_len = sizeof(usdt_197_transfer_data);
    CHECK(ethereum_tx_preflight(&eth_req, &eth_res));
    CHECK(ethereum_confirm_summary_from_preflight(&eth_req, &eth_res, &confirm_summary));
    token_amount_field = find_confirm_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_AMOUNT);
    CHECK(token_amount_field && token_amount_field->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(token_amount_field->value.text, "19.7 USDT") == 0);
    eth_req.data = erc20_transfer_data;
    eth_req.data_len = sizeof(erc20_transfer_data);
    eth_req.data = NULL;
    eth_req.data_len = 0;
    CHECK(!ethereum_tx_preflight(&eth_req, &eth_res));
    eth_req.data = erc20_transfer_data;
    eth_req.data_len = sizeof(erc20_transfer_data);
    eth_req.has_token_definition = false;
    wally_bzero(&eth_req.token_definition, sizeof(eth_req.token_definition));

    uint8_t one_wei[EVM_ABI_WORD_LEN] = { 0 };
    one_wei[EVM_ABI_WORD_LEN - 1] = 1;
    eth_req.value = one_wei;
    eth_req.value_len = sizeof(one_wei);
    CHECK(!ethereum_tx_preflight(&eth_req, &eth_res));
    eth_req.value = NULL;
    eth_req.value_len = 0;

    eth_req.data = erc20_approve_data;
    eth_req.data_len = sizeof(erc20_approve_data);
    CHECK(ethereum_tx_preflight(&eth_req, &eth_res));
    CHECK(eth_res.type == ETHEREUM_TX_SUMMARY_ERC20_APPROVE);
    CHECK(ethereum_confirm_summary_from_preflight(&eth_req, &eth_res, &confirm_summary));
    CHECK(confirm_summary.operation == CHAIN_CONFIRM_OPERATION_TOKEN_APPROVE);
    CHECK(test_confirm_summary_fits_tdisplay_s3(&confirm_summary));
    CHECK((confirm_summary.flags & CHAIN_CONFIRM_FLAG_APPROVAL) != 0);
    CHECK((confirm_summary.flags & CHAIN_CONFIRM_FLAG_EXTRA_CONFIRM) != 0);

    uint8_t unknown_call[EVM_ABI_ADDRESS_UINT256_CALL_LEN] = { 0xde, 0xad, 0xbe, 0xef };
    eth_req.data = unknown_call;
    eth_req.data_len = sizeof(unknown_call);
    CHECK(!ethereum_tx_preflight(&eth_req, &eth_res));
    eth_req.allow_unknown_contract_call = true;
    CHECK(ethereum_tx_preflight(&eth_req, &eth_res));
    CHECK(eth_res.type == ETHEREUM_TX_SUMMARY_CONTRACT_CALL);
    CHECK(ethereum_confirm_summary_from_preflight(&eth_req, &eth_res, &confirm_summary));
    CHECK(confirm_summary.operation == CHAIN_CONFIRM_OPERATION_CONTRACT_CALL);
    CHECK(test_confirm_summary_fits_tdisplay_s3(&confirm_summary));
    CHECK((confirm_summary.flags & CHAIN_CONFIRM_FLAG_UNKNOWN_CONTRACT) != 0);
    CHECK((confirm_summary.flags & CHAIN_CONFIRM_FLAG_EXTRA_CONFIRM) != 0);
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_CALLDATA_HASH));

    uint8_t tron_recipient[TRON_ADDRESS_LEN];
    tron_recipient[0] = TRON_ADDRESS_PREFIX;
    memcpy(tron_recipient + 1, token_contract, sizeof(token_contract));
    uint8_t tron_token_recipient[TRON_ADDRESS_LEN];
    tron_token_recipient[0] = TRON_ADDRESS_PREFIX;
    memcpy(tron_token_recipient + 1, EXPECTED_ETH_ADDRESS, sizeof(EXPECTED_ETH_ADDRESS));

    tron_tx_preflight_request_t tron_req = { 0 };
    tron_tx_preflight_result_t tron_res = { 0 };
    tron_req.path = tron_external;
    tron_req.path_len = ARRAY_LEN(tron_external);
    tron_req.signer_address = EXPECTED_TRON_ADDRESS;
    tron_req.signer_address_len = sizeof(EXPECTED_TRON_ADDRESS);
    tron_req.owner_address = EXPECTED_TRON_ADDRESS;
    tron_req.owner_address_len = sizeof(EXPECTED_TRON_ADDRESS);
    tron_req.contract_type = TRON_TX_CONTRACT_TRANSFER;
    memcpy(tron_req.transfer_to, tron_recipient, sizeof(tron_req.transfer_to));
    tron_req.transfer_amount = 1000000;
    CHECK(tron_tx_preflight(&tron_req, &tron_res));
    CHECK(tron_res.type == TRON_TX_SUMMARY_TRX_TRANSFER);
    CHECK(memcmp(tron_res.owner, EXPECTED_TRON_ADDRESS, sizeof(EXPECTED_TRON_ADDRESS)) == 0);
    CHECK(memcmp(tron_res.recipient, tron_recipient, sizeof(tron_recipient)) == 0);
    CHECK(tron_confirm_summary_from_preflight(&tron_req, &tron_res, &confirm_summary));
    CHECK(confirm_summary.chain == CHAIN_CONFIRM_CHAIN_TRON);
    CHECK(confirm_summary.operation == CHAIN_CONFIRM_OPERATION_NATIVE_TRANSFER);
    CHECK(test_confirm_summary_fits_tdisplay_s3(&confirm_summary));
    CHECK((confirm_summary.flags & CHAIN_CONFIRM_FLAG_USER_CONFIRM) != 0);
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_PATH));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_OWNER));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TO));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_FEE_LIMIT));

    g_ui_calls = 0;
    CHECK(tron_authorize_tx(&tron_req, &authorization));
    CHECK(g_ui_calls == 1);
    CHECK(authorization.summary.chain == CHAIN_CONFIRM_CHAIN_TRON);
    CHECK(authorization.summary.operation == CHAIN_CONFIRM_OPERATION_NATIVE_TRANSFER);
    CHECK(chain_confirm_summary_has_field(&authorization.summary, CHAIN_CONFIRM_FIELD_OWNER));
    g_ui_accept = false;
    CHECK(!tron_authorize_tx(&tron_req, &authorization));
    g_ui_accept = true;

    tron_req.owner_address = tron_recipient;
    g_ui_calls = 0;
    CHECK(!tron_authorize_tx(&tron_req, &authorization));
    CHECK(g_ui_calls == 0);
    CHECK(!tron_tx_preflight(&tron_req, &tron_res));
    tron_req.owner_address = EXPECTED_TRON_ADDRESS;

    tron_req.fee_limit = TRON_TX_MAX_FEE_LIMIT_SUN + 1;
    CHECK(!tron_tx_preflight(&tron_req, &tron_res));
    tron_req.fee_limit = 100000000;

    tron_req.contract_type = TRON_TX_CONTRACT_TRIGGER_SMART_CONTRACT;
    memcpy(tron_req.contract_address, EXPECTED_TRON_ADDRESS, sizeof(tron_req.contract_address));
    tron_req.contract_data = erc20_transfer_data;
    tron_req.contract_data_len = sizeof(erc20_transfer_data);
    CHECK(tron_tx_preflight(&tron_req, &tron_res));
    CHECK(tron_res.type == TRON_TX_SUMMARY_TRC20_TRANSFER);
    CHECK(memcmp(tron_res.contract_address, EXPECTED_TRON_ADDRESS, sizeof(EXPECTED_TRON_ADDRESS)) == 0);
    CHECK(memcmp(tron_res.recipient, tron_token_recipient, sizeof(tron_token_recipient)) == 0);
    CHECK(tron_confirm_summary_from_preflight(&tron_req, &tron_res, &confirm_summary));
    CHECK(confirm_summary.operation == CHAIN_CONFIRM_OPERATION_TOKEN_TRANSFER);
    CHECK(test_confirm_summary_fits_tdisplay_s3(&confirm_summary));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_CONTRACT));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_RECIPIENT));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_AMOUNT));

    tron_req.contract_data = erc20_approve_data;
    tron_req.contract_data_len = sizeof(erc20_approve_data);
    CHECK(tron_tx_preflight(&tron_req, &tron_res));
    CHECK(tron_res.type == TRON_TX_SUMMARY_TRC20_APPROVE);
    CHECK(tron_confirm_summary_from_preflight(&tron_req, &tron_res, &confirm_summary));
    CHECK(confirm_summary.operation == CHAIN_CONFIRM_OPERATION_TOKEN_APPROVE);
    CHECK(test_confirm_summary_fits_tdisplay_s3(&confirm_summary));
    CHECK((confirm_summary.flags & CHAIN_CONFIRM_FLAG_APPROVAL) != 0);
    CHECK((confirm_summary.flags & CHAIN_CONFIRM_FLAG_EXTRA_CONFIRM) != 0);
    tron_req.contract_data = erc20_transfer_data;
    tron_req.contract_data_len = sizeof(erc20_transfer_data);

    tron_req.call_value = 1;
    CHECK(!tron_tx_preflight(&tron_req, &tron_res));
    tron_req.call_value = 0;
    tron_req.contract_data = unknown_call;
    tron_req.contract_data_len = sizeof(unknown_call);
    CHECK(!tron_tx_preflight(&tron_req, &tron_res));
    tron_req.allow_unknown_contract_call = true;
    CHECK(tron_tx_preflight(&tron_req, &tron_res));
    CHECK(tron_res.type == TRON_TX_SUMMARY_UNKNOWN_SMART_CONTRACT);
    CHECK(tron_confirm_summary_from_preflight(&tron_req, &tron_res, &confirm_summary));
    CHECK(confirm_summary.operation == CHAIN_CONFIRM_OPERATION_CONTRACT_CALL);
    CHECK(test_confirm_summary_fits_tdisplay_s3(&confirm_summary));
    CHECK((confirm_summary.flags & CHAIN_CONFIRM_FLAG_UNKNOWN_CONTRACT) != 0);
    CHECK((confirm_summary.flags & CHAIN_CONFIRM_FLAG_EXTRA_CONFIRM) != 0);
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_CALLDATA_HASH));

    uint8_t keccak_hash[KECCAK256_LEN];
    CHECK(keccak256(NULL, 0, keccak_hash, sizeof(keccak_hash)));
    CHECK(memcmp(keccak_hash, EXPECTED_KECCAK256_EMPTY, sizeof(EXPECTED_KECCAK256_EMPTY)) == 0);
    CHECK(keccak256((const uint8_t*)"abc", 3, keccak_hash, sizeof(keccak_hash)));
    CHECK(memcmp(keccak_hash, EXPECTED_KECCAK256_ABC, sizeof(EXPECTED_KECCAK256_ABC)) == 0);
    CHECK(!keccak256(PRIVATE_KEY_ONE, sizeof(PRIVATE_KEY_ONE), keccak_hash, sizeof(keccak_hash) - 1));

    uint8_t eth_address[ETHEREUM_ADDRESS_LEN];
    CHECK(ethereum_address_from_uncompressed_pubkey(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY,
        sizeof(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY), eth_address, sizeof(eth_address)));
    CHECK(memcmp(eth_address, EXPECTED_ETH_ADDRESS, sizeof(EXPECTED_ETH_ADDRESS)) == 0);
    CHECK(ethereum_address_matches_uncompressed_pubkey(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY,
        sizeof(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY), EXPECTED_ETH_ADDRESS, sizeof(EXPECTED_ETH_ADDRESS)));
    CHECK(!ethereum_address_from_uncompressed_pubkey(
        PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY, EC_PUBLIC_KEY_LEN, eth_address, sizeof(eth_address)));
    CHECK(!ethereum_address_from_uncompressed_pubkey(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY,
        sizeof(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY), eth_address, sizeof(eth_address) - 1));

    uint8_t bad_pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    memcpy(bad_pubkey, PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY, sizeof(bad_pubkey));
    bad_pubkey[0] = 0x02;
    CHECK(!ethereum_address_from_uncompressed_pubkey(bad_pubkey, sizeof(bad_pubkey), eth_address, sizeof(eth_address)));

    uint8_t bad_eth[ETHEREUM_ADDRESS_LEN];
    memcpy(bad_eth, EXPECTED_ETH_ADDRESS, sizeof(bad_eth));
    bad_eth[sizeof(bad_eth) - 1] ^= 0x01;
    CHECK(!ethereum_address_matches_uncompressed_pubkey(
        PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY), bad_eth, sizeof(bad_eth)));

    char eth_checksum[ETHEREUM_CHECKSUM_ADDRESS_STRING_LEN];
    CHECK(ethereum_address_to_checksum_string(
        EXPECTED_ETH_ADDRESS, sizeof(EXPECTED_ETH_ADDRESS), eth_checksum, sizeof(eth_checksum)));
    CHECK(strcmp(eth_checksum, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf") == 0);
    CHECK(!ethereum_address_to_checksum_string(
        EXPECTED_ETH_ADDRESS, sizeof(EXPECTED_ETH_ADDRESS), eth_checksum, sizeof(eth_checksum) - 1));

    uint8_t eip55_address[ETHEREUM_ADDRESS_LEN];
    CHECK(hex_to_bytes("52908400098527886e0f7030069857d2e4169ee7", eip55_address, sizeof(eip55_address)));
    CHECK(
        ethereum_address_to_checksum_string(eip55_address, sizeof(eip55_address), eth_checksum, sizeof(eth_checksum)));
    CHECK(strcmp(eth_checksum, "0x52908400098527886E0F7030069857D2E4169EE7") == 0);
    CHECK(hex_to_bytes("de709f2102306220921060314715629080e2fb77", eip55_address, sizeof(eip55_address)));
    CHECK(
        ethereum_address_to_checksum_string(eip55_address, sizeof(eip55_address), eth_checksum, sizeof(eth_checksum)));
    CHECK(strcmp(eth_checksum, "0xde709f2102306220921060314715629080e2fb77") == 0);

    uint8_t tron_address[TRON_ADDRESS_LEN];
    CHECK(tron_address_from_uncompressed_pubkey(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY,
        sizeof(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY), tron_address, sizeof(tron_address)));
    CHECK(memcmp(tron_address, EXPECTED_TRON_ADDRESS, sizeof(EXPECTED_TRON_ADDRESS)) == 0);
    CHECK(tron_owner_address_matches_uncompressed_pubkey(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY,
        sizeof(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY), EXPECTED_TRON_ADDRESS, sizeof(EXPECTED_TRON_ADDRESS)));

    uint8_t bad_tron[TRON_ADDRESS_LEN];
    memcpy(bad_tron, EXPECTED_TRON_ADDRESS, sizeof(bad_tron));
    bad_tron[sizeof(bad_tron) - 1] ^= 0x01;
    CHECK(!tron_owner_address_matches_uncompressed_pubkey(
        PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY), bad_tron, sizeof(bad_tron)));
    CHECK(!tron_owner_address_matches_uncompressed_pubkey(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY,
        sizeof(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY), EXPECTED_TRON_ADDRESS + 1, TRON_ADDRESS_LEN - 1));
    bad_tron[0] = 0x00;
    CHECK(!tron_owner_address_matches_uncompressed_pubkey(
        PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY), bad_tron, sizeof(bad_tron)));

    char base58[TRON_BASE58_ADDRESS_MAX_LEN];
    CHECK(tron_address_to_base58(EXPECTED_TRON_ADDRESS, sizeof(EXPECTED_TRON_ADDRESS), base58, sizeof(base58)));
    CHECK(strcmp(base58, "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC") == 0);
    CHECK(!tron_address_to_base58(EXPECTED_TRON_ADDRESS, sizeof(EXPECTED_TRON_ADDRESS), base58, 4));
    CHECK(!tron_address_to_base58(EXPECTED_TRON_ADDRESS + 1, TRON_ADDRESS_LEN - 1, base58, sizeof(base58)));

    uint8_t trezor_payload[256];
    trezor_protobuf_writer_t trezor_writer;
    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    for (size_t i = 0; i < ARRAY_LEN(eth_bip44); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, eth_bip44[i]));
    }
    CHECK(trezor_protobuf_write_bool_field(&trezor_writer, 2, true));
    CHECK(trezor_protobuf_write_bool_field(&trezor_writer, 4, true));
    trezor_ethereum_get_address_t trezor_get_address;
    CHECK(trezor_ethereum_get_address_decode(trezor_payload, trezor_writer.len, &trezor_get_address));
    CHECK(trezor_get_address.address_n_len == ARRAY_LEN(eth_bip44));
    CHECK(memcmp(trezor_get_address.address_n, eth_bip44, sizeof(eth_bip44)) == 0);
    CHECK(trezor_get_address.has_show_display && trezor_get_address.show_display);
    CHECK(trezor_get_address.has_chunkify && trezor_get_address.chunkify);

    uint8_t trezor_address_payload[64];
    size_t trezor_address_payload_len = 0;
    CHECK(trezor_ethereum_address_encode("0x52908400098527886E0F7030069857D2E4169EE7", trezor_address_payload,
        sizeof(trezor_address_payload), &trezor_address_payload_len));
    CHECK(trezor_address_payload_len == 44);
    CHECK(trezor_address_payload[0] == ((2 << 3) | TREZOR_PROTOBUF_WIRE_LEN));
    CHECK(trezor_address_payload[1] == 42);

    uint8_t trezor_bitcoin_payload[256];
    trezor_protobuf_writer_t trezor_bitcoin_writer;
    trezor_protobuf_writer_init(&trezor_bitcoin_writer, trezor_bitcoin_payload, sizeof(trezor_bitcoin_payload));
    for (size_t i = 0; i < ARRAY_LEN(btc_state_path); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_bitcoin_writer, 1, btc_state_path[i]));
    }
    CHECK(trezor_protobuf_write_string_field(&trezor_bitcoin_writer, 2, "Testnet"));
    CHECK(trezor_protobuf_write_varint_field(&trezor_bitcoin_writer, 5, BITCOIN_P2PKH_SPENDADDRESS));
    trezor_bitcoin_get_address_t trezor_bitcoin_get_address;
    CHECK(trezor_bitcoin_get_address_decode(
        trezor_bitcoin_payload, trezor_bitcoin_writer.len, &trezor_bitcoin_get_address));
    CHECK(trezor_bitcoin_get_address.address_n_len == ARRAY_LEN(btc_state_path));
    CHECK(memcmp(trezor_bitcoin_get_address.address_n, btc_state_path, sizeof(btc_state_path)) == 0);
    CHECK(trezor_bitcoin_get_address.has_coin_name && strcmp(trezor_bitcoin_get_address.coin_name, "Testnet") == 0);
    CHECK(trezor_bitcoin_get_address.has_script_type
        && trezor_bitcoin_get_address.script_type == BITCOIN_P2PKH_SPENDADDRESS);
    const size_t trezor_bitcoin_payload_len = trezor_bitcoin_writer.len;

    uint8_t trezor_bitcoin_taproot_payload[256];
    trezor_protobuf_writer_init(
        &trezor_bitcoin_writer, trezor_bitcoin_taproot_payload, sizeof(trezor_bitcoin_taproot_payload));
    for (size_t i = 0; i < ARRAY_LEN(btc_state_path); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_bitcoin_writer, 1, btc_state_path[i]));
    }
    CHECK(trezor_protobuf_write_string_field(&trezor_bitcoin_writer, 2, "Testnet"));
    CHECK(trezor_protobuf_write_varint_field(&trezor_bitcoin_writer, 5, 5));
    CHECK(!trezor_bitcoin_get_address_decode(
        trezor_bitcoin_taproot_payload, trezor_bitcoin_writer.len, &trezor_bitcoin_get_address));

    uint8_t trezor_bitcoin_multisig_payload[256];
    trezor_protobuf_writer_init(
        &trezor_bitcoin_writer, trezor_bitcoin_multisig_payload, sizeof(trezor_bitcoin_multisig_payload));
    for (size_t i = 0; i < ARRAY_LEN(btc_state_path); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_bitcoin_writer, 1, btc_state_path[i]));
    }
    CHECK(trezor_protobuf_write_string_field(&trezor_bitcoin_writer, 2, "Testnet"));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_bitcoin_writer, 4, (const uint8_t*)"\x08\x02", 2));
    CHECK(!trezor_bitcoin_get_address_decode(
        trezor_bitcoin_multisig_payload, trezor_bitcoin_writer.len, &trezor_bitcoin_get_address));

    uint8_t trezor_bitcoin_address_payload[64];
    size_t trezor_bitcoin_address_payload_len = 0;
    CHECK(trezor_bitcoin_address_encode("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r", trezor_bitcoin_address_payload,
        sizeof(trezor_bitcoin_address_payload), &trezor_bitcoin_address_payload_len));
    CHECK(trezor_bitcoin_address_payload_len == 36);
    CHECK(trezor_bitcoin_address_payload[0] == ((1 << 3) | TREZOR_PROTOBUF_WIRE_LEN));
    CHECK(trezor_bitcoin_address_payload[1] == 34);

    uint8_t trezor_sign_tx_payload[128];
    uint8_t trezor_valid_sign_tx_payload[128];
    size_t trezor_valid_sign_tx_payload_len = 0;
    trezor_protobuf_writer_t trezor_sign_tx_writer;
    trezor_protobuf_writer_init(&trezor_sign_tx_writer, trezor_sign_tx_payload, sizeof(trezor_sign_tx_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 1, 1));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 2, 1));
    CHECK(trezor_protobuf_write_string_field(&trezor_sign_tx_writer, 3, "Testnet"));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 4, 2));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 5, 0));
    CHECK(trezor_protobuf_write_bool_field(&trezor_sign_tx_writer, 12, false));
    CHECK(trezor_protobuf_write_bool_field(&trezor_sign_tx_writer, 13, true));
    trezor_bitcoin_sign_tx_t trezor_sign_tx;
    CHECK(trezor_bitcoin_sign_tx_decode(trezor_sign_tx_payload, trezor_sign_tx_writer.len, &trezor_sign_tx));
    CHECK(trezor_sign_tx.inputs_count == 1);
    CHECK(trezor_sign_tx.outputs_count == 1);
    CHECK(trezor_sign_tx.has_coin_name && strcmp(trezor_sign_tx.coin_name, "Testnet") == 0);
    CHECK(trezor_sign_tx.version == 2);
    CHECK(trezor_sign_tx.lock_time == 0);
    CHECK(trezor_sign_tx.serialize);
    trezor_valid_sign_tx_payload_len = trezor_sign_tx_writer.len;
    memcpy(trezor_valid_sign_tx_payload, trezor_sign_tx_payload, trezor_valid_sign_tx_payload_len);

    trezor_protobuf_writer_init(&trezor_sign_tx_writer, trezor_sign_tx_payload, sizeof(trezor_sign_tx_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 1, 1));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 2, 1));
    CHECK(!trezor_bitcoin_sign_tx_decode(trezor_sign_tx_payload, trezor_sign_tx_writer.len, &trezor_sign_tx));

    trezor_protobuf_writer_init(&trezor_sign_tx_writer, trezor_sign_tx_payload, sizeof(trezor_sign_tx_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 1, 1));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 2, 1));
    CHECK(trezor_protobuf_write_string_field(&trezor_sign_tx_writer, 3, "Testnet"));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 4, 3));
    CHECK(!trezor_bitcoin_sign_tx_decode(trezor_sign_tx_payload, trezor_sign_tx_writer.len, &trezor_sign_tx));

    trezor_protobuf_writer_init(&trezor_sign_tx_writer, trezor_sign_tx_payload, sizeof(trezor_sign_tx_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 1, 1));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 2, 1));
    CHECK(trezor_protobuf_write_string_field(&trezor_sign_tx_writer, 3, "Testnet"));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 5, 1));
    CHECK(trezor_bitcoin_sign_tx_decode(trezor_sign_tx_payload, trezor_sign_tx_writer.len, &trezor_sign_tx));
    CHECK(trezor_sign_tx.lock_time == 1);

    trezor_protobuf_writer_init(&trezor_sign_tx_writer, trezor_sign_tx_payload, sizeof(trezor_sign_tx_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 1, 1));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 2, 1));
    CHECK(trezor_protobuf_write_string_field(&trezor_sign_tx_writer, 3, "Testnet"));
    CHECK(trezor_protobuf_write_bool_field(&trezor_sign_tx_writer, 13, false));
    CHECK(!trezor_bitcoin_sign_tx_decode(trezor_sign_tx_payload, trezor_sign_tx_writer.len, &trezor_sign_tx));

    trezor_protobuf_writer_init(&trezor_sign_tx_writer, trezor_sign_tx_payload, sizeof(trezor_sign_tx_payload));
    CHECK(trezor_protobuf_write_varint_field(
        &trezor_sign_tx_writer, 1, TREZOR_BITCOIN_TX_OUTPUTS_MAX + 1U));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 2, 1));
    CHECK(!trezor_bitcoin_sign_tx_decode(trezor_sign_tx_payload, trezor_sign_tx_writer.len, &trezor_sign_tx));

    trezor_protobuf_writer_init(&trezor_sign_tx_writer, trezor_sign_tx_payload, sizeof(trezor_sign_tx_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 1, 1));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 2, 1));
    CHECK(trezor_protobuf_write_string_field(&trezor_sign_tx_writer, 3, "Bitcoin"));
    CHECK(trezor_bitcoin_sign_tx_decode(trezor_sign_tx_payload, trezor_sign_tx_writer.len, &trezor_sign_tx));
    CHECK(trezor_sign_tx.has_coin_name && strcmp(trezor_sign_tx.coin_name, "Bitcoin") == 0);

    const uint8_t trezor_btc_prev_hash[32]
        = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
              0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
    uint8_t trezor_btc_input_payload[160];
    uint8_t trezor_btc_output_payload[160];
    uint8_t trezor_btc_tx_payload[256];
    uint8_t trezor_btc_ack_payload[288];
    uint8_t trezor_btc_input_ack_payload[288];
    uint8_t trezor_btc_output_ack_payload[288];
    uint8_t trezor_btc_meta_ack_payload[288];
    size_t trezor_btc_input_ack_payload_len = 0;
    size_t trezor_btc_output_ack_payload_len = 0;
    size_t trezor_btc_meta_ack_payload_len = 0;
    trezor_protobuf_writer_t trezor_btc_input_writer;
    trezor_protobuf_writer_t trezor_btc_output_writer;
    trezor_protobuf_writer_t trezor_btc_tx_writer;
    trezor_protobuf_writer_t trezor_btc_ack_writer;

    trezor_protobuf_writer_init(&trezor_btc_input_writer, trezor_btc_input_payload, sizeof(trezor_btc_input_payload));
    for (size_t i = 0; i < ARRAY_LEN(btc_signing_path); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_btc_input_writer, 1, btc_signing_path[i]));
    }
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_input_writer, 2, trezor_btc_prev_hash, sizeof(trezor_btc_prev_hash)));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_input_writer, 3, 0));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_input_writer, 6, BITCOIN_P2WPKH_SPENDWITNESS));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_input_writer, 8, 100000));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_input_writer, 20, 0));
    trezor_protobuf_writer_init(&trezor_btc_tx_writer, trezor_btc_tx_payload, sizeof(trezor_btc_tx_payload));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_tx_writer, 2, trezor_btc_input_payload, trezor_btc_input_writer.len));
    trezor_protobuf_writer_init(&trezor_btc_ack_writer, trezor_btc_ack_payload, sizeof(trezor_btc_ack_payload));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_btc_ack_writer, 1, trezor_btc_tx_payload, trezor_btc_tx_writer.len));
    trezor_btc_input_ack_payload_len = trezor_btc_ack_writer.len;
    memcpy(trezor_btc_input_ack_payload, trezor_btc_ack_payload, trezor_btc_input_ack_payload_len);
    trezor_bitcoin_transaction_t trezor_btc_tx_ack;
    CHECK(trezor_bitcoin_tx_ack_decode(trezor_btc_ack_payload, trezor_btc_ack_writer.len, &trezor_btc_tx_ack));
    CHECK(trezor_btc_tx_ack.inputs_len == 1);
    CHECK(trezor_btc_tx_ack.outputs_len == 0);
    CHECK(trezor_btc_tx_ack.inputs[0].address_n_len == ARRAY_LEN(btc_signing_path));
    CHECK(memcmp(trezor_btc_tx_ack.inputs[0].address_n, btc_signing_path, sizeof(btc_signing_path)) == 0);
    CHECK(trezor_btc_tx_ack.inputs[0].has_prev_hash);
    CHECK(memcmp(trezor_btc_tx_ack.inputs[0].prev_hash, trezor_btc_prev_hash, sizeof(trezor_btc_prev_hash)) == 0);
    CHECK(trezor_btc_tx_ack.inputs[0].has_prev_index && trezor_btc_tx_ack.inputs[0].prev_index == 0);
    CHECK(trezor_btc_tx_ack.inputs[0].script_type == BITCOIN_P2WPKH_SPENDWITNESS);
    CHECK(trezor_btc_tx_ack.inputs[0].has_amount && trezor_btc_tx_ack.inputs[0].amount == 100000);

    uint8_t trezor_btc_multisig_payload[512];
    size_t trezor_btc_multisig_payload_len = 0;
    CHECK(make_test_trezor_multisig_payload(
        trezor_btc_multisig_payload, sizeof(trezor_btc_multisig_payload), &trezor_btc_multisig_payload_len));
    trezor_bitcoin_multisig_t trezor_btc_multisig;
    trezor_bitcoin_multisig_policy_t trezor_btc_multisig_p2wsh_policy;
    trezor_bitcoin_multisig_policy_t trezor_btc_multisig_p2sh_policy;
    wally_bzero(&trezor_btc_multisig, sizeof(trezor_btc_multisig));
    wally_bzero(&trezor_btc_multisig_p2wsh_policy, sizeof(trezor_btc_multisig_p2wsh_policy));
    wally_bzero(&trezor_btc_multisig_p2sh_policy, sizeof(trezor_btc_multisig_p2sh_policy));
    CHECK(trezor_bitcoin_multisig_decode(
        trezor_btc_multisig_payload, trezor_btc_multisig_payload_len, &trezor_btc_multisig));
    CHECK(trezor_bitcoin_multisig_normalize(
        &trezor_btc_multisig, BITCOIN_P2WPKH_SPENDWITNESS, &trezor_btc_multisig_p2wsh_policy));
    CHECK(trezor_bitcoin_multisig_normalize(
        &trezor_btc_multisig, BITCOIN_MULTISIG_SPENDMULTISIG, &trezor_btc_multisig_p2sh_policy));
    CHECK(memcmp(trezor_btc_multisig_p2wsh_policy.fingerprint, trezor_btc_multisig_p2sh_policy.fingerprint,
              SHA256_LEN)
        == 0);
    uint8_t trezor_btc_private_multisig_payload[512];
    size_t trezor_btc_private_multisig_payload_len = 0;
    trezor_bitcoin_multisig_t trezor_btc_private_multisig;
    wally_bzero(&trezor_btc_private_multisig, sizeof(trezor_btc_private_multisig));
    CHECK(make_test_trezor_multisig_private_key_payload(1, trezor_btc_private_multisig_payload,
        sizeof(trezor_btc_private_multisig_payload), &trezor_btc_private_multisig_payload_len));
    CHECK(!trezor_bitcoin_multisig_decode(trezor_btc_private_multisig_payload,
        trezor_btc_private_multisig_payload_len, &trezor_btc_private_multisig));
    CHECK(make_test_trezor_multisig_private_key_payload(4, trezor_btc_private_multisig_payload,
        sizeof(trezor_btc_private_multisig_payload), &trezor_btc_private_multisig_payload_len));
    CHECK(!trezor_bitcoin_multisig_decode(trezor_btc_private_multisig_payload,
        trezor_btc_private_multisig_payload_len, &trezor_btc_private_multisig));
    wally_bzero(trezor_btc_private_multisig_payload, sizeof(trezor_btc_private_multisig_payload));
    wally_bzero(&trezor_btc_private_multisig, sizeof(trezor_btc_private_multisig));

    uint8_t trezor_btc_multisig_input_payload[768];
    uint8_t trezor_btc_multisig_output_payload[768];
    uint8_t trezor_btc_multisig_tx_payload[1024];
    uint8_t trezor_btc_multisig_ack_payload[1100];
    uint8_t trezor_btc_multisig_input_ack_payload[1100];
    uint8_t trezor_btc_multisig_output_ack_payload[1100];
    size_t trezor_btc_multisig_input_ack_payload_len = 0;
    size_t trezor_btc_multisig_output_ack_payload_len = 0;
    trezor_bitcoin_tx_ack_multisig_fingerprints_t trezor_btc_tx_ack_fingerprints;
    trezor_protobuf_writer_init(
        &trezor_btc_input_writer, trezor_btc_multisig_input_payload, sizeof(trezor_btc_multisig_input_payload));
    for (size_t i = 0; i < ARRAY_LEN(btc_p2wsh_account_path); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_btc_input_writer, 1, btc_p2wsh_account_path[i]));
    }
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_input_writer, 1, 0));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_input_writer, 2, trezor_btc_prev_hash, sizeof(trezor_btc_prev_hash)));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_input_writer, 3, 0));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_input_writer, 6, BITCOIN_P2WPKH_SPENDWITNESS));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_input_writer, 7, trezor_btc_multisig_payload, trezor_btc_multisig_payload_len));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_input_writer, 8, 100000));
    trezor_protobuf_writer_init(
        &trezor_btc_tx_writer, trezor_btc_multisig_tx_payload, sizeof(trezor_btc_multisig_tx_payload));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_tx_writer, 2, trezor_btc_multisig_input_payload, trezor_btc_input_writer.len));
    trezor_protobuf_writer_init(
        &trezor_btc_ack_writer, trezor_btc_multisig_ack_payload, sizeof(trezor_btc_multisig_ack_payload));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_ack_writer, 1, trezor_btc_multisig_tx_payload, trezor_btc_tx_writer.len));
    trezor_btc_multisig_input_ack_payload_len = trezor_btc_ack_writer.len;
    memcpy(trezor_btc_multisig_input_ack_payload, trezor_btc_multisig_ack_payload,
        trezor_btc_multisig_input_ack_payload_len);
    CHECK(trezor_bitcoin_tx_ack_decode_with_multisig_fingerprints(trezor_btc_multisig_ack_payload,
        trezor_btc_ack_writer.len, &trezor_btc_tx_ack, &trezor_btc_tx_ack_fingerprints));
    CHECK(trezor_btc_tx_ack.inputs_len == 1 && trezor_btc_tx_ack.inputs[0].has_multisig);
    CHECK(trezor_btc_tx_ack_fingerprints.input_has_multisig_fingerprint[0]);
    CHECK(memcmp(trezor_btc_tx_ack_fingerprints.input_multisig_fingerprints[0],
              trezor_btc_multisig_p2wsh_policy.fingerprint, SHA256_LEN)
        == 0);
    CHECK(trezor_bitcoin_tx_ack_decode(trezor_btc_multisig_ack_payload, trezor_btc_ack_writer.len,
        &trezor_btc_tx_ack));
    CHECK(trezor_btc_tx_ack.inputs_len == 1 && trezor_btc_tx_ack.inputs[0].has_multisig);

    trezor_protobuf_writer_init(
        &trezor_btc_output_writer, trezor_btc_multisig_output_payload, sizeof(trezor_btc_multisig_output_payload));
    for (size_t i = 0; i < ARRAY_LEN(btc_p2sh_p2wsh_account_path); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_btc_output_writer, 2, btc_p2sh_p2wsh_account_path[i]));
    }
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_output_writer, 2, 1));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_output_writer, 3, 90000));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_output_writer, 4, BITCOIN_PAYTOMULTISIG));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_output_writer, 5, trezor_btc_multisig_payload, trezor_btc_multisig_payload_len));
    trezor_protobuf_writer_init(
        &trezor_btc_tx_writer, trezor_btc_multisig_tx_payload, sizeof(trezor_btc_multisig_tx_payload));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_tx_writer, 5, trezor_btc_multisig_output_payload, trezor_btc_output_writer.len));
    trezor_protobuf_writer_init(
        &trezor_btc_ack_writer, trezor_btc_multisig_ack_payload, sizeof(trezor_btc_multisig_ack_payload));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_ack_writer, 1, trezor_btc_multisig_tx_payload, trezor_btc_tx_writer.len));
    trezor_btc_multisig_output_ack_payload_len = trezor_btc_ack_writer.len;
    memcpy(trezor_btc_multisig_output_ack_payload, trezor_btc_multisig_ack_payload,
        trezor_btc_multisig_output_ack_payload_len);
    CHECK(trezor_bitcoin_tx_ack_decode_with_multisig_fingerprints(trezor_btc_multisig_ack_payload,
        trezor_btc_ack_writer.len, &trezor_btc_tx_ack, &trezor_btc_tx_ack_fingerprints));
    CHECK(trezor_btc_tx_ack.outputs_len == 1 && trezor_btc_tx_ack.outputs[0].has_multisig);
    CHECK(trezor_btc_tx_ack_fingerprints.output_has_multisig_fingerprint[0]);
    CHECK(memcmp(trezor_btc_tx_ack_fingerprints.output_multisig_fingerprints[0],
              trezor_btc_multisig_p2sh_policy.fingerprint, SHA256_LEN)
        == 0);
    CHECK(trezor_bitcoin_tx_ack_decode(trezor_btc_multisig_ack_payload, trezor_btc_ack_writer.len,
        &trezor_btc_tx_ack));
    CHECK(trezor_btc_tx_ack.outputs_len == 1 && trezor_btc_tx_ack.outputs[0].has_multisig);

    uint8_t trezor_btc_prev_script[32];
    memset(trezor_btc_prev_script, 0x51, sizeof(trezor_btc_prev_script));
    uint8_t trezor_btc_prev_item_payload[640];
    trezor_protobuf_writer_t trezor_btc_prev_item_writer;
    trezor_protobuf_writer_init(
        &trezor_btc_prev_item_writer, trezor_btc_prev_item_payload, sizeof(trezor_btc_prev_item_payload));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_prev_item_writer, 2, trezor_btc_prev_hash, sizeof(trezor_btc_prev_hash)));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_prev_item_writer, 3, 7));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_prev_item_writer, 4, trezor_btc_prev_script, sizeof(trezor_btc_prev_script)));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_prev_item_writer, 5, 0xfffffffeUL));
    trezor_bitcoin_prev_input_t trezor_btc_prev_input;
    CHECK(trezor_bitcoin_prev_input_decode(
        trezor_btc_prev_item_payload, trezor_btc_prev_item_writer.len, &trezor_btc_prev_input));
    CHECK(trezor_btc_prev_input.has_prev_hash);
    CHECK(memcmp(trezor_btc_prev_input.prev_hash, trezor_btc_prev_hash, sizeof(trezor_btc_prev_hash)) == 0);
    CHECK(trezor_btc_prev_input.has_prev_index && trezor_btc_prev_input.prev_index == 7);
    CHECK(trezor_btc_prev_input.has_script_sig && trezor_btc_prev_input.script_sig_len == sizeof(trezor_btc_prev_script));
    CHECK(memcmp(trezor_btc_prev_input.script_sig, trezor_btc_prev_script, sizeof(trezor_btc_prev_script)) == 0);
    CHECK(trezor_btc_prev_input.has_sequence && trezor_btc_prev_input.sequence == 0xfffffffeUL);
    const trezor_bitcoin_prev_input_t trezor_btc_valid_prev_input = trezor_btc_prev_input;

    trezor_protobuf_writer_init(
        &trezor_btc_prev_item_writer, trezor_btc_prev_item_payload, sizeof(trezor_btc_prev_item_payload));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_prev_item_writer, 2, trezor_btc_prev_hash, sizeof(trezor_btc_prev_hash)));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_prev_item_writer, 3, 7));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_prev_item_writer, 5, 0xfffffffeUL));
    CHECK(!trezor_bitcoin_prev_input_decode(
        trezor_btc_prev_item_payload, trezor_btc_prev_item_writer.len, &trezor_btc_prev_input));

    uint8_t trezor_btc_oversized_script[TREZOR_BITCOIN_PREV_SCRIPT_MAX_LEN + 1U];
    memset(trezor_btc_oversized_script, 0x52, sizeof(trezor_btc_oversized_script));
    trezor_protobuf_writer_init(
        &trezor_btc_prev_item_writer, trezor_btc_prev_item_payload, sizeof(trezor_btc_prev_item_payload));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_prev_item_writer, 2, trezor_btc_prev_hash, sizeof(trezor_btc_prev_hash)));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_prev_item_writer, 3, 0));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_btc_prev_item_writer, 4, trezor_btc_oversized_script,
        sizeof(trezor_btc_oversized_script)));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_prev_item_writer, 5, UINT32_MAX));
    CHECK(!trezor_bitcoin_prev_input_decode(
        trezor_btc_prev_item_payload, trezor_btc_prev_item_writer.len, &trezor_btc_prev_input));

    trezor_protobuf_writer_init(
        &trezor_btc_prev_item_writer, trezor_btc_prev_item_payload, sizeof(trezor_btc_prev_item_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_prev_item_writer, 1, 90000));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_btc_prev_item_writer, 2, EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY,
        sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY)));
    trezor_bitcoin_prev_output_t trezor_btc_prev_output;
    CHECK(trezor_bitcoin_prev_output_decode(
        trezor_btc_prev_item_payload, trezor_btc_prev_item_writer.len, &trezor_btc_prev_output));
    CHECK(trezor_btc_prev_output.has_amount && trezor_btc_prev_output.amount == 90000);
    CHECK(trezor_btc_prev_output.has_script_pubkey
        && trezor_btc_prev_output.script_pubkey_len == sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY));
    CHECK(memcmp(trezor_btc_prev_output.script_pubkey, EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY,
              sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY))
        == 0);
    const trezor_bitcoin_prev_output_t trezor_btc_valid_prev_output = trezor_btc_prev_output;

    trezor_protobuf_writer_init(
        &trezor_btc_prev_item_writer, trezor_btc_prev_item_payload, sizeof(trezor_btc_prev_item_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_prev_item_writer, 1, 90000));
    CHECK(!trezor_bitcoin_prev_output_decode(
        trezor_btc_prev_item_payload, trezor_btc_prev_item_writer.len, &trezor_btc_prev_output));

    trezor_protobuf_writer_init(
        &trezor_btc_prev_item_writer, trezor_btc_prev_item_payload, sizeof(trezor_btc_prev_item_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_prev_item_writer, 1, 90000));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_btc_prev_item_writer, 2, EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY,
        sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY)));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_prev_item_writer, 3, 0));
    CHECK(!trezor_bitcoin_prev_output_decode(
        trezor_btc_prev_item_payload, trezor_btc_prev_item_writer.len, &trezor_btc_prev_output));

    struct wally_tx* expected_prev_tx = NULL;
    uint8_t expected_prev_txid[SHA256_LEN];
    CHECK(wally_tx_init_alloc(2, 0, 1, 2, &expected_prev_tx) == WALLY_OK);
    CHECK(expected_prev_tx);
    CHECK(wally_tx_add_raw_input(expected_prev_tx, trezor_btc_prev_hash, sizeof(trezor_btc_prev_hash), 7,
              0xfffffffeUL, trezor_btc_prev_script, sizeof(trezor_btc_prev_script), NULL, 0)
        == WALLY_OK);
    CHECK(wally_tx_add_raw_output(expected_prev_tx, 90000, EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY,
              sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY), 0)
        == WALLY_OK);
    CHECK(wally_tx_add_raw_output(expected_prev_tx, 1000, EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY,
              sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY), 0)
        == WALLY_OK);
    CHECK(wally_tx_get_txid(expected_prev_tx, expected_prev_txid, sizeof(expected_prev_txid)) == WALLY_OK);
    CHECK(wally_tx_free(expected_prev_tx) == WALLY_OK);
    uint8_t expected_prev_txid_wire[SHA256_LEN];
    for (size_t i = 0; i < sizeof(expected_prev_txid_wire); ++i) {
        expected_prev_txid_wire[i] = expected_prev_txid[sizeof(expected_prev_txid_wire) - 1U - i];
    }

    trezor_bitcoin_transaction_t trezor_btc_prev_meta;
    memset(&trezor_btc_prev_meta, 0, sizeof(trezor_btc_prev_meta));
    trezor_btc_prev_meta.has_version = true;
    trezor_btc_prev_meta.version = 2;
    trezor_btc_prev_meta.has_lock_time = true;
    trezor_btc_prev_meta.lock_time = 0;
    trezor_btc_prev_meta.has_inputs_cnt = true;
    trezor_btc_prev_meta.inputs_cnt = 1;
    trezor_btc_prev_meta.has_outputs_cnt = true;
    trezor_btc_prev_meta.outputs_cnt = 2;

    trezor_bitcoin_prev_output_t trezor_btc_prev_output_change = trezor_btc_valid_prev_output;
    trezor_btc_prev_output_change.amount = 1000;
    trezor_bitcoin_prev_tx_verifier_t trezor_btc_prev_verifier;
    memset(&trezor_btc_prev_verifier, 0, sizeof(trezor_btc_prev_verifier));
    CHECK(trezor_bitcoin_prev_tx_verifier_init(&trezor_btc_prev_verifier, &trezor_btc_prev_meta,
        expected_prev_txid_wire, sizeof(expected_prev_txid_wire), 0));
    CHECK(!trezor_bitcoin_prev_tx_verifier_apply_output(&trezor_btc_prev_verifier, &trezor_btc_valid_prev_output));
    CHECK(trezor_bitcoin_prev_tx_verifier_apply_input(&trezor_btc_prev_verifier, &trezor_btc_valid_prev_input));
    CHECK(trezor_bitcoin_prev_tx_verifier_apply_output(&trezor_btc_prev_verifier, &trezor_btc_valid_prev_output));
    CHECK(trezor_bitcoin_prev_tx_verifier_apply_output(&trezor_btc_prev_verifier, &trezor_btc_prev_output_change));
    uint64_t verified_prevout_amount = 0;
    uint8_t verified_prevout_script[TREZOR_BITCOIN_PREV_SCRIPT_MAX_LEN];
    size_t verified_prevout_script_len = 0;
    CHECK(trezor_bitcoin_prev_tx_verifier_finish(&trezor_btc_prev_verifier, &verified_prevout_amount,
        verified_prevout_script, sizeof(verified_prevout_script), &verified_prevout_script_len));
    CHECK(verified_prevout_amount == 90000);
    CHECK(verified_prevout_script_len == sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY));
    CHECK(memcmp(verified_prevout_script, EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY,
              sizeof(EXPECTED_BTC_P2WPKH_SCRIPTPUBKEY))
        == 0);

    uint8_t wrong_prev_txid[SHA256_LEN];
    memcpy(wrong_prev_txid, expected_prev_txid_wire, sizeof(wrong_prev_txid));
    wrong_prev_txid[0] ^= 0x01;
    CHECK(trezor_bitcoin_prev_tx_verifier_init(&trezor_btc_prev_verifier, &trezor_btc_prev_meta,
        wrong_prev_txid, sizeof(wrong_prev_txid), 0));
    CHECK(trezor_bitcoin_prev_tx_verifier_apply_input(&trezor_btc_prev_verifier, &trezor_btc_valid_prev_input));
    CHECK(trezor_bitcoin_prev_tx_verifier_apply_output(&trezor_btc_prev_verifier, &trezor_btc_valid_prev_output));
    CHECK(trezor_bitcoin_prev_tx_verifier_apply_output(&trezor_btc_prev_verifier, &trezor_btc_prev_output_change));
    CHECK(!trezor_bitcoin_prev_tx_verifier_finish(&trezor_btc_prev_verifier, &verified_prevout_amount,
        verified_prevout_script, sizeof(verified_prevout_script), &verified_prevout_script_len));
    CHECK(verified_prevout_amount == 0);
    CHECK(verified_prevout_script_len == 0);

    CHECK(!trezor_bitcoin_prev_tx_verifier_init(&trezor_btc_prev_verifier, &trezor_btc_prev_meta,
        expected_prev_txid_wire, sizeof(expected_prev_txid_wire), trezor_btc_prev_meta.outputs_cnt));

    trezor_protobuf_writer_init(&trezor_btc_output_writer, trezor_btc_output_payload, sizeof(trezor_btc_output_payload));
    CHECK(trezor_protobuf_write_string_field(
        &trezor_btc_output_writer, 1, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_output_writer, 3, 90000));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_output_writer, 4, 0));
    trezor_protobuf_writer_init(&trezor_btc_tx_writer, trezor_btc_tx_payload, sizeof(trezor_btc_tx_payload));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_tx_writer, 5, trezor_btc_output_payload, trezor_btc_output_writer.len));
    trezor_protobuf_writer_init(&trezor_btc_ack_writer, trezor_btc_ack_payload, sizeof(trezor_btc_ack_payload));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_btc_ack_writer, 1, trezor_btc_tx_payload, trezor_btc_tx_writer.len));
    trezor_btc_output_ack_payload_len = trezor_btc_ack_writer.len;
    memcpy(trezor_btc_output_ack_payload, trezor_btc_ack_payload, trezor_btc_output_ack_payload_len);
    CHECK(trezor_bitcoin_tx_ack_decode(trezor_btc_ack_payload, trezor_btc_ack_writer.len, &trezor_btc_tx_ack));
    CHECK(trezor_btc_tx_ack.inputs_len == 0);
    CHECK(trezor_btc_tx_ack.outputs_len == 1);
    CHECK(trezor_btc_tx_ack.outputs[0].has_address);
    CHECK(strcmp(trezor_btc_tx_ack.outputs[0].address, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx") == 0);
    CHECK(trezor_btc_tx_ack.outputs[0].has_amount && trezor_btc_tx_ack.outputs[0].amount == 90000);

    trezor_protobuf_writer_init(&trezor_btc_tx_writer, trezor_btc_tx_payload, sizeof(trezor_btc_tx_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_tx_writer, 1, 2));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_tx_writer, 6, 1));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_tx_writer, 7, 1));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_tx_writer, 9, 0));
    trezor_protobuf_writer_init(&trezor_btc_ack_writer, trezor_btc_ack_payload, sizeof(trezor_btc_ack_payload));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_btc_ack_writer, 1, trezor_btc_tx_payload, trezor_btc_tx_writer.len));
    trezor_btc_meta_ack_payload_len = trezor_btc_ack_writer.len;
    memcpy(trezor_btc_meta_ack_payload, trezor_btc_ack_payload, trezor_btc_meta_ack_payload_len);
    CHECK(trezor_bitcoin_tx_ack_decode(trezor_btc_ack_payload, trezor_btc_ack_writer.len, &trezor_btc_tx_ack));
    CHECK(trezor_btc_tx_ack.has_version && trezor_btc_tx_ack.version == 2);
    CHECK(trezor_btc_tx_ack.has_inputs_cnt && trezor_btc_tx_ack.inputs_cnt == 1);
    CHECK(trezor_btc_tx_ack.has_outputs_cnt && trezor_btc_tx_ack.outputs_cnt == 1);

    trezor_bitcoin_signing_state_t trezor_btc_confirm_bind_state;
    bitcoin_confirm_request_t trezor_btc_confirm_bind_request;
    CHECK(trezor_bitcoin_signing_init(&trezor_btc_confirm_bind_state, trezor_valid_sign_tx_payload,
        trezor_valid_sign_tx_payload_len));
    CHECK(trezor_bitcoin_signing_apply_tx_ack(
        &trezor_btc_confirm_bind_state, trezor_btc_meta_ack_payload, trezor_btc_meta_ack_payload_len));
    CHECK(trezor_bitcoin_signing_apply_tx_ack(
        &trezor_btc_confirm_bind_state, trezor_btc_input_ack_payload, trezor_btc_input_ack_payload_len));
    CHECK(trezor_bitcoin_signing_apply_tx_ack(
        &trezor_btc_confirm_bind_state, trezor_btc_output_ack_payload, trezor_btc_output_ack_payload_len));
    CHECK(trezor_bitcoin_signing_ready(&trezor_btc_confirm_bind_state));
    CHECK(trezor_bitcoin_signing_to_confirm_request(
        &trezor_btc_confirm_bind_state, &trezor_btc_confirm_bind_request));
    CHECK(trezor_bitcoin_confirm_request_matches_state(
        &trezor_btc_confirm_bind_state, &trezor_btc_confirm_bind_request));
    trezor_btc_confirm_bind_request.amount++;
    CHECK(!trezor_bitcoin_confirm_request_matches_state(
        &trezor_btc_confirm_bind_state, &trezor_btc_confirm_bind_request));
    trezor_btc_confirm_bind_request.amount--;
    trezor_btc_confirm_bind_request.fee++;
    CHECK(!trezor_bitcoin_confirm_request_matches_state(
        &trezor_btc_confirm_bind_state, &trezor_btc_confirm_bind_request));
    trezor_btc_confirm_bind_request.fee--;
    trezor_btc_confirm_bind_request.to[0] = trezor_btc_confirm_bind_request.to[0] == 't' ? 'b' : 't';
    CHECK(!trezor_bitcoin_confirm_request_matches_state(
        &trezor_btc_confirm_bind_state, &trezor_btc_confirm_bind_request));
    CHECK(trezor_bitcoin_signing_to_confirm_request(
        &trezor_btc_confirm_bind_state, &trezor_btc_confirm_bind_request));
    trezor_btc_confirm_bind_request.path[0] ^= 1U;
    CHECK(!trezor_bitcoin_confirm_request_matches_state(
        &trezor_btc_confirm_bind_state, &trezor_btc_confirm_bind_request));
    wally_bzero(&trezor_btc_confirm_bind_state, sizeof(trezor_btc_confirm_bind_state));
    wally_bzero(&trezor_btc_confirm_bind_request, sizeof(trezor_btc_confirm_bind_request));

    trezor_bitcoin_signing_state_t trezor_btc_multisig_capture_state;
    CHECK(trezor_bitcoin_signing_init(&trezor_btc_multisig_capture_state, trezor_valid_sign_tx_payload,
        trezor_valid_sign_tx_payload_len));
    CHECK(trezor_bitcoin_signing_apply_tx_ack(&trezor_btc_multisig_capture_state, trezor_btc_meta_ack_payload,
        trezor_btc_meta_ack_payload_len));
    CHECK(trezor_btc_multisig_capture_state.phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_INPUT);
    CHECK(trezor_bitcoin_signing_apply_tx_ack(&trezor_btc_multisig_capture_state, trezor_btc_multisig_input_ack_payload,
        trezor_btc_multisig_input_ack_payload_len));
    CHECK(trezor_btc_multisig_capture_state.inputs_len == 1);
    CHECK(trezor_btc_multisig_capture_state.input_has_multisig_fingerprint[0]);
    CHECK(memcmp(trezor_btc_multisig_capture_state.input_multisig_fingerprints[0],
              trezor_btc_multisig_p2wsh_policy.fingerprint, SHA256_LEN)
        == 0);

    CHECK(trezor_bitcoin_signing_apply_tx_ack(&trezor_btc_multisig_capture_state, trezor_btc_multisig_output_ack_payload,
        trezor_btc_multisig_output_ack_payload_len));
    CHECK(trezor_btc_multisig_capture_state.phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_PREV_META);
    CHECK(trezor_btc_multisig_capture_state.outputs_len == 1);
    CHECK(trezor_btc_multisig_capture_state.output_has_multisig_fingerprint[0]);
    CHECK(memcmp(trezor_btc_multisig_capture_state.output_multisig_fingerprints[0],
              trezor_btc_multisig_p2sh_policy.fingerprint, SHA256_LEN)
        == 0);
    CHECK(trezor_bitcoin_policy_multisig_output_matches_inputs(&trezor_btc_multisig_capture_state, 0));
    CHECK(!trezor_bitcoin_policy_multisig_output_matches_inputs(&trezor_btc_multisig_capture_state, 1));
    trezor_btc_multisig_capture_state.output_multisig_fingerprints[0][0] ^= 0x01;
    CHECK(!trezor_bitcoin_policy_multisig_output_matches_inputs(&trezor_btc_multisig_capture_state, 0));
    trezor_btc_multisig_capture_state.output_multisig_fingerprints[0][0] ^= 0x01;
    trezor_btc_multisig_capture_state.inputs_len = 2;
    trezor_btc_multisig_capture_state.inputs[1] = trezor_btc_multisig_capture_state.inputs[0];
    trezor_btc_multisig_capture_state.input_has_multisig_fingerprint[1] = true;
    memcpy(trezor_btc_multisig_capture_state.input_multisig_fingerprints[1],
        trezor_btc_multisig_capture_state.input_multisig_fingerprints[0],
        sizeof(trezor_btc_multisig_capture_state.input_multisig_fingerprints[1]));
    trezor_btc_multisig_capture_state.input_multisig_fingerprints[1][0] ^= 0x01;
    CHECK(!trezor_bitcoin_policy_multisig_output_matches_inputs(&trezor_btc_multisig_capture_state, 0));
    trezor_btc_multisig_capture_state.input_multisig_fingerprints[1][0] ^= 0x01;
    trezor_btc_multisig_capture_state.inputs[1].has_multisig = false;
    CHECK(!trezor_bitcoin_policy_multisig_output_matches_inputs(&trezor_btc_multisig_capture_state, 0));
    trezor_btc_multisig_capture_state.inputs_len = 1;
    CHECK(!trezor_bitcoin_policy_is_basic(&trezor_btc_multisig_capture_state));

    trezor_bitcoin_signing_state_t trezor_btc_multisig_preview_state = trezor_btc_multisig_capture_state;
    trezor_btc_multisig_preview_state.inputs[0].address_n_len = ARRAY_LEN(btc_p2wsh_account_path) + 2U;
    memcpy(
        trezor_btc_multisig_preview_state.inputs[0].address_n, btc_p2wsh_account_path, sizeof(btc_p2wsh_account_path));
    trezor_btc_multisig_preview_state.inputs[0].address_n[ARRAY_LEN(btc_p2wsh_account_path)] = 0;
    trezor_btc_multisig_preview_state.inputs[0].address_n[ARRAY_LEN(btc_p2wsh_account_path) + 1U] = 0;
    trezor_btc_multisig_preview_state.request.outputs_count = 2;
    trezor_btc_multisig_preview_state.outputs_len = 2;
    trezor_btc_multisig_preview_state.outputs[1] = trezor_btc_multisig_preview_state.outputs[0];
    trezor_btc_multisig_preview_state.outputs[1].address_n_len = ARRAY_LEN(btc_p2wsh_account_path) + 2U;
    memcpy(
        trezor_btc_multisig_preview_state.outputs[1].address_n, btc_p2wsh_account_path, sizeof(btc_p2wsh_account_path));
    trezor_btc_multisig_preview_state.outputs[1].address_n[ARRAY_LEN(btc_p2wsh_account_path)] = 1;
    trezor_btc_multisig_preview_state.outputs[1].address_n[ARRAY_LEN(btc_p2wsh_account_path) + 1U] = 0;
    host_multisig_policy_to_summary(
        &trezor_btc_multisig_p2wsh_policy, &trezor_btc_multisig_preview_state.outputs[1].multisig);
    trezor_btc_multisig_preview_state.output_has_multisig_fingerprint[1]
        = trezor_btc_multisig_preview_state.output_has_multisig_fingerprint[0];
    memcpy(trezor_btc_multisig_preview_state.output_multisig_fingerprints[1],
        trezor_btc_multisig_preview_state.output_multisig_fingerprints[0],
        sizeof(trezor_btc_multisig_preview_state.output_multisig_fingerprints[1]));
    memset(&trezor_btc_multisig_preview_state.outputs[0], 0, sizeof(trezor_btc_multisig_preview_state.outputs[0]));
    trezor_btc_multisig_preview_state.outputs[0].has_address = true;
    memcpy(trezor_btc_multisig_preview_state.outputs[0].address,
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        sizeof("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"));
    trezor_btc_multisig_preview_state.outputs[0].has_amount = true;
    trezor_btc_multisig_preview_state.outputs[0].amount = 90000;
    trezor_btc_multisig_preview_state.outputs[0].script_type = BITCOIN_PAYTOADDRESS;
    trezor_btc_multisig_preview_state.outputs[1].amount = 5000;
    trezor_btc_multisig_preview_state.inputs[0].has_verified_prevout_script = true;
    trezor_btc_multisig_preview_state.inputs[0].verified_prevout_script_len
        = trezor_btc_multisig_p2wsh_policy.script_pubkey_len;
    memcpy(trezor_btc_multisig_preview_state.inputs[0].verified_prevout_script,
        trezor_btc_multisig_p2wsh_policy.script_pubkey,
        trezor_btc_multisig_p2wsh_policy.script_pubkey_len);
    trezor_btc_multisig_preview_state.total_input = 100000;
    trezor_btc_multisig_preview_state.total_output = 95000;
    trezor_btc_multisig_preview_state.fee = 5000;
    trezor_btc_multisig_preview_state.fee_rate_sats_per_vbyte = 10;
    trezor_btc_multisig_preview_state.phase = TREZOR_BITCOIN_SIGNING_PHASE_READY;
    trezor_bitcoin_multisig_preview_t trezor_btc_multisig_preview;
    CHECK(trezor_bitcoin_policy_multisig_preview(&trezor_btc_multisig_preview_state, &trezor_btc_multisig_preview));
    CHECK(trezor_btc_multisig_preview.external_outputs == 1);
    CHECK(trezor_btc_multisig_preview.first_external_output_index == 0);
    CHECK(trezor_btc_multisig_preview.external_amount == 90000);
    CHECK(trezor_btc_multisig_preview.change_amount == 5000);
    bitcoin_confirm_request_t trezor_btc_multisig_confirm_request;
    CHECK(trezor_bitcoin_signing_to_multisig_confirm_request(
        &trezor_btc_multisig_preview_state, &trezor_btc_multisig_confirm_request));
    CHECK(trezor_btc_multisig_confirm_request.amount == 90000);
    CHECK(trezor_btc_multisig_confirm_request.change == 5000);
    CHECK(trezor_btc_multisig_confirm_request.fee == 5000);
    CHECK(strcmp(trezor_btc_multisig_confirm_request.policy, "2-of-2 P2WSH") == 0);
    CHECK(strcmp(trezor_btc_multisig_confirm_request.to, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx") == 0);
    CHECK(trezor_bitcoin_multisig_confirm_request_matches_state(
        &trezor_btc_multisig_preview_state, &trezor_btc_multisig_confirm_request));
    trezor_btc_multisig_confirm_request.change++;
    CHECK(!trezor_bitcoin_multisig_confirm_request_matches_state(
        &trezor_btc_multisig_preview_state, &trezor_btc_multisig_confirm_request));
    CHECK(trezor_bitcoin_signing_to_multisig_confirm_request(
        &trezor_btc_multisig_preview_state, &trezor_btc_multisig_confirm_request));
    trezor_btc_multisig_confirm_request.policy[0] = '3';
    CHECK(!trezor_bitcoin_multisig_confirm_request_matches_state(
        &trezor_btc_multisig_preview_state, &trezor_btc_multisig_confirm_request));
    CHECK(trezor_bitcoin_signing_to_multisig_confirm_request(
        &trezor_btc_multisig_preview_state, &trezor_btc_multisig_confirm_request));
    chain_confirm_summary_t trezor_btc_multisig_summary;
    CHECK(bitcoin_confirm_summary_from_request(&trezor_btc_multisig_confirm_request, &trezor_btc_multisig_summary));
    const chain_confirm_field_t* const trezor_btc_multisig_policy
        = find_confirm_field(&trezor_btc_multisig_summary, CHAIN_CONFIRM_FIELD_POLICY);
    CHECK(trezor_btc_multisig_policy && trezor_btc_multisig_policy->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(trezor_btc_multisig_policy->value.text, "2-of-2 P2WSH") == 0);
    CHECK(test_confirm_summary_fits_tdisplay_s3(&trezor_btc_multisig_summary));
    trezor_btc_multisig_preview_state.inputs[0].has_verified_prevout_script = false;
    CHECK(!trezor_bitcoin_policy_multisig_preview(&trezor_btc_multisig_preview_state, &trezor_btc_multisig_preview));
    trezor_btc_multisig_preview_state.inputs[0].has_verified_prevout_script = true;
    memcpy(trezor_btc_multisig_preview_state.outputs[0].address, "not-a-bitcoin-address",
        sizeof("not-a-bitcoin-address"));
    CHECK(trezor_bitcoin_policy_multisig_preview(&trezor_btc_multisig_preview_state, &trezor_btc_multisig_preview));
    CHECK(!trezor_bitcoin_signing_to_multisig_confirm_request(
        &trezor_btc_multisig_preview_state, &trezor_btc_multisig_confirm_request));

    uint8_t trezor_btc_tx_request_payload[64];
    size_t trezor_btc_tx_request_payload_len = 0;
    CHECK(trezor_bitcoin_tx_request_encode(TREZOR_BITCOIN_REQUEST_TXINPUT, true, 0,
        trezor_btc_tx_request_payload, sizeof(trezor_btc_tx_request_payload), &trezor_btc_tx_request_payload_len));
    CHECK(trezor_btc_tx_request_payload_len == 6);
    CHECK(trezor_btc_tx_request_payload[0] == ((1 << 3) | TREZOR_PROTOBUF_WIRE_VARINT));
    CHECK(trezor_btc_tx_request_payload[1] == TREZOR_BITCOIN_REQUEST_TXINPUT);
    CHECK(trezor_btc_tx_request_payload[2] == ((2 << 3) | TREZOR_PROTOBUF_WIRE_LEN));
    CHECK(trezor_btc_tx_request_payload[3] == 2);
    CHECK(trezor_btc_tx_request_payload[4] == ((1 << 3) | TREZOR_PROTOBUF_WIRE_VARINT));
    CHECK(trezor_btc_tx_request_payload[5] == 0);
    CHECK(trezor_bitcoin_tx_request_encode(TREZOR_BITCOIN_REQUEST_TXMETA, false, 0,
        trezor_btc_tx_request_payload, sizeof(trezor_btc_tx_request_payload), &trezor_btc_tx_request_payload_len));
    CHECK(trezor_btc_tx_request_payload_len == 4);
    CHECK(trezor_btc_tx_request_payload[0] == ((1 << 3) | TREZOR_PROTOBUF_WIRE_VARINT));
    CHECK(trezor_btc_tx_request_payload[1] == TREZOR_BITCOIN_REQUEST_TXMETA);
    CHECK(trezor_btc_tx_request_payload[2] == ((2 << 3) | TREZOR_PROTOBUF_WIRE_LEN));
    CHECK(trezor_btc_tx_request_payload[3] == 0);
    CHECK(trezor_bitcoin_tx_request_encode(TREZOR_BITCOIN_REQUEST_TXFINISHED, false, 0,
        trezor_btc_tx_request_payload, sizeof(trezor_btc_tx_request_payload), &trezor_btc_tx_request_payload_len));
    CHECK(trezor_btc_tx_request_payload_len == 2);
    CHECK(trezor_btc_tx_request_payload[0] == ((1 << 3) | TREZOR_PROTOBUF_WIRE_VARINT));
    CHECK(trezor_btc_tx_request_payload[1] == TREZOR_BITCOIN_REQUEST_TXFINISHED);
    const uint8_t trezor_btc_txoriginput_request_payload[] = { 0x08, 0x05, 0x12, 0x24, 0x08, 0x00,
        0x12, 0x20, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
    CHECK(trezor_bitcoin_tx_request_encode_with_tx_hash(TREZOR_BITCOIN_REQUEST_TXORIGINPUT, true, 0,
        trezor_btc_prev_hash, sizeof(trezor_btc_prev_hash), trezor_btc_tx_request_payload,
        sizeof(trezor_btc_tx_request_payload), &trezor_btc_tx_request_payload_len));
    CHECK(trezor_btc_tx_request_payload_len == sizeof(trezor_btc_txoriginput_request_payload));
    CHECK(memcmp(trezor_btc_tx_request_payload, trezor_btc_txoriginput_request_payload,
              sizeof(trezor_btc_txoriginput_request_payload))
        == 0);
    const uint8_t trezor_btc_txorigoutput_request_payload[] = { 0x08, 0x06, 0x12, 0x24, 0x08, 0x01,
        0x12, 0x20, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
    CHECK(trezor_bitcoin_tx_request_encode_with_tx_hash(TREZOR_BITCOIN_REQUEST_TXORIGOUTPUT, true, 1,
        trezor_btc_prev_hash, sizeof(trezor_btc_prev_hash), trezor_btc_tx_request_payload,
        sizeof(trezor_btc_tx_request_payload), &trezor_btc_tx_request_payload_len));
    CHECK(trezor_btc_tx_request_payload_len == sizeof(trezor_btc_txorigoutput_request_payload));
    CHECK(memcmp(trezor_btc_tx_request_payload, trezor_btc_txorigoutput_request_payload,
              sizeof(trezor_btc_txorigoutput_request_payload))
        == 0);
    const uint8_t trezor_btc_prevmeta_request_payload[] = { 0x08, 0x02, 0x12, 0x22, 0x12, 0x20,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11 };
    CHECK(trezor_bitcoin_tx_request_encode_with_tx_hash(TREZOR_BITCOIN_REQUEST_TXMETA, false, 0,
        trezor_btc_prev_hash, sizeof(trezor_btc_prev_hash), trezor_btc_tx_request_payload,
        sizeof(trezor_btc_tx_request_payload), &trezor_btc_tx_request_payload_len));
    CHECK(trezor_btc_tx_request_payload_len == sizeof(trezor_btc_prevmeta_request_payload));
    CHECK(memcmp(trezor_btc_tx_request_payload, trezor_btc_prevmeta_request_payload,
              sizeof(trezor_btc_prevmeta_request_payload))
        == 0);
    CHECK(!trezor_bitcoin_tx_request_encode_with_tx_hash(TREZOR_BITCOIN_REQUEST_TXFINISHED, false, 0,
        trezor_btc_prev_hash, sizeof(trezor_btc_prev_hash), trezor_btc_tx_request_payload,
        sizeof(trezor_btc_tx_request_payload), &trezor_btc_tx_request_payload_len));
    CHECK(!trezor_bitcoin_tx_request_encode_with_tx_hash(TREZOR_BITCOIN_REQUEST_TXMETA, false, 0,
        trezor_btc_prev_hash, sizeof(trezor_btc_prev_hash) - 1U, trezor_btc_tx_request_payload,
        sizeof(trezor_btc_tx_request_payload), &trezor_btc_tx_request_payload_len));

    uint8_t trezor_public_key_payload[256];
    trezor_protobuf_writer_t trezor_public_key_writer;
    trezor_protobuf_writer_init(&trezor_public_key_writer, trezor_public_key_payload, sizeof(trezor_public_key_payload));
    for (size_t i = 0; i < ARRAY_LEN(eth_ledger_live_legacy); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_public_key_writer, 1, eth_ledger_live_legacy[i]));
    }
    CHECK(trezor_protobuf_write_string_field(&trezor_public_key_writer, 4, "Bitcoin"));
    trezor_public_key_request_t trezor_public_key_request;
    CHECK(trezor_public_key_decode_generic(
        trezor_public_key_payload, trezor_public_key_writer.len, &trezor_public_key_request));
    CHECK(trezor_public_key_request.kind == TREZOR_PUBLIC_KEY_REQUEST_GENERIC);
    CHECK(trezor_public_key_request.address_n_len == ARRAY_LEN(eth_ledger_live_legacy));
    CHECK(memcmp(trezor_public_key_request.address_n, eth_ledger_live_legacy, sizeof(eth_ledger_live_legacy)) == 0);
    const size_t trezor_public_key_payload_len = trezor_public_key_writer.len;

    uint8_t trezor_btc_public_key_payload[256];
    trezor_protobuf_writer_t trezor_btc_public_key_writer;
    trezor_protobuf_writer_init(
        &trezor_btc_public_key_writer, trezor_btc_public_key_payload, sizeof(trezor_btc_public_key_payload));
    for (size_t i = 0; i < ARRAY_LEN(btc_account_path); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_btc_public_key_writer, 1, btc_account_path[i]));
    }
    CHECK(trezor_protobuf_write_string_field(&trezor_btc_public_key_writer, 4, "Testnet"));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_public_key_writer, 5, BITCOIN_P2PKH_SPENDADDRESS));
    CHECK(trezor_public_key_decode_generic(
        trezor_btc_public_key_payload, trezor_btc_public_key_writer.len, &trezor_public_key_request));
    CHECK(trezor_public_key_request.kind == TREZOR_PUBLIC_KEY_REQUEST_GENERIC);
    CHECK(trezor_public_key_request.has_coin_name && strcmp(trezor_public_key_request.coin_name, "Testnet") == 0);
    CHECK(trezor_public_key_request.has_script_type
        && trezor_public_key_request.script_type == BITCOIN_P2PKH_SPENDADDRESS);
    CHECK(trezor_public_key_request.address_n_len == ARRAY_LEN(btc_account_path));
    CHECK(memcmp(trezor_public_key_request.address_n, btc_account_path, sizeof(btc_account_path)) == 0);
    const size_t trezor_btc_public_key_payload_len = trezor_btc_public_key_writer.len;

    uint8_t trezor_btc_taproot_public_key_payload[256];
    trezor_protobuf_writer_init(&trezor_btc_public_key_writer, trezor_btc_taproot_public_key_payload,
        sizeof(trezor_btc_taproot_public_key_payload));
    for (size_t i = 0; i < ARRAY_LEN(btc_account_path); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_btc_public_key_writer, 1, btc_account_path[i]));
    }
    CHECK(trezor_protobuf_write_string_field(&trezor_btc_public_key_writer, 4, "Testnet"));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_public_key_writer, 5, 5));
    CHECK(!trezor_public_key_decode_generic(trezor_btc_taproot_public_key_payload,
        trezor_btc_public_key_writer.len, &trezor_public_key_request));

    uint8_t trezor_btc_mainnet_public_key_payload[256];
    trezor_protobuf_writer_t trezor_btc_mainnet_public_key_writer;
    trezor_protobuf_writer_init(&trezor_btc_mainnet_public_key_writer, trezor_btc_mainnet_public_key_payload,
        sizeof(trezor_btc_mainnet_public_key_payload));
    for (size_t i = 0; i < ARRAY_LEN(btc_mainnet_p2wpkh_account_path); ++i) {
        CHECK(trezor_protobuf_write_varint_field(
            &trezor_btc_mainnet_public_key_writer, 1, btc_mainnet_p2wpkh_account_path[i]));
    }
    CHECK(trezor_protobuf_write_string_field(&trezor_btc_mainnet_public_key_writer, 4, "Bitcoin"));
    CHECK(trezor_protobuf_write_varint_field(
        &trezor_btc_mainnet_public_key_writer, 5, BITCOIN_P2WPKH_SPENDWITNESS));
    CHECK(trezor_protobuf_write_bool_field(&trezor_btc_mainnet_public_key_writer, 6, false));
    CHECK(trezor_public_key_decode_generic(trezor_btc_mainnet_public_key_payload,
        trezor_btc_mainnet_public_key_writer.len, &trezor_public_key_request));
    CHECK(trezor_public_key_request.kind == TREZOR_PUBLIC_KEY_REQUEST_GENERIC);
    CHECK(trezor_public_key_request.has_coin_name && strcmp(trezor_public_key_request.coin_name, "Bitcoin") == 0);
    CHECK(trezor_public_key_request.has_script_type
        && trezor_public_key_request.script_type == BITCOIN_P2WPKH_SPENDWITNESS);
    CHECK(trezor_public_key_request.has_ignore_xpub_magic && !trezor_public_key_request.ignore_xpub_magic);
    CHECK(trezor_public_key_request.address_n_len == ARRAY_LEN(btc_mainnet_p2wpkh_account_path));
    CHECK(memcmp(trezor_public_key_request.address_n, btc_mainnet_p2wpkh_account_path,
              sizeof(btc_mainnet_p2wpkh_account_path))
        == 0);
    const size_t trezor_btc_mainnet_public_key_payload_len = trezor_btc_mainnet_public_key_writer.len;

    uint8_t trezor_root_fingerprint_payload[64];
    trezor_protobuf_writer_t trezor_root_fingerprint_writer;
    trezor_protobuf_writer_init(
        &trezor_root_fingerprint_writer, trezor_root_fingerprint_payload, sizeof(trezor_root_fingerprint_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_root_fingerprint_writer, 1, chain_path_harden(0)));
    CHECK(trezor_protobuf_write_string_field(&trezor_root_fingerprint_writer, 2, "secp256k1"));
    CHECK(trezor_protobuf_write_bool_field(&trezor_root_fingerprint_writer, 3, false));
    CHECK(trezor_protobuf_write_bool_field(&trezor_root_fingerprint_writer, 6, true));
    trezor_public_key_request_t trezor_root_fingerprint_request;
    CHECK(trezor_public_key_decode_generic(trezor_root_fingerprint_payload, trezor_root_fingerprint_writer.len,
        &trezor_root_fingerprint_request));
    CHECK(trezor_public_key_is_root_fingerprint_probe(&trezor_root_fingerprint_request));

    trezor_protobuf_writer_init(
        &trezor_root_fingerprint_writer, trezor_root_fingerprint_payload, sizeof(trezor_root_fingerprint_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_root_fingerprint_writer, 1, chain_path_harden(1)));
    CHECK(trezor_protobuf_write_string_field(&trezor_root_fingerprint_writer, 2, "secp256k1"));
    CHECK(trezor_protobuf_write_bool_field(&trezor_root_fingerprint_writer, 3, false));
    CHECK(trezor_protobuf_write_bool_field(&trezor_root_fingerprint_writer, 6, true));
    CHECK(trezor_public_key_decode_generic(trezor_root_fingerprint_payload, trezor_root_fingerprint_writer.len,
        &trezor_root_fingerprint_request));
    CHECK(!trezor_public_key_is_root_fingerprint_probe(&trezor_root_fingerprint_request));

    uint8_t trezor_eth_public_key_payload[256];
    trezor_protobuf_writer_t trezor_eth_public_key_writer;
    trezor_protobuf_writer_init(
        &trezor_eth_public_key_writer, trezor_eth_public_key_payload, sizeof(trezor_eth_public_key_payload));
    for (size_t i = 0; i < ARRAY_LEN(eth_sep5); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_eth_public_key_writer, 1, eth_sep5[i]));
    }
    CHECK(trezor_protobuf_write_bool_field(&trezor_eth_public_key_writer, 2, false));
    CHECK(trezor_public_key_decode_ethereum(
        trezor_eth_public_key_payload, trezor_eth_public_key_writer.len, &trezor_public_key_request));
    CHECK(trezor_public_key_request.kind == TREZOR_PUBLIC_KEY_REQUEST_ETHEREUM);
    CHECK(trezor_public_key_request.has_show_display && !trezor_public_key_request.show_display);
    CHECK(trezor_public_key_request.address_n_len == ARRAY_LEN(eth_sep5));
    CHECK(memcmp(trezor_public_key_request.address_n, eth_sep5, sizeof(eth_sep5)) == 0);
    const size_t trezor_eth_public_key_payload_len = trezor_eth_public_key_writer.len;

    trezor_public_key_response_t trezor_public_key_response;
    CHECK(trezor_test_get_public_key(NULL, &trezor_public_key_request, &trezor_public_key_response));
    uint8_t trezor_public_key_response_payload[256];
    size_t trezor_public_key_response_payload_len = 0;
    CHECK(trezor_public_key_encode_generic(&trezor_public_key_response, trezor_public_key_response_payload,
        sizeof(trezor_public_key_response_payload), &trezor_public_key_response_payload_len));
    CHECK(trezor_public_key_response_payload_len > 0);
    CHECK(!trezor_public_key_payload_has_private_key_field(
        trezor_public_key_response_payload, trezor_public_key_response_payload_len));
    CHECK(trezor_payload_has_varint(
        trezor_public_key_response_payload, trezor_public_key_response_payload_len, 3, 0xaabbccdd));

    uint8_t trezor_eth_public_key_response_payload[256];
    size_t trezor_eth_public_key_response_payload_len = 0;
    CHECK(trezor_public_key_encode_ethereum(&trezor_public_key_response, trezor_eth_public_key_response_payload,
        sizeof(trezor_eth_public_key_response_payload), &trezor_eth_public_key_response_payload_len));
    CHECK(trezor_eth_public_key_response_payload_len > 0);
    CHECK(!trezor_public_key_payload_has_private_key_field(
        trezor_eth_public_key_response_payload, trezor_eth_public_key_response_payload_len));
    CHECK(!trezor_payload_has_varint(
        trezor_eth_public_key_response_payload, trezor_eth_public_key_response_payload_len, 3, 0xaabbccdd));

    uint8_t invalid_public_key_payload[64];
    trezor_protobuf_writer_t invalid_public_key_writer;
    trezor_protobuf_writer_init(&invalid_public_key_writer, invalid_public_key_payload, sizeof(invalid_public_key_payload));
    CHECK(trezor_protobuf_write_varint_field(&invalid_public_key_writer, 1, eth_sep5[0]));
    CHECK(trezor_protobuf_write_string_field(&invalid_public_key_writer, 4, "Litecoin"));
    CHECK(!trezor_public_key_decode_generic(
        invalid_public_key_payload, invalid_public_key_writer.len, &trezor_public_key_request));

    size_t wire_len = 0;
    uint8_t wire_chunks[256];
    uint8_t wire_decoded[256];
    uint16_t wire_type = 0;
    size_t wire_payload_len = 0;
    CHECK(trezor_wire_encoded_len(trezor_writer.len, &wire_len));
    CHECK(wire_len == TREZOR_WIRE_CHUNK_SIZE);
    CHECK(trezor_wire_encode_message(TREZOR_MSG_ETHEREUM_GET_ADDRESS, trezor_payload, trezor_writer.len, wire_chunks,
        sizeof(wire_chunks), &wire_len));
    CHECK(wire_len == TREZOR_WIRE_CHUNK_SIZE);
    CHECK(wire_chunks[0] == TREZOR_WIRE_MARKER);
    CHECK(wire_chunks[1] == TREZOR_WIRE_MAGIC);
    CHECK(wire_chunks[2] == TREZOR_WIRE_MAGIC);
    // Trezor Protocol v1: first packet is '?##' + BE message type + BE payload length + 55 payload bytes.
    CHECK(wire_chunks[3] == 0x00);
    CHECK(wire_chunks[4] == TREZOR_MSG_ETHEREUM_GET_ADDRESS);
    CHECK(wire_chunks[5] == 0x00);
    CHECK(wire_chunks[6] == 0x00);
    CHECK(wire_chunks[7] == 0x00);
    CHECK(wire_chunks[8] == trezor_writer.len);
    CHECK(trezor_wire_decode_message(
        wire_chunks, wire_len, &wire_type, wire_decoded, sizeof(wire_decoded), &wire_payload_len));
    CHECK(wire_type == TREZOR_MSG_ETHEREUM_GET_ADDRESS);
    CHECK(wire_payload_len == trezor_writer.len);
    CHECK(memcmp(wire_decoded, trezor_payload, trezor_writer.len) == 0);
    for (size_t i = TREZOR_WIRE_INIT_HEADER_LEN + trezor_writer.len; i < TREZOR_WIRE_CHUNK_SIZE; ++i) {
        CHECK(wire_chunks[i] == 0);
    }

    uint8_t large_payload[150];
    for (size_t i = 0; i < sizeof(large_payload); ++i) {
        large_payload[i] = (uint8_t)(i ^ 0x5a);
    }
    CHECK(trezor_wire_encode_message(
        TREZOR_MSG_FEATURES, large_payload, sizeof(large_payload), wire_chunks, sizeof(wire_chunks), &wire_len));
    CHECK(wire_len == TREZOR_WIRE_CHUNK_SIZE * 3);
    CHECK(wire_chunks[3] == 0x00);
    CHECK(wire_chunks[4] == TREZOR_MSG_FEATURES);
    CHECK(wire_chunks[5] == 0x00);
    CHECK(wire_chunks[6] == 0x00);
    CHECK(wire_chunks[7] == 0x00);
    CHECK(wire_chunks[8] == sizeof(large_payload));
    CHECK(memcmp(wire_chunks + TREZOR_WIRE_INIT_HEADER_LEN, large_payload, 55) == 0);
    CHECK(wire_chunks[TREZOR_WIRE_CHUNK_SIZE] == TREZOR_WIRE_MARKER);
    CHECK(memcmp(wire_chunks + TREZOR_WIRE_CHUNK_SIZE + TREZOR_WIRE_CONT_HEADER_LEN, large_payload + 55, 63) == 0);
    CHECK(wire_chunks[TREZOR_WIRE_CHUNK_SIZE * 2] == TREZOR_WIRE_MARKER);
    CHECK(memcmp(wire_chunks + (TREZOR_WIRE_CHUNK_SIZE * 2) + TREZOR_WIRE_CONT_HEADER_LEN, large_payload + 118,
              sizeof(large_payload) - 118)
        == 0);
    for (size_t i = (TREZOR_WIRE_CHUNK_SIZE * 2) + TREZOR_WIRE_CONT_HEADER_LEN + sizeof(large_payload) - 118;
         i < wire_len; ++i) {
        CHECK(wire_chunks[i] == 0);
    }
    CHECK(trezor_wire_decode_message(
        wire_chunks, wire_len, &wire_type, wire_decoded, sizeof(wire_decoded), &wire_payload_len));
    CHECK(wire_type == TREZOR_MSG_FEATURES);
    CHECK(wire_payload_len == sizeof(large_payload));
    CHECK(memcmp(wire_decoded, large_payload, sizeof(large_payload)) == 0);

    uint8_t malformed_wire[sizeof(wire_chunks)];
    memcpy(malformed_wire, wire_chunks, wire_len);
    malformed_wire[0] = 0;
    CHECK(!trezor_wire_decode_message(
        malformed_wire, wire_len, &wire_type, wire_decoded, sizeof(wire_decoded), &wire_payload_len));
    memcpy(malformed_wire, wire_chunks, wire_len);
    malformed_wire[1] = 0;
    CHECK(!trezor_wire_decode_message(
        malformed_wire, wire_len, &wire_type, wire_decoded, sizeof(wire_decoded), &wire_payload_len));
    memcpy(malformed_wire, wire_chunks, wire_len);
    malformed_wire[TREZOR_WIRE_CHUNK_SIZE] = 0;
    CHECK(!trezor_wire_decode_message(
        malformed_wire, wire_len, &wire_type, wire_decoded, sizeof(wire_decoded), &wire_payload_len));
    CHECK(!trezor_wire_decode_message(
        wire_chunks, wire_len - 1, &wire_type, wire_decoded, sizeof(wire_decoded), &wire_payload_len));
    CHECK(!trezor_wire_decode_message(wire_chunks, wire_len, &wire_type, wire_decoded, 8, &wire_payload_len));
    memcpy(malformed_wire, wire_chunks, wire_len);
    malformed_wire[5] = 0x00;
    malformed_wire[6] = 0x00;
    malformed_wire[7] = 0x40;
    malformed_wire[8] = 0x01;
    CHECK(!trezor_wire_decode_message(
        malformed_wire, wire_len, &wire_type, wire_decoded, sizeof(wire_decoded), &wire_payload_len));

    const uint8_t trezor_session_id[TREZOR_FEATURES_SESSION_ID_LEN]
        = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
              0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    trezor_features_t features = { .vendor = "trezor.io",
        .fw_vendor = "Jade T-Display-S3",
        .device_id = "jade-test",
        .language = "en-US",
        .model = "Safe 5",
        .internal_model = "T3T1",
        .session_id = trezor_session_id,
        .session_id_len = sizeof(trezor_session_id),
        .major_version = 2,
        .minor_version = 1,
        .patch_version = 0,
        .initialized = true,
        .has_unlocked = true,
        .unlocked = false,
        .pin_protection = true,
        .expose_private_fields = true,
        .passphrase_protection = false,
        .capabilities = { TREZOR_CAPABILITY_BITCOIN, TREZOR_CAPABILITY_BITCOIN_LIKE, TREZOR_CAPABILITY_ETHEREUM },
        .capabilities_len = 3 };
    uint8_t features_payload[256];
    size_t features_payload_len = 0;
    CHECK(trezor_features_encode(&features, features_payload, sizeof(features_payload), &features_payload_len));
    CHECK(features_payload_len > 0);

    bool saw_vendor = false;
    bool saw_major_version = false;
    bool saw_minor_version = false;
    bool saw_patch_version = false;
    bool saw_model = false;
    bool saw_bootloader_mode = false;
    bool saw_initialized = false;
    bool saw_imported = false;
    bool saw_pin_protection = false;
    bool saw_passphrase_protection = false;
    bool saw_unlocked = false;
    bool saw_firmware_present = false;
    bool saw_backup_availability = false;
    bool saw_flags = false;
    bool saw_fw_vendor = false;
    bool saw_unfinished_backup = false;
    bool saw_no_backup = false;
    bool saw_backup_type = false;
    bool saw_session_id = false;
    bool saw_safety_checks = false;
    bool saw_busy = false;
    bool saw_internal_model = false;
    bool saw_language_version_matches = false;
    bool saw_usb_connected = false;
    bool saw_btc = false;
    bool saw_btc_like = false;
    bool saw_eth = false;
    bool saw_tron = false;
    trezor_protobuf_reader_t features_reader;
    trezor_protobuf_reader_init(&features_reader, features_payload, features_payload_len);
    while (features_reader.pos < features_reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type_field = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        CHECK(trezor_protobuf_reader_next(&features_reader, &field_number, &wire_type_field, &value, &value_len));
        if (field_number == 1) {
            saw_vendor = wire_type_field == TREZOR_PROTOBUF_WIRE_LEN && value_len == strlen("trezor.io")
                && memcmp(value, "trezor.io", value_len) == 0;
        } else if (field_number == 2) {
            uint64_t version = 0;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &version));
            saw_major_version = version == 2;
        } else if (field_number == 3) {
            uint64_t version = 1;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &version));
            saw_minor_version = version == 1;
        } else if (field_number == 4) {
            uint64_t version = 1;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &version));
            saw_patch_version = version == 0;
        } else if (field_number == 5) {
            uint64_t bool_value = 1;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &bool_value));
            saw_bootloader_mode = true;
        } else if (field_number == 7) {
            uint64_t bool_value = 0;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &bool_value));
            saw_pin_protection = bool_value == 1;
        } else if (field_number == 8) {
            uint64_t bool_value = 1;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &bool_value));
            saw_passphrase_protection = bool_value == 0;
        } else if (field_number == 12) {
            uint64_t bool_value = 0;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &bool_value));
            saw_initialized = bool_value == 1;
        } else if (field_number == 15) {
            uint64_t bool_value = 1;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &bool_value));
            saw_imported = bool_value == 0;
        } else if (field_number == 16) {
            uint64_t bool_value = 1;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &bool_value));
            saw_unlocked = bool_value == 0;
        } else if (field_number == 18) {
            uint64_t bool_value = 0;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &bool_value));
            saw_firmware_present = bool_value == 1;
        } else if (field_number == 19) {
            uint64_t backup = 1;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &backup));
            saw_backup_availability = backup == 0;
        } else if (field_number == 20) {
            uint64_t flags = 1;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &flags));
            saw_flags = flags == 0;
        } else if (field_number == 21) {
            saw_model = wire_type_field == TREZOR_PROTOBUF_WIRE_LEN && value_len == strlen("Safe 5")
                && memcmp(value, "Safe 5", value_len) == 0;
        } else if (field_number == 25) {
            saw_fw_vendor = wire_type_field == TREZOR_PROTOBUF_WIRE_LEN && value_len == strlen("Jade T-Display-S3")
                && memcmp(value, "Jade T-Display-S3", value_len) == 0;
        } else if (field_number == 30) {
            uint64_t capability = 0;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &capability));
            saw_btc = saw_btc || capability == TREZOR_CAPABILITY_BITCOIN;
            saw_btc_like = saw_btc_like || capability == TREZOR_CAPABILITY_BITCOIN_LIKE;
            saw_eth = saw_eth || capability == TREZOR_CAPABILITY_ETHEREUM;
            saw_tron = saw_tron || capability == TREZOR_CAPABILITY_TRON;
        } else if (field_number == 27) {
            uint64_t bool_value = 1;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &bool_value));
            saw_unfinished_backup = bool_value == 0;
        } else if (field_number == 28) {
            uint64_t bool_value = 1;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &bool_value));
            saw_no_backup = bool_value == 0;
        } else if (field_number == 31) {
            uint64_t backup_type = 1;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &backup_type));
            saw_backup_type = backup_type == 0;
        } else if (field_number == 35) {
            saw_session_id = wire_type_field == TREZOR_PROTOBUF_WIRE_LEN && value_len == sizeof(trezor_session_id)
                && memcmp(value, trezor_session_id, sizeof(trezor_session_id)) == 0;
        } else if (field_number == 37) {
            uint64_t safety_checks = 1;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &safety_checks));
            saw_safety_checks = safety_checks == 0;
        } else if (field_number == 41) {
            uint64_t bool_value = 1;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &bool_value));
            saw_busy = bool_value == 0;
        } else if (field_number == 44) {
            saw_internal_model = wire_type_field == TREZOR_PROTOBUF_WIRE_LEN && value_len == strlen("T3T1")
                && memcmp(value, "T3T1", value_len) == 0;
        } else if (field_number == 50) {
            uint64_t bool_value = 0;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &bool_value));
            saw_language_version_matches = bool_value == 1;
        } else if (field_number == 59) {
            uint64_t bool_value = 0;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &bool_value));
            saw_usb_connected = bool_value == 1;
        }
    }
    CHECK(saw_vendor);
    CHECK(saw_major_version);
    CHECK(saw_minor_version);
    CHECK(saw_patch_version);
    CHECK(saw_model);
    CHECK(!saw_bootloader_mode);
    CHECK(saw_pin_protection);
    CHECK(saw_passphrase_protection);
    CHECK(saw_initialized);
    CHECK(saw_imported);
    CHECK(saw_unlocked);
    CHECK(saw_firmware_present);
    CHECK(saw_backup_availability);
    CHECK(saw_flags);
    CHECK(saw_fw_vendor);
    CHECK(saw_unfinished_backup);
    CHECK(saw_no_backup);
    CHECK(saw_backup_type);
    CHECK(saw_session_id);
    CHECK(saw_safety_checks);
    CHECK(saw_busy);
    CHECK(saw_internal_model);
    CHECK(saw_language_version_matches);
    CHECK(saw_usb_connected);
    CHECK(saw_btc);
    CHECK(saw_btc_like);
    CHECK(saw_eth);
    CHECK(!saw_tron);

    trezor_features_t custom_identity_features = features;
    custom_identity_features.model = "Jade";
    custom_identity_features.internal_model = "UNKNOWN";
    memset(features_payload, 0, sizeof(features_payload));
    features_payload_len = 0;
    CHECK(trezor_features_encode(
        &custom_identity_features, features_payload, sizeof(features_payload), &features_payload_len));
    CHECK(features_payload_len > 0);
    saw_model = false;
    saw_internal_model = false;
    saw_bootloader_mode = false;
    trezor_protobuf_reader_init(&features_reader, features_payload, features_payload_len);
    while (features_reader.pos < features_reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type_field = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        CHECK(trezor_protobuf_reader_next(&features_reader, &field_number, &wire_type_field, &value, &value_len));
        if (field_number == 5) {
            saw_bootloader_mode = true;
        } else if (field_number == 21) {
            saw_model = wire_type_field == TREZOR_PROTOBUF_WIRE_LEN && value_len == strlen("Jade")
                && memcmp(value, "Jade", value_len) == 0;
        } else if (field_number == 44) {
            saw_internal_model = wire_type_field == TREZOR_PROTOBUF_WIRE_LEN && value_len == strlen("UNKNOWN")
                && memcmp(value, "UNKNOWN", value_len) == 0;
        }
    }
    CHECK(!saw_bootloader_mode);
    CHECK(saw_model);
    CHECK(saw_internal_model);

    trezor_features_t locked_custom_features = features;
    locked_custom_features.has_unlocked = false;
    locked_custom_features.unlocked = false;
    locked_custom_features.expose_private_fields = false;
    memset(features_payload, 0, sizeof(features_payload));
    features_payload_len = 0;
    CHECK(trezor_features_encode(
        &locked_custom_features, features_payload, sizeof(features_payload), &features_payload_len));
    CHECK(features_payload_len > 0);
    saw_initialized = false;
    saw_pin_protection = false;
    saw_passphrase_protection = false;
    saw_unlocked = false;
    saw_backup_availability = false;
    saw_flags = false;
    saw_unfinished_backup = false;
    saw_no_backup = false;
    saw_backup_type = false;
    saw_safety_checks = false;
    trezor_protobuf_reader_init(&features_reader, features_payload, features_payload_len);
    while (features_reader.pos < features_reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type_field = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        CHECK(trezor_protobuf_reader_next(&features_reader, &field_number, &wire_type_field, &value, &value_len));
        if (field_number == 7) {
            uint64_t bool_value = 0;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &bool_value));
            saw_pin_protection = bool_value == 1;
        } else if (field_number == 8) {
            saw_passphrase_protection = true;
        } else if (field_number == 12) {
            uint64_t bool_value = 0;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &bool_value));
            saw_initialized = bool_value == 1;
        } else if (field_number == 16) {
            saw_unlocked = true;
        } else if (field_number == 19) {
            saw_backup_availability = true;
        } else if (field_number == 20) {
            saw_flags = true;
        } else if (field_number == 27) {
            saw_unfinished_backup = true;
        } else if (field_number == 28) {
            saw_no_backup = true;
        } else if (field_number == 31) {
            saw_backup_type = true;
        } else if (field_number == 37) {
            saw_safety_checks = true;
        }
    }
    CHECK(saw_initialized);
    CHECK(saw_pin_protection);
    CHECK(!saw_passphrase_protection);
    CHECK(!saw_unlocked);
    CHECK(!saw_backup_availability);
    CHECK(!saw_flags);
    CHECK(!saw_unfinished_backup);
    CHECK(!saw_no_backup);
    CHECK(!saw_backup_type);
    CHECK(!saw_safety_checks);

    trezor_session_state_t trezor_session_state;
    wally_bzero(&trezor_session_state, sizeof(trezor_session_state));
    trezor_session_t trezor_session = {
        .features = features,
        .state = &trezor_session_state,
        .initialize_session = trezor_test_initialize_session,
        .initialize_session_ctx = NULL,
        .needs_local_unlock = trezor_test_needs_local_unlock,
        .needs_local_unlock_ctx = NULL,
        .perform_local_unlock = trezor_test_perform_local_unlock,
        .perform_local_unlock_ctx = NULL,
        .get_bitcoin_address = trezor_test_get_bitcoin_address,
        .get_bitcoin_address_ctx = NULL,
        .get_eth_address = trezor_test_get_eth_address,
        .get_eth_address_ctx = NULL,
        .get_public_key = trezor_test_get_public_key,
        .get_public_key_ctx = NULL,
        .sign_eth_tx = trezor_test_sign_eth_tx,
        .sign_eth_tx_ctx = NULL,
        .sign_eth_safe_tx = trezor_test_sign_eth_safe_tx,
        .sign_eth_safe_tx_ctx = NULL,
        .confirm_btc_tx = trezor_test_confirm_btc_tx,
        .confirm_btc_tx_ctx = NULL,
        .sign_btc_digest = trezor_test_sign_btc_digest,
        .sign_btc_digest_ctx = NULL,
        .get_entropy = trezor_test_get_entropy,
        .get_entropy_ctx = NULL,
    };
    uint8_t session_request_chunks[2304];
    uint8_t session_response_chunks[512];
    uint8_t session_response_payload[TREZOR_SESSION_MAX_RESPONSE_PAYLOAD_LEN];
    size_t session_request_len = 0;
    size_t session_response_len = 0;
    size_t session_response_payload_len = 0;
    uint16_t session_response_type = 0;
    trezor_session_response_event_t session_response_event = TREZOR_SESSION_RESPONSE_EVENT_NONE;
    trezor_trace_snapshot_t trace_snapshot;
    char trace_text[TREZOR_TRACE_FORMATTED_LEN];

    g_trezor_last_initialize_session_id_len = 99;
    CHECK(trezor_wire_encode_message(
        TREZOR_MSG_INITIALIZE, NULL, 0, session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FEATURES);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 30, TREZOR_CAPABILITY_BITCOIN));
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 30, TREZOR_CAPABILITY_BITCOIN_LIKE));
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 30, TREZOR_CAPABILITY_ETHEREUM));
    CHECK(
        !trezor_payload_has_varint(session_response_payload, session_response_payload_len, 30, TREZOR_CAPABILITY_TRON));
    CHECK(g_trezor_last_initialize_session_id_len == 0);
    CHECK(trezor_trace_snapshot(&trace_snapshot));
    CHECK(trace_snapshot.latest.request_type == TREZOR_MSG_INITIALIZE);
    CHECK(trace_snapshot.latest.response_type == TREZOR_MSG_FEATURES);
    CHECK(trace_snapshot.latest.failure_code == 0);
    CHECK(trace_snapshot.latest.wire_ok);
    CHECK(trace_snapshot.latest.handler_ok);
    CHECK(trezor_trace_format_latest(trace_text, sizeof(trace_text)));
    CHECK(strstr(trace_text, "Initialize") != NULL);
    CHECK(strstr(trace_text, "init=1") != NULL);
    CHECK(strstr(trace_text, "unlock=0") != NULL);
    CHECK(strstr(trace_text, "sid_len=32") != NULL);

    uint8_t initialize_payload[96];
    trezor_protobuf_writer_t initialize_writer;
    trezor_protobuf_writer_init(&initialize_writer, initialize_payload, sizeof(initialize_payload));
    CHECK(trezor_protobuf_write_bytes_field(&initialize_writer, 1, trezor_session_id, sizeof(trezor_session_id)));
    CHECK(trezor_protobuf_write_bool_field(&initialize_writer, 3, true));
    CHECK(trezor_wire_encode_message(TREZOR_MSG_INITIALIZE, initialize_payload, initialize_writer.len,
        session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FEATURES);
    CHECK(g_trezor_last_initialize_session_id_len == sizeof(trezor_session_id));
    CHECK(memcmp(g_trezor_last_initialize_session_id, trezor_session_id, sizeof(trezor_session_id)) == 0);

    trezor_protobuf_writer_init(&initialize_writer, initialize_payload, sizeof(initialize_payload));
    CHECK(trezor_protobuf_write_bytes_field(&initialize_writer, 1, (const uint8_t*)"session", 7));
    CHECK(trezor_wire_encode_message(TREZOR_MSG_INITIALIZE, initialize_payload, initialize_writer.len,
        session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_DATA_ERROR));

    trezor_protobuf_writer_init(&initialize_writer, initialize_payload, sizeof(initialize_payload));
    CHECK(trezor_protobuf_write_varint_field(&initialize_writer, 3, 2));
    CHECK(trezor_wire_encode_message(TREZOR_MSG_INITIALIZE, initialize_payload, initialize_writer.len,
        session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_DATA_ERROR));

    CHECK(trezor_wire_encode_message(
        TREZOR_MSG_CANCEL, NULL, 0, session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_ACTION_CANCELLED));

    g_trezor_needs_local_unlock = true;
    g_trezor_local_unlock_ok = true;
    g_trezor_local_unlock_calls = 0;
    CHECK(trezor_wire_encode_message(TREZOR_MSG_ETHEREUM_GET_PUBLIC_KEY, trezor_eth_public_key_payload,
        trezor_eth_public_key_payload_len, session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_BUTTON_REQUEST);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_BUTTON_REQUEST_PIN_ENTRY));
    CHECK(!trezor_payload_contains_bytes(session_response_payload, session_response_payload_len,
        (const uint8_t*)"xpub-test-only", strlen("xpub-test-only")));
    CHECK(g_trezor_local_unlock_calls == 0);
    CHECK(trezor_session_state.has_pending_local_unlock);
    CHECK(trezor_session_state.pending_request_type == TREZOR_MSG_ETHEREUM_GET_PUBLIC_KEY);
    CHECK(trezor_session_state.pending_request_payload_len == trezor_eth_public_key_payload_len);
    CHECK(trezor_trace_format_latest(trace_text, sizeof(trace_text)));
    CHECK(strstr(trace_text, "EthereumGetPublicKey") != NULL);
    CHECK(strstr(trace_text, "ButtonRequest") != NULL);

    CHECK(trezor_wire_encode_message(
        TREZOR_MSG_BUTTON_ACK, NULL, 0, session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_ETHEREUM_PUBLIC_KEY);
    CHECK(g_trezor_local_unlock_calls == 1);
    CHECK(!g_trezor_needs_local_unlock);
    CHECK(!trezor_session_state.has_pending_local_unlock);
    CHECK(!trezor_public_key_payload_has_private_key_field(session_response_payload, session_response_payload_len));

    g_trezor_needs_local_unlock = true;
    session_response_type = 0;
    session_response_payload_len = 0;
    CHECK(!trezor_session_handle_payload(&trezor_session, TREZOR_MSG_ETHEREUM_GET_PUBLIC_KEY,
        trezor_eth_public_key_payload, trezor_eth_public_key_payload_len, &session_response_type,
        session_response_payload, 1, &session_response_payload_len));
    CHECK(!trezor_session_state.has_pending_local_unlock);
    g_trezor_needs_local_unlock = false;

    g_trezor_needs_local_unlock = true;
    CHECK(trezor_wire_encode_message(TREZOR_MSG_GET_ADDRESS, trezor_bitcoin_payload, trezor_bitcoin_payload_len,
        session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_BUTTON_REQUEST);
    CHECK(trezor_session_state.has_pending_local_unlock);

    CHECK(trezor_wire_encode_message(
        TREZOR_MSG_CANCEL, NULL, 0, session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(!trezor_session_state.has_pending_local_unlock);
    g_trezor_needs_local_unlock = false;

    CHECK(trezor_wire_encode_message(TREZOR_MSG_GET_ADDRESS, trezor_bitcoin_payload, trezor_bitcoin_payload_len,
        session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_ADDRESS);
    CHECK(session_response_payload_len == trezor_bitcoin_address_payload_len);
    CHECK(memcmp(session_response_payload, trezor_bitcoin_address_payload, trezor_bitcoin_address_payload_len) == 0);
    CHECK(g_last_trezor_bitcoin_address_request.address_n_len == ARRAY_LEN(btc_state_path));
    CHECK(memcmp(g_last_trezor_bitcoin_address_request.address_n, btc_state_path, sizeof(btc_state_path)) == 0);
    CHECK(g_last_trezor_bitcoin_address_request.has_coin_name
        && strcmp(g_last_trezor_bitcoin_address_request.coin_name, "Testnet") == 0);
    CHECK(g_last_trezor_bitcoin_address_request.has_script_type
        && g_last_trezor_bitcoin_address_request.script_type == BITCOIN_P2PKH_SPENDADDRESS);
    CHECK(trezor_trace_format_latest(trace_text, sizeof(trace_text)));
    CHECK(strstr(trace_text, "GetAddress") != NULL);
    CHECK(strstr(trace_text, "path=m/44'/1'/0'/0/0") != NULL);
    CHECK(strstr(trace_text, "coin=Testnet") != NULL);
    CHECK(strstr(trace_text, "address omitted") != NULL);
    CHECK(strstr(trace_text, "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r") == NULL);

    trezor_protobuf_writer_init(&trezor_bitcoin_writer, trezor_bitcoin_payload, sizeof(trezor_bitcoin_payload));
    for (size_t i = 0; i < ARRAY_LEN(btc_signing_path); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_bitcoin_writer, 1, btc_signing_path[i]));
    }
    CHECK(trezor_protobuf_write_string_field(&trezor_bitcoin_writer, 2, "Testnet"));
    CHECK(trezor_protobuf_write_varint_field(&trezor_bitcoin_writer, 5, BITCOIN_P2WPKH_SPENDWITNESS));
    CHECK(trezor_wire_encode_message(TREZOR_MSG_GET_ADDRESS, trezor_bitcoin_payload, trezor_bitcoin_writer.len,
        session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_ADDRESS);
    uint8_t trezor_btc_p2wpkh_address_payload[80];
    size_t trezor_btc_p2wpkh_address_payload_len = 0;
    CHECK(trezor_bitcoin_address_encode("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        trezor_btc_p2wpkh_address_payload, sizeof(trezor_btc_p2wpkh_address_payload),
        &trezor_btc_p2wpkh_address_payload_len));
    CHECK(session_response_payload_len == trezor_btc_p2wpkh_address_payload_len);
    CHECK(memcmp(session_response_payload, trezor_btc_p2wpkh_address_payload,
              trezor_btc_p2wpkh_address_payload_len)
        == 0);
    CHECK(trezor_trace_format_latest(trace_text, sizeof(trace_text)));
    CHECK(strstr(trace_text, "GetAddress") != NULL);
    CHECK(strstr(trace_text, "path=m/84'/1'/0'/0/0") != NULL);
    CHECK(strstr(trace_text, "address omitted") != NULL);
    CHECK(strstr(trace_text, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx") == NULL);

    trezor_protobuf_writer_init(&trezor_bitcoin_writer, trezor_bitcoin_payload, sizeof(trezor_bitcoin_payload));
    for (size_t i = 0; i < ARRAY_LEN(btc_mainnet_signing_path); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_bitcoin_writer, 1, btc_mainnet_signing_path[i]));
    }
    CHECK(trezor_protobuf_write_string_field(&trezor_bitcoin_writer, 2, "Bitcoin"));
    CHECK(trezor_protobuf_write_varint_field(&trezor_bitcoin_writer, 5, BITCOIN_P2WPKH_SPENDWITNESS));
    CHECK(trezor_wire_encode_message(TREZOR_MSG_GET_ADDRESS, trezor_bitcoin_payload, trezor_bitcoin_writer.len,
        session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_ADDRESS);
    CHECK(trezor_bitcoin_address_encode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        trezor_btc_p2wpkh_address_payload, sizeof(trezor_btc_p2wpkh_address_payload),
        &trezor_btc_p2wpkh_address_payload_len));
    CHECK(session_response_payload_len == trezor_btc_p2wpkh_address_payload_len);
    CHECK(memcmp(session_response_payload, trezor_btc_p2wpkh_address_payload,
              trezor_btc_p2wpkh_address_payload_len)
        == 0);

    uint8_t expected_btc_tx_request_payload[32];
    size_t expected_btc_tx_request_payload_len = 0;
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_SIGN_TX, trezor_valid_sign_tx_payload,
        trezor_valid_sign_tx_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_state.has_pending_btc_signing);
    CHECK(trezor_session_state.pending_btc_signing.phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_INPUT);
    CHECK(trezor_bitcoin_tx_request_encode(TREZOR_BITCOIN_REQUEST_TXINPUT, true, 0,
        expected_btc_tx_request_payload, sizeof(expected_btc_tx_request_payload), &expected_btc_tx_request_payload_len));
    CHECK(session_response_payload_len == expected_btc_tx_request_payload_len);
    CHECK(memcmp(session_response_payload, expected_btc_tx_request_payload, expected_btc_tx_request_payload_len) == 0);

    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_GET_ENTROPY, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));
    CHECK(trezor_session_state.has_pending_btc_signing);
    CHECK(trezor_session_state.pending_btc_signing.phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_INPUT);

    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_ETHEREUM_TX_ACK, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));
    CHECK(trezor_session_state.has_pending_btc_signing);
    CHECK(trezor_session_state.pending_btc_signing.phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_INPUT);
    CHECK(g_trezor_btc_sign_calls == 0);

    CHECK(trezor_session_handle_payload(
        &trezor_session, TREZOR_MSG_ETHEREUM_GNOSIS_SAFE_TX_ACK, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));
    CHECK(trezor_session_state.has_pending_btc_signing);
    CHECK(trezor_session_state.pending_btc_signing.phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_INPUT);
    CHECK(g_trezor_btc_sign_calls == 0);

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, 16));
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_GET_ENTROPY, trezor_payload, trezor_writer.len,
        &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));
    CHECK(trezor_session_state.has_pending_btc_signing);
    CHECK(trezor_session_state.pending_btc_signing.phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_INPUT);
    CHECK(g_trezor_entropy_calls == 0);
    CHECK(g_trezor_btc_sign_calls == 0);

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, 0));
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_APPLY_FLAGS, trezor_payload, trezor_writer.len,
        &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));
    CHECK(trezor_session_state.has_pending_btc_signing);
    CHECK(trezor_session_state.pending_btc_signing.phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_INPUT);
    CHECK(g_trezor_btc_sign_calls == 0);

    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_meta_ack_payload,
        trezor_btc_meta_ack_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_state.pending_btc_signing.phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_INPUT);
    CHECK(trezor_bitcoin_tx_request_encode(TREZOR_BITCOIN_REQUEST_TXINPUT, true, 0,
        expected_btc_tx_request_payload, sizeof(expected_btc_tx_request_payload), &expected_btc_tx_request_payload_len));
    CHECK(session_response_payload_len == expected_btc_tx_request_payload_len);
    CHECK(memcmp(session_response_payload, expected_btc_tx_request_payload, expected_btc_tx_request_payload_len) == 0);

    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_input_ack_payload,
        trezor_btc_input_ack_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_state.pending_btc_signing.phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_OUTPUT);
    CHECK(trezor_bitcoin_tx_request_encode(TREZOR_BITCOIN_REQUEST_TXOUTPUT, true, 0,
        expected_btc_tx_request_payload, sizeof(expected_btc_tx_request_payload), &expected_btc_tx_request_payload_len));
    CHECK(session_response_payload_len == expected_btc_tx_request_payload_len);
    CHECK(memcmp(session_response_payload, expected_btc_tx_request_payload, expected_btc_tx_request_payload_len) == 0);

    g_ui_calls = 0;
    g_trezor_btc_confirm_calls = 0;
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_output_ack_payload,
        trezor_btc_output_ack_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(!trezor_session_state.has_pending_btc_signing);
    CHECK(trezor_session_state.pending_btc_signing.phase == TREZOR_BITCOIN_SIGNING_PHASE_NONE);
    CHECK(g_trezor_btc_confirm_calls == 1);
    CHECK(g_ui_calls == 1);
    CHECK(g_last_trezor_btc_confirm_request.path_len == ARRAY_LEN(btc_signing_path));
    CHECK(memcmp(g_last_trezor_btc_confirm_request.path, btc_signing_path, sizeof(btc_signing_path)) == 0);
    CHECK(strcmp(g_last_trezor_btc_confirm_request.to, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx") == 0);
    CHECK(g_last_trezor_btc_confirm_request.amount == 90000);
    CHECK(g_last_trezor_btc_confirm_request.fee == 10000);
    CHECK(g_last_trezor_btc_confirm_request.fee_rate_sats_per_vbyte == 89);
    CHECK(g_last_ui_summary.chain == CHAIN_CONFIRM_CHAIN_BITCOIN);
    CHECK(g_last_ui_summary.operation == CHAIN_CONFIRM_OPERATION_NATIVE_TRANSFER);
    CHECK(chain_confirm_summary_has_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_PATH));
    const chain_confirm_field_t* const btc_to = find_confirm_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_TO);
    CHECK(btc_to && btc_to->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(btc_to->value.text, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx") == 0);
    const chain_confirm_field_t* const btc_amount = find_confirm_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_AMOUNT);
    CHECK(btc_amount && btc_amount->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(btc_amount->value.text, "0.0009 BTC") == 0);
    const chain_confirm_field_t* const btc_change = find_confirm_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_CHANGE);
    CHECK(btc_change && btc_change->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(btc_change->value.text, "0 BTC") == 0);
    const chain_confirm_field_t* const btc_fee = find_confirm_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_FEE);
    CHECK(btc_fee && btc_fee->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(btc_fee->value.text, "0.0001 BTC") == 0);
    const chain_confirm_field_t* const btc_fee_rate
        = find_confirm_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_FEE_RATE);
    CHECK(btc_fee_rate && btc_fee_rate->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(btc_fee_rate->value.text, "89 sat/vB") == 0);
    CHECK(test_confirm_summary_fits_tdisplay_s3(&g_last_ui_summary));
    CHECK(trezor_btc_tx_request_has_signed_serialized_payload(session_response_payload, session_response_payload_len));

    uint8_t trezor_btc_change_output_payload[160];
    uint8_t trezor_btc_self_output_payload[160];
    uint8_t trezor_btc_self_transfer_output_payload[160];
    uint8_t trezor_btc_rbf_input_payload[160];
    uint8_t trezor_btc_rbf_input_ack_payload[288];
    uint8_t trezor_btc_change_output_ack_payload[288];
    uint8_t trezor_btc_self_output_ack_payload[288];
    uint8_t trezor_btc_self_transfer_output_ack_payload[288];
    uint8_t trezor_btc_one_input_two_output_sign_tx_payload[128];
    uint8_t trezor_btc_one_input_two_output_meta_ack_payload[288];
    size_t trezor_btc_rbf_input_ack_payload_len = 0;
    size_t trezor_btc_change_output_ack_payload_len = 0;
    size_t trezor_btc_self_output_ack_payload_len = 0;
    size_t trezor_btc_self_transfer_output_ack_payload_len = 0;
    size_t trezor_btc_one_input_two_output_sign_tx_payload_len = 0;
    size_t trezor_btc_one_input_two_output_meta_ack_payload_len = 0;
    const uint32_t trezor_btc_sparrow_lock_time = 5126746U;
    const uint32_t trezor_btc_sparrow_sequence = 0xfffffffdU;

    trezor_protobuf_writer_init(
        &trezor_sign_tx_writer, trezor_btc_one_input_two_output_sign_tx_payload, sizeof(trezor_btc_one_input_two_output_sign_tx_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 1, 2));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 2, 1));
    CHECK(trezor_protobuf_write_string_field(&trezor_sign_tx_writer, 3, "Testnet"));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 4, 2));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 5, trezor_btc_sparrow_lock_time));
    CHECK(trezor_protobuf_write_bool_field(&trezor_sign_tx_writer, 13, true));
    trezor_btc_one_input_two_output_sign_tx_payload_len = trezor_sign_tx_writer.len;

    trezor_protobuf_writer_init(&trezor_btc_input_writer, trezor_btc_rbf_input_payload, sizeof(trezor_btc_rbf_input_payload));
    for (size_t i = 0; i < ARRAY_LEN(btc_signing_path); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_btc_input_writer, 1, btc_signing_path[i]));
    }
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_input_writer, 2, trezor_btc_prev_hash, sizeof(trezor_btc_prev_hash)));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_input_writer, 3, 0));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_input_writer, 5, trezor_btc_sparrow_sequence));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_input_writer, 6, BITCOIN_P2WPKH_SPENDWITNESS));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_input_writer, 8, 100000));
    trezor_protobuf_writer_init(&trezor_btc_tx_writer, trezor_btc_tx_payload, sizeof(trezor_btc_tx_payload));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_tx_writer, 2, trezor_btc_rbf_input_payload, trezor_btc_input_writer.len));
    trezor_protobuf_writer_init(&trezor_btc_ack_writer, trezor_btc_ack_payload, sizeof(trezor_btc_ack_payload));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_btc_ack_writer, 1, trezor_btc_tx_payload, trezor_btc_tx_writer.len));
    trezor_btc_rbf_input_ack_payload_len = trezor_btc_ack_writer.len;
    memcpy(trezor_btc_rbf_input_ack_payload, trezor_btc_ack_payload, trezor_btc_rbf_input_ack_payload_len);

    trezor_protobuf_writer_init(&trezor_btc_output_writer, trezor_btc_change_output_payload, sizeof(trezor_btc_change_output_payload));
    for (size_t i = 0; i < ARRAY_LEN(btc_change_path); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_btc_output_writer, 2, btc_change_path[i]));
    }
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_output_writer, 3, 5000));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_output_writer, 4, BITCOIN_PAYTOWITNESS));
    trezor_protobuf_writer_init(&trezor_btc_tx_writer, trezor_btc_tx_payload, sizeof(trezor_btc_tx_payload));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_tx_writer, 5, trezor_btc_change_output_payload, trezor_btc_output_writer.len));
    trezor_protobuf_writer_init(&trezor_btc_ack_writer, trezor_btc_ack_payload, sizeof(trezor_btc_ack_payload));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_btc_ack_writer, 1, trezor_btc_tx_payload, trezor_btc_tx_writer.len));
    trezor_btc_change_output_ack_payload_len = trezor_btc_ack_writer.len;
    memcpy(trezor_btc_change_output_ack_payload, trezor_btc_ack_payload, trezor_btc_change_output_ack_payload_len);

    trezor_protobuf_writer_init(&trezor_btc_output_writer, trezor_btc_self_output_payload, sizeof(trezor_btc_self_output_payload));
    for (size_t i = 0; i < ARRAY_LEN(btc_self_path); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_btc_output_writer, 2, btc_self_path[i]));
    }
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_output_writer, 3, 5000));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_output_writer, 4, BITCOIN_PAYTOWITNESS));
    trezor_protobuf_writer_init(&trezor_btc_tx_writer, trezor_btc_tx_payload, sizeof(trezor_btc_tx_payload));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_tx_writer, 5, trezor_btc_self_output_payload, trezor_btc_output_writer.len));
    trezor_protobuf_writer_init(&trezor_btc_ack_writer, trezor_btc_ack_payload, sizeof(trezor_btc_ack_payload));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_btc_ack_writer, 1, trezor_btc_tx_payload, trezor_btc_tx_writer.len));
    trezor_btc_self_output_ack_payload_len = trezor_btc_ack_writer.len;
    memcpy(trezor_btc_self_output_ack_payload, trezor_btc_ack_payload, trezor_btc_self_output_ack_payload_len);

    trezor_protobuf_writer_init(
        &trezor_btc_output_writer, trezor_btc_self_transfer_output_payload, sizeof(trezor_btc_self_transfer_output_payload));
    for (size_t i = 0; i < ARRAY_LEN(btc_self_path_2); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_btc_output_writer, 2, btc_self_path_2[i]));
    }
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_output_writer, 3, 90000));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_output_writer, 4, BITCOIN_PAYTOWITNESS));
    trezor_protobuf_writer_init(&trezor_btc_tx_writer, trezor_btc_tx_payload, sizeof(trezor_btc_tx_payload));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_tx_writer, 5, trezor_btc_self_transfer_output_payload, trezor_btc_output_writer.len));
    trezor_protobuf_writer_init(&trezor_btc_ack_writer, trezor_btc_ack_payload, sizeof(trezor_btc_ack_payload));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_btc_ack_writer, 1, trezor_btc_tx_payload, trezor_btc_tx_writer.len));
    trezor_btc_self_transfer_output_ack_payload_len = trezor_btc_ack_writer.len;
    memcpy(trezor_btc_self_transfer_output_ack_payload, trezor_btc_ack_payload,
        trezor_btc_self_transfer_output_ack_payload_len);

    trezor_protobuf_writer_init(&trezor_btc_tx_writer, trezor_btc_tx_payload, sizeof(trezor_btc_tx_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_tx_writer, 1, 2));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_tx_writer, 4, trezor_btc_sparrow_lock_time));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_tx_writer, 6, 1));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_tx_writer, 7, 2));
    trezor_protobuf_writer_init(&trezor_btc_ack_writer, trezor_btc_ack_payload, sizeof(trezor_btc_ack_payload));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_btc_ack_writer, 1, trezor_btc_tx_payload, trezor_btc_tx_writer.len));
    trezor_btc_one_input_two_output_meta_ack_payload_len = trezor_btc_ack_writer.len;
    memcpy(trezor_btc_one_input_two_output_meta_ack_payload, trezor_btc_ack_payload,
        trezor_btc_one_input_two_output_meta_ack_payload_len);

    g_trezor_btc_sign_calls = 0;
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_SIGN_TX,
        trezor_btc_one_input_two_output_sign_tx_payload, trezor_btc_one_input_two_output_sign_tx_payload_len,
        &session_response_type, session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK,
        trezor_btc_one_input_two_output_meta_ack_payload, trezor_btc_one_input_two_output_meta_ack_payload_len,
        &session_response_type, session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_rbf_input_ack_payload,
        trezor_btc_rbf_input_ack_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_output_ack_payload,
        trezor_btc_output_ack_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    g_trezor_btc_confirm_calls = 0;
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_change_output_ack_payload,
        trezor_btc_change_output_ack_payload_len, &session_response_type, session_response_payload,
        sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(!trezor_session_state.has_pending_btc_signing);
    CHECK(!trezor_session_state.has_pending_btc_signed_tx);
    CHECK(g_trezor_btc_confirm_calls == 1);
    CHECK(g_trezor_btc_sign_calls == 1);
    CHECK(g_last_trezor_btc_confirm_request.amount == 90000);
    CHECK(g_last_trezor_btc_confirm_request.change == 5000);
    CHECK(g_last_trezor_btc_confirm_request.fee == 5000);
    CHECK(g_last_trezor_btc_confirm_request.fee_rate_sats_per_vbyte == 35);
    CHECK(g_last_trezor_btc_confirm_request.lock_time == trezor_btc_sparrow_lock_time);
    CHECK(g_last_trezor_btc_confirm_request.sequence == trezor_btc_sparrow_sequence);
    CHECK(g_last_ui_summary.chain == CHAIN_CONFIRM_CHAIN_BITCOIN);
    CHECK(g_last_ui_summary.operation == CHAIN_CONFIRM_OPERATION_NATIVE_TRANSFER);
    CHECK(chain_confirm_summary_has_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_PATH));
    const chain_confirm_field_t* const btc_change_case_to
        = find_confirm_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_TO);
    CHECK(btc_change_case_to && btc_change_case_to->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(btc_change_case_to->value.text, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx") == 0);
    const chain_confirm_field_t* const btc_change_case_amount
        = find_confirm_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_AMOUNT);
    CHECK(btc_change_case_amount && btc_change_case_amount->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(btc_change_case_amount->value.text, "0.0009 BTC") == 0);
    const chain_confirm_field_t* const btc_change_case_change
        = find_confirm_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_CHANGE);
    CHECK(btc_change_case_change && btc_change_case_change->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(btc_change_case_change->value.text, "0.00005 BTC") == 0);
    const chain_confirm_field_t* const btc_change_case_fee
        = find_confirm_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_FEE);
    CHECK(btc_change_case_fee && btc_change_case_fee->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(btc_change_case_fee->value.text, "0.00005 BTC") == 0);
    const chain_confirm_field_t* const btc_change_case_fee_rate
        = find_confirm_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_FEE_RATE);
    CHECK(btc_change_case_fee_rate && btc_change_case_fee_rate->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(btc_change_case_fee_rate->value.text, "35 sat/vB") == 0);
    const chain_confirm_field_t* const btc_change_case_tx_flags
        = find_confirm_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_TX_FLAGS);
    CHECK(btc_change_case_tx_flags && btc_change_case_tx_flags->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(btc_change_case_tx_flags->value.text, "RBF, block 5126746") == 0);
    CHECK(test_confirm_summary_fits_tdisplay_s3(&g_last_ui_summary));
    CHECK(trezor_btc_tx_request_has_signed_payload(session_response_payload, session_response_payload_len,
        TREZOR_BITCOIN_REQUEST_TXFINISHED, 0, true, 1, 2));

    g_trezor_btc_sign_calls = 0;
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_SIGN_TX,
        trezor_btc_one_input_two_output_sign_tx_payload, trezor_btc_one_input_two_output_sign_tx_payload_len,
        &session_response_type, session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK,
        trezor_btc_one_input_two_output_meta_ack_payload, trezor_btc_one_input_two_output_meta_ack_payload_len,
        &session_response_type, session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_rbf_input_ack_payload,
        trezor_btc_rbf_input_ack_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_output_ack_payload,
        trezor_btc_output_ack_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    g_trezor_btc_confirm_calls = 0;
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_self_output_ack_payload,
        trezor_btc_self_output_ack_payload_len, &session_response_type, session_response_payload,
        sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(!trezor_session_state.has_pending_btc_signing);
    CHECK(!trezor_session_state.has_pending_btc_signed_tx);
    CHECK(g_trezor_btc_confirm_calls == 1);
    CHECK(g_trezor_btc_sign_calls == 1);
    CHECK(g_last_trezor_btc_confirm_request.amount == 90000);
    CHECK(g_last_trezor_btc_confirm_request.self == 5000);
    CHECK(g_last_trezor_btc_confirm_request.change == 0);
    CHECK(g_last_trezor_btc_confirm_request.fee == 5000);
    const chain_confirm_field_t* const btc_self_case_self
        = find_confirm_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_SELF);
    CHECK(btc_self_case_self && btc_self_case_self->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(btc_self_case_self->value.text, "0.00005 BTC") == 0);
    const chain_confirm_field_t* const btc_self_case_change
        = find_confirm_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_CHANGE);
    CHECK(btc_self_case_change && btc_self_case_change->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(btc_self_case_change->value.text, "0 BTC") == 0);
    CHECK(test_confirm_summary_fits_tdisplay_s3(&g_last_ui_summary));
    CHECK(trezor_btc_tx_request_has_signed_payload(session_response_payload, session_response_payload_len,
        TREZOR_BITCOIN_REQUEST_TXFINISHED, 0, true, 1, 2));

    g_trezor_btc_sign_calls = 0;
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_SIGN_TX,
        trezor_btc_one_input_two_output_sign_tx_payload, trezor_btc_one_input_two_output_sign_tx_payload_len,
        &session_response_type, session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK,
        trezor_btc_one_input_two_output_meta_ack_payload, trezor_btc_one_input_two_output_meta_ack_payload_len,
        &session_response_type, session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_rbf_input_ack_payload,
        trezor_btc_rbf_input_ack_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_self_transfer_output_ack_payload,
        trezor_btc_self_transfer_output_ack_payload_len, &session_response_type, session_response_payload,
        sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    g_trezor_btc_confirm_calls = 0;
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_change_output_ack_payload,
        trezor_btc_change_output_ack_payload_len, &session_response_type, session_response_payload,
        sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(!trezor_session_state.has_pending_btc_signing);
    CHECK(!trezor_session_state.has_pending_btc_signed_tx);
    CHECK(g_trezor_btc_confirm_calls == 1);
    CHECK(g_trezor_btc_sign_calls == 1);
    CHECK(strcmp(g_last_trezor_btc_confirm_request.to, "Own wallet") == 0);
    CHECK(g_last_trezor_btc_confirm_request.amount == 95000);
    CHECK(g_last_trezor_btc_confirm_request.self == 90000);
    CHECK(g_last_trezor_btc_confirm_request.change == 5000);
    CHECK(g_last_trezor_btc_confirm_request.fee == 5000);
    const chain_confirm_field_t* const btc_self_only_to
        = find_confirm_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_TO);
    CHECK(btc_self_only_to && btc_self_only_to->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(btc_self_only_to->value.text, "Own wallet") == 0);
    const chain_confirm_field_t* const btc_self_only_amount
        = find_confirm_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_AMOUNT);
    CHECK(btc_self_only_amount && btc_self_only_amount->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(btc_self_only_amount->value.text, "0.00095 BTC") == 0);
    const chain_confirm_field_t* const btc_self_only_self
        = find_confirm_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_SELF);
    CHECK(btc_self_only_self && btc_self_only_self->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(btc_self_only_self->value.text, "0.0009 BTC") == 0);
    const chain_confirm_field_t* const btc_self_only_change
        = find_confirm_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_CHANGE);
    CHECK(btc_self_only_change && btc_self_only_change->value_type == CHAIN_CONFIRM_VALUE_TEXT);
    CHECK(strcmp(btc_self_only_change->value.text, "0.00005 BTC") == 0);
    CHECK(test_confirm_summary_fits_tdisplay_s3(&g_last_ui_summary));
    CHECK(trezor_btc_tx_request_has_signed_payload(session_response_payload, session_response_payload_len,
        TREZOR_BITCOIN_REQUEST_TXFINISHED, 0, true, 1, 2));

    uint8_t trezor_btc_input1_payload[160];
    uint8_t trezor_btc_input1_ack_payload[288];
    uint8_t trezor_btc_two_input_sign_tx_payload[128];
    uint8_t trezor_btc_two_input_meta_ack_payload[288];
    size_t trezor_btc_input1_ack_payload_len = 0;
    size_t trezor_btc_two_input_sign_tx_payload_len = 0;
    size_t trezor_btc_two_input_meta_ack_payload_len = 0;
    const uint8_t trezor_btc_prev_hash1[32]
        = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
              0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };

    trezor_protobuf_writer_init(&trezor_sign_tx_writer, trezor_btc_two_input_sign_tx_payload, sizeof(trezor_btc_two_input_sign_tx_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 1, 1));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 2, 2));
    CHECK(trezor_protobuf_write_string_field(&trezor_sign_tx_writer, 3, "Testnet"));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_tx_writer, 4, 2));
    CHECK(trezor_protobuf_write_bool_field(&trezor_sign_tx_writer, 13, true));
    trezor_btc_two_input_sign_tx_payload_len = trezor_sign_tx_writer.len;

    trezor_protobuf_writer_init(&trezor_btc_input_writer, trezor_btc_input1_payload, sizeof(trezor_btc_input1_payload));
    for (size_t i = 0; i < ARRAY_LEN(btc_signing_path_1); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_btc_input_writer, 1, btc_signing_path_1[i]));
    }
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_input_writer, 2, trezor_btc_prev_hash1, sizeof(trezor_btc_prev_hash1)));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_input_writer, 3, 1));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_input_writer, 6, BITCOIN_P2WPKH_SPENDWITNESS));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_input_writer, 8, 40000));
    trezor_protobuf_writer_init(&trezor_btc_tx_writer, trezor_btc_tx_payload, sizeof(trezor_btc_tx_payload));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_btc_tx_writer, 2, trezor_btc_input1_payload, trezor_btc_input_writer.len));
    trezor_protobuf_writer_init(&trezor_btc_ack_writer, trezor_btc_ack_payload, sizeof(trezor_btc_ack_payload));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_btc_ack_writer, 1, trezor_btc_tx_payload, trezor_btc_tx_writer.len));
    trezor_btc_input1_ack_payload_len = trezor_btc_ack_writer.len;
    memcpy(trezor_btc_input1_ack_payload, trezor_btc_ack_payload, trezor_btc_input1_ack_payload_len);

    trezor_protobuf_writer_init(&trezor_btc_tx_writer, trezor_btc_tx_payload, sizeof(trezor_btc_tx_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_tx_writer, 1, 2));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_tx_writer, 6, 2));
    CHECK(trezor_protobuf_write_varint_field(&trezor_btc_tx_writer, 7, 1));
    trezor_protobuf_writer_init(&trezor_btc_ack_writer, trezor_btc_ack_payload, sizeof(trezor_btc_ack_payload));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_btc_ack_writer, 1, trezor_btc_tx_payload, trezor_btc_tx_writer.len));
    trezor_btc_two_input_meta_ack_payload_len = trezor_btc_ack_writer.len;
    memcpy(trezor_btc_two_input_meta_ack_payload, trezor_btc_ack_payload, trezor_btc_two_input_meta_ack_payload_len);

    g_trezor_btc_sign_calls = 0;
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_SIGN_TX, trezor_btc_two_input_sign_tx_payload,
        trezor_btc_two_input_sign_tx_payload_len, &session_response_type, session_response_payload,
        sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_two_input_meta_ack_payload,
        trezor_btc_two_input_meta_ack_payload_len, &session_response_type, session_response_payload,
        sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_input_ack_payload,
        trezor_btc_input_ack_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_input1_ack_payload,
        trezor_btc_input1_ack_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    g_trezor_btc_confirm_calls = 0;
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_output_ack_payload,
        trezor_btc_output_ack_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(g_trezor_btc_confirm_calls == 1);
    CHECK(g_trezor_btc_sign_calls == 2);
    CHECK(trezor_session_state.has_pending_btc_signed_tx);
    CHECK(trezor_btc_tx_request_has_signed_payload(session_response_payload, session_response_payload_len,
        TREZOR_BITCOIN_REQUEST_TXMETA, 0, false, 0, 0));
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_GET_PUBLIC_KEY, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));
    CHECK(trezor_session_state.has_pending_btc_signed_tx);
    CHECK(g_trezor_btc_sign_calls == 2);
    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, 16));
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_GET_ENTROPY, trezor_payload, trezor_writer.len,
        &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));
    CHECK(trezor_session_state.has_pending_btc_signed_tx);
    CHECK(g_trezor_entropy_calls == 0);
    CHECK(g_trezor_btc_sign_calls == 2);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_two_input_meta_ack_payload,
        trezor_btc_two_input_meta_ack_payload_len, &session_response_type, session_response_payload,
        sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(!trezor_session_state.has_pending_btc_signed_tx);
    CHECK(trezor_btc_tx_request_has_signed_payload(session_response_payload, session_response_payload_len,
        TREZOR_BITCOIN_REQUEST_TXFINISHED, 1, true, 2, 1));

    wally_bzero(&trezor_session_state, sizeof(trezor_session_state));
    g_trezor_btc_sign_calls = 0;
    session_response_event = TREZOR_SESSION_RESPONSE_EVENT_SIGNED_RESULT;
    CHECK(trezor_test_handle_wire_payload_event(&trezor_session, TREZOR_MSG_SIGN_TX,
        trezor_btc_two_input_sign_tx_payload, trezor_btc_two_input_sign_tx_payload_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len,
        &session_response_event));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(session_response_event == TREZOR_SESSION_RESPONSE_EVENT_NONE);
    CHECK(trezor_test_handle_wire_payload_event(&trezor_session, TREZOR_MSG_TX_ACK,
        trezor_btc_two_input_meta_ack_payload, trezor_btc_two_input_meta_ack_payload_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len,
        &session_response_event));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(session_response_event == TREZOR_SESSION_RESPONSE_EVENT_NONE);
    CHECK(trezor_test_handle_wire_payload_event(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_input_ack_payload,
        trezor_btc_input_ack_payload_len, &session_response_type, session_response_payload,
        sizeof(session_response_payload), &session_response_payload_len, &session_response_event));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(session_response_event == TREZOR_SESSION_RESPONSE_EVENT_NONE);
    CHECK(trezor_test_handle_wire_payload_event(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_input1_ack_payload,
        trezor_btc_input1_ack_payload_len, &session_response_type, session_response_payload,
        sizeof(session_response_payload), &session_response_payload_len, &session_response_event));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(session_response_event == TREZOR_SESSION_RESPONSE_EVENT_NONE);
    CHECK(trezor_test_handle_wire_payload_event(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_output_ack_payload,
        trezor_btc_output_ack_payload_len, &session_response_type, session_response_payload,
        sizeof(session_response_payload), &session_response_payload_len, &session_response_event));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(session_response_event == TREZOR_SESSION_RESPONSE_EVENT_NONE);
    CHECK(trezor_btc_tx_request_has_signed_payload(session_response_payload, session_response_payload_len,
        TREZOR_BITCOIN_REQUEST_TXMETA, 0, false, 0, 0));
    CHECK(trezor_test_handle_wire_payload_event(&trezor_session, TREZOR_MSG_TX_ACK,
        trezor_btc_two_input_meta_ack_payload, trezor_btc_two_input_meta_ack_payload_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len,
        &session_response_event));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(session_response_event == TREZOR_SESSION_RESPONSE_EVENT_SIGNED_RESULT);
    CHECK(trezor_btc_tx_request_has_signed_payload(session_response_payload, session_response_payload_len,
        TREZOR_BITCOIN_REQUEST_TXFINISHED, 1, true, 2, 1));

    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_SIGN_TX, trezor_valid_sign_tx_payload,
        trezor_valid_sign_tx_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_state.has_pending_btc_signing);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_meta_ack_payload,
        trezor_btc_meta_ack_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_output_ack_payload,
        trezor_btc_output_ack_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(!trezor_session_state.has_pending_btc_signing);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_DATA_ERROR));

    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_SIGN_TX, trezor_valid_sign_tx_payload,
        trezor_valid_sign_tx_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_meta_ack_payload,
        trezor_btc_meta_ack_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_input_ack_payload,
        trezor_btc_input_ack_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    g_ui_accept = false;
    g_trezor_btc_confirm_calls = 0;
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_output_ack_payload,
        trezor_btc_output_ack_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(g_trezor_btc_confirm_calls == 1);
    CHECK(!trezor_session_state.has_pending_btc_signing);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_ACTION_CANCELLED));
    g_ui_accept = true;

    wally_bzero(&trezor_session_state, sizeof(trezor_session_state));
    g_trezor_btc_confirm_calls = 0;
    g_trezor_btc_sign_calls = 0;
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_SIGN_TX, trezor_valid_sign_tx_payload,
        trezor_valid_sign_tx_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_meta_ack_payload,
        trezor_btc_meta_ack_payload_len, &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_multisig_input_ack_payload,
        trezor_btc_multisig_input_ack_payload_len, &session_response_type, session_response_payload,
        sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, trezor_btc_multisig_output_ack_payload,
        trezor_btc_multisig_output_ack_payload_len, &session_response_type, session_response_payload,
        sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_TX_REQUEST);
    CHECK(trezor_session_state.has_pending_btc_signing);
    CHECK(!trezor_session_state.has_pending_btc_signed_tx);
    CHECK(g_trezor_btc_confirm_calls == 0);
    CHECK(g_trezor_btc_sign_calls == 0);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_BITCOIN_REQUEST_TXMETA));
    trezor_bitcoin_signing_reset(&trezor_session_state.pending_btc_signing);
    trezor_session_state.has_pending_btc_signing = false;

    trezor_protobuf_writer_init(&trezor_bitcoin_writer, trezor_bitcoin_payload, sizeof(trezor_bitcoin_payload));
    for (size_t i = 0; i < ARRAY_LEN(btc_state_path); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_bitcoin_writer, 1, btc_state_path[i]));
    }
    CHECK(trezor_protobuf_write_string_field(&trezor_bitcoin_writer, 2, "Testnet"));
    CHECK(trezor_protobuf_write_bool_field(&trezor_bitcoin_writer, 3, true));
    CHECK(trezor_wire_encode_message(TREZOR_MSG_GET_ADDRESS, trezor_bitcoin_payload, trezor_bitcoin_writer.len,
        session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_ACTION_CANCELLED));

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    for (size_t i = 0; i < ARRAY_LEN(eth_bip44); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, eth_bip44[i]));
    }
    CHECK(trezor_wire_encode_message(TREZOR_MSG_ETHEREUM_GET_ADDRESS, trezor_payload, trezor_writer.len,
        session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_ETHEREUM_ADDRESS);
    CHECK(session_response_payload_len == trezor_address_payload_len);
    CHECK(memcmp(session_response_payload, trezor_address_payload, trezor_address_payload_len) == 0);
    CHECK(g_last_trezor_eth_address_request.address_n_len == ARRAY_LEN(eth_bip44));
    CHECK(memcmp(g_last_trezor_eth_address_request.address_n, eth_bip44, sizeof(eth_bip44)) == 0);
    CHECK(trezor_trace_format_latest(trace_text, sizeof(trace_text)));
    CHECK(strstr(trace_text, "EthereumGetAddress") != NULL);
    CHECK(strstr(trace_text, "path=m/44'/60'/0'/0/0") != NULL);
    CHECK(strstr(trace_text, "address omitted") != NULL);
    CHECK(strstr(trace_text, "0x52908400098527886E0F7030069857D2E4169EE7") == NULL);

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, 0));
    CHECK(trezor_wire_encode_message(TREZOR_MSG_APPLY_FLAGS, trezor_payload, trezor_writer.len,
        session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_SUCCESS);
    CHECK(session_response_payload_len == 0);

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, 1));
    CHECK(trezor_wire_encode_message(TREZOR_MSG_APPLY_FLAGS, trezor_payload, trezor_writer.len,
        session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_DATA_ERROR));

    CHECK(trezor_wire_encode_message(TREZOR_MSG_END_SESSION, NULL, 0, session_request_chunks,
        sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_SUCCESS);
    CHECK(session_response_payload_len == 0);

    CHECK(trezor_wire_encode_message(TREZOR_MSG_GET_PUBLIC_KEY, trezor_public_key_payload,
        trezor_public_key_payload_len, session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_PUBLIC_KEY);
    CHECK(!trezor_public_key_payload_has_private_key_field(session_response_payload, session_response_payload_len));
    CHECK(g_last_trezor_public_key_request.kind == TREZOR_PUBLIC_KEY_REQUEST_GENERIC);
    CHECK(g_last_trezor_public_key_request.address_n_len == ARRAY_LEN(eth_ledger_live_legacy));
    CHECK(memcmp(g_last_trezor_public_key_request.address_n, eth_ledger_live_legacy, sizeof(eth_ledger_live_legacy))
        == 0);
    CHECK(trezor_trace_format_latest(trace_text, sizeof(trace_text)));
    CHECK(strstr(trace_text, "GetPublicKey") != NULL);
    CHECK(strstr(trace_text, "path=m/44'/60'/0'/7") != NULL);
    CHECK(strstr(trace_text, "coin=Bitcoin") != NULL);
    CHECK(strstr(trace_text, "node/xpub omitted") != NULL);
    CHECK(strstr(trace_text, "xpub-test-only") == NULL);

    CHECK(trezor_wire_encode_message(TREZOR_MSG_GET_PUBLIC_KEY, trezor_btc_public_key_payload,
        trezor_btc_public_key_payload_len, session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_PUBLIC_KEY);
    CHECK(!trezor_public_key_payload_has_private_key_field(session_response_payload, session_response_payload_len));
    CHECK(g_last_trezor_public_key_request.kind == TREZOR_PUBLIC_KEY_REQUEST_GENERIC);
    CHECK(g_last_trezor_public_key_request.has_coin_name
        && strcmp(g_last_trezor_public_key_request.coin_name, "Testnet") == 0);
    CHECK(g_last_trezor_public_key_request.address_n_len == ARRAY_LEN(btc_account_path));
    CHECK(memcmp(g_last_trezor_public_key_request.address_n, btc_account_path, sizeof(btc_account_path)) == 0);

    CHECK(trezor_wire_encode_message(TREZOR_MSG_GET_PUBLIC_KEY, trezor_btc_mainnet_public_key_payload,
        trezor_btc_mainnet_public_key_payload_len, session_request_chunks, sizeof(session_request_chunks),
        &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_PUBLIC_KEY);
    CHECK(!trezor_public_key_payload_has_private_key_field(session_response_payload, session_response_payload_len));
    CHECK(g_last_trezor_public_key_request.kind == TREZOR_PUBLIC_KEY_REQUEST_GENERIC);
    CHECK(g_last_trezor_public_key_request.has_coin_name
        && strcmp(g_last_trezor_public_key_request.coin_name, "Bitcoin") == 0);
    CHECK(g_last_trezor_public_key_request.has_script_type
        && g_last_trezor_public_key_request.script_type == BITCOIN_P2WPKH_SPENDWITNESS);
    CHECK(g_last_trezor_public_key_request.address_n_len == ARRAY_LEN(btc_mainnet_p2wpkh_account_path));
    CHECK(memcmp(g_last_trezor_public_key_request.address_n, btc_mainnet_p2wpkh_account_path,
              sizeof(btc_mainnet_p2wpkh_account_path))
        == 0);

    CHECK(trezor_wire_encode_message(TREZOR_MSG_ETHEREUM_GET_PUBLIC_KEY, trezor_eth_public_key_payload,
        trezor_eth_public_key_payload_len, session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_ETHEREUM_PUBLIC_KEY);
    CHECK(!trezor_public_key_payload_has_private_key_field(session_response_payload, session_response_payload_len));
    CHECK(g_last_trezor_public_key_request.kind == TREZOR_PUBLIC_KEY_REQUEST_ETHEREUM);
    CHECK(g_last_trezor_public_key_request.address_n_len == ARRAY_LEN(eth_sep5));

    static const uint8_t trezor_sign_to[] = "0x52908400098527886E0F7030069857D2E4169EE7";
    static const uint8_t trezor_sign_value[] = { 0x01 };
    static const uint8_t trezor_sign_data_initial[] = { 0xde, 0xad };
    static const uint8_t trezor_sign_data_ack[] = { 0xbe, 0xef };
    uint8_t trezor_sign_payload[1024];
    trezor_protobuf_writer_t trezor_sign_writer;
    trezor_protobuf_writer_init(&trezor_sign_writer, trezor_sign_payload, sizeof(trezor_sign_payload));
    for (size_t i = 0; i < ARRAY_LEN(eth_bip44); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_sign_writer, 1, eth_bip44[i]));
    }
    CHECK(trezor_protobuf_write_bytes_field(&trezor_sign_writer, 3, (const uint8_t*)"\x09", 1));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_sign_writer, 4, (const uint8_t*)"\x52\x08", 2));
    CHECK(trezor_protobuf_write_string_field(&trezor_sign_writer, 11, (const char*)trezor_sign_to));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_sign_writer, 6, trezor_sign_value, sizeof(trezor_sign_value)));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_sign_writer, 7, trezor_sign_data_initial, sizeof(trezor_sign_data_initial)));
    CHECK(trezor_protobuf_write_varint_field(
        &trezor_sign_writer, 8, sizeof(trezor_sign_data_initial) + sizeof(trezor_sign_data_ack)));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_writer, 9, 1));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_sign_writer, 12, NULL, 0));
    CHECK(trezor_wire_encode_message(TREZOR_MSG_ETHEREUM_SIGN_TX, trezor_sign_payload, trezor_sign_writer.len,
        session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    session_response_event = TREZOR_SESSION_RESPONSE_EVENT_SIGNED_RESULT;
    CHECK(trezor_session_handle_wire_ex(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len, &session_response_event));
    CHECK(session_response_event == TREZOR_SESSION_RESPONSE_EVENT_NONE);
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_ETHEREUM_TX_REQUEST);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, sizeof(trezor_sign_data_ack)));
    CHECK(trezor_session_state.has_pending_eth_signing);
    CHECK(g_trezor_eth_sign_calls == 0);

    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_GET_PUBLIC_KEY, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));
    CHECK(trezor_session_state.has_pending_eth_signing);
    CHECK(g_trezor_eth_sign_calls == 0);

    CHECK(trezor_session_handle_payload(
        &trezor_session, TREZOR_MSG_ETHEREUM_GNOSIS_SAFE_TX_ACK, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));
    CHECK(trezor_session_state.has_pending_eth_signing);
    CHECK(g_trezor_eth_sign_calls == 0);

    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));
    CHECK(trezor_session_state.has_pending_eth_signing);
    CHECK(g_trezor_eth_sign_calls == 0);

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, 16));
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_GET_ENTROPY, trezor_payload, trezor_writer.len,
        &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));
    CHECK(trezor_session_state.has_pending_eth_signing);
    CHECK(g_trezor_entropy_calls == 0);
    CHECK(g_trezor_eth_sign_calls == 0);

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, 0));
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_APPLY_FLAGS, trezor_payload, trezor_writer.len,
        &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));
    CHECK(trezor_session_state.has_pending_eth_signing);
    CHECK(g_trezor_eth_sign_calls == 0);

    uint8_t trezor_ack_payload[64];
    trezor_protobuf_writer_t trezor_ack_writer;
    trezor_protobuf_writer_init(&trezor_ack_writer, trezor_ack_payload, sizeof(trezor_ack_payload));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_ack_writer, 1, trezor_sign_data_ack, sizeof(trezor_sign_data_ack)));
    CHECK(trezor_wire_encode_message(TREZOR_MSG_ETHEREUM_TX_ACK, trezor_ack_payload, trezor_ack_writer.len,
        session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    session_response_event = TREZOR_SESSION_RESPONSE_EVENT_NONE;
    CHECK(trezor_session_handle_wire_ex(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len, &session_response_event));
    CHECK(session_response_event == TREZOR_SESSION_RESPONSE_EVENT_SIGNED_RESULT);
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_ETHEREUM_TX_REQUEST);
    CHECK(trezor_payload_has_varint(session_response_payload, session_response_payload_len, 2, 37));
    CHECK(trezor_payload_contains_bytes(session_response_payload, session_response_payload_len,
        (const uint8_t*)"\xa0\xa1\xa2\xa3", 4));
    CHECK(trezor_payload_contains_bytes(session_response_payload, session_response_payload_len,
        (const uint8_t*)"\xc0\xc1\xc2\xc3", 4));
    CHECK(!trezor_session_state.has_pending_eth_signing);
    CHECK(g_trezor_eth_sign_calls == 1);
    CHECK(g_last_trezor_eth_sign_request.tx_type == ETHEREUM_TX_TYPE_LEGACY);
    CHECK(g_last_trezor_eth_sign_request.chain_id == 1);
    CHECK(g_last_trezor_eth_sign_request.path_len == ARRAY_LEN(eth_bip44));
    CHECK(memcmp(g_last_trezor_eth_sign_path, eth_bip44, sizeof(eth_bip44)) == 0);
    CHECK(g_last_trezor_eth_sign_request.value_len == sizeof(trezor_sign_value));
    CHECK(memcmp(g_last_trezor_eth_sign_value, trezor_sign_value, sizeof(trezor_sign_value)) == 0);
    CHECK(g_last_trezor_eth_sign_request.data_len == sizeof(trezor_sign_data_initial) + sizeof(trezor_sign_data_ack));
    CHECK(memcmp(g_last_trezor_eth_sign_data, trezor_sign_data_initial, sizeof(trezor_sign_data_initial)) == 0);
    CHECK(memcmp(g_last_trezor_eth_sign_data + sizeof(trezor_sign_data_initial), trezor_sign_data_ack,
              sizeof(trezor_sign_data_ack))
        == 0);
    CHECK(trezor_trace_format_latest(trace_text, sizeof(trace_text)));
    CHECK(strstr(trace_text, "EthereumTxAck") != NULL);
    CHECK(strstr(trace_text, "EthereumTxRequest") != NULL);

    trezor_protobuf_writer_init(&trezor_sign_writer, trezor_sign_payload, sizeof(trezor_sign_payload));
    for (size_t i = 0; i < ARRAY_LEN(eth_bip44); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_sign_writer, 1, eth_bip44[i]));
    }
    CHECK(trezor_protobuf_write_bytes_field(&trezor_sign_writer, 2, NULL, 0));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_sign_writer, 3, (const uint8_t*)"\x64", 1));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_sign_writer, 4, (const uint8_t*)"\x01", 1));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_sign_writer, 5, (const uint8_t*)"\x52\x08", 2));
    CHECK(trezor_protobuf_write_string_field(&trezor_sign_writer, 6, (const char*)trezor_sign_to));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_sign_writer, 7, NULL, 0));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_writer, 9, 0));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_writer, 10, 1));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_sign_writer, 12, NULL, 0));
    CHECK(trezor_wire_encode_message(TREZOR_MSG_ETHEREUM_SIGN_TX_EIP1559, trezor_sign_payload,
        trezor_sign_writer.len, session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    session_response_event = TREZOR_SESSION_RESPONSE_EVENT_NONE;
    CHECK(trezor_session_handle_wire_ex(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len, &session_response_event));
    CHECK(session_response_event == TREZOR_SESSION_RESPONSE_EVENT_SIGNED_RESULT);
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_ETHEREUM_TX_REQUEST);
    CHECK(trezor_payload_has_varint(session_response_payload, session_response_payload_len, 2, 1));
    CHECK(!trezor_session_state.has_pending_eth_signing);
    CHECK(g_trezor_eth_sign_calls == 2);
    CHECK(g_last_trezor_eth_sign_request.tx_type == ETHEREUM_TX_TYPE_EIP1559);
    CHECK(g_last_trezor_eth_sign_request.max_fee_per_gas == 100);
    CHECK(g_last_trezor_eth_sign_request.max_priority_fee_per_gas == 1);

    uint8_t signed_token_definition[256];
    size_t signed_token_definition_len = 0;
    uint8_t eth_definitions[512];
    size_t eth_definitions_len = 0;
    CHECK(make_signed_eth_token_definition(token_contract, 1, "USDT", 6, "Tether USD", true,
        signed_token_definition, sizeof(signed_token_definition), &signed_token_definition_len));
    CHECK(make_eth_definitions_with_token(
        signed_token_definition, signed_token_definition_len, eth_definitions, sizeof(eth_definitions), &eth_definitions_len));
    trezor_ethereum_definitions_t decoded_definitions;
    CHECK(trezor_ethereum_definitions_decode(eth_definitions, eth_definitions_len, &decoded_definitions));
    CHECK(decoded_definitions.has_token);
    CHECK(decoded_definitions.token.chain_id == 1);
    CHECK(decoded_definitions.token.decimals == 6);
    CHECK(strcmp(decoded_definitions.token.symbol, "USDT") == 0);
    CHECK(strcmp(decoded_definitions.token.name, "Tether USD") == 0);
    CHECK(memcmp(decoded_definitions.token.address, token_contract, sizeof(token_contract)) == 0);

    uint8_t bad_token_definition[256];
    size_t bad_token_definition_len = 0;
    CHECK(make_signed_eth_token_definition(token_contract, 1, "USDT", 6, "Tether USD", false,
        bad_token_definition, sizeof(bad_token_definition), &bad_token_definition_len));
    CHECK(make_eth_definitions_with_token(
        bad_token_definition, bad_token_definition_len, eth_definitions, sizeof(eth_definitions), &eth_definitions_len));
    CHECK(!trezor_ethereum_definitions_decode(eth_definitions, eth_definitions_len, &decoded_definitions));

    CHECK(make_eth_definitions_with_token(
        signed_token_definition, signed_token_definition_len, eth_definitions, sizeof(eth_definitions), &eth_definitions_len));
    static const uint8_t trezor_token_contract[] = "0x1111111111111111111111111111111111111111";
    trezor_protobuf_writer_init(&trezor_sign_writer, trezor_sign_payload, sizeof(trezor_sign_payload));
    for (size_t i = 0; i < ARRAY_LEN(eth_bip44); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_sign_writer, 1, eth_bip44[i]));
    }
    CHECK(trezor_protobuf_write_bytes_field(&trezor_sign_writer, 3, (const uint8_t*)"\x09", 1));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_sign_writer, 4, (const uint8_t*)"\x52\x08", 2));
    CHECK(trezor_protobuf_write_string_field(&trezor_sign_writer, 11, (const char*)trezor_token_contract));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_sign_writer, 7, erc20_transfer_data, sizeof(erc20_transfer_data)));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_writer, 8, sizeof(erc20_transfer_data)));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_writer, 9, 1));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_sign_writer, 12, eth_definitions, eth_definitions_len));
    CHECK(trezor_wire_encode_message(TREZOR_MSG_ETHEREUM_SIGN_TX, trezor_sign_payload, trezor_sign_writer.len,
        session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_ETHEREUM_TX_REQUEST);
    CHECK(trezor_payload_has_varint(session_response_payload, session_response_payload_len, 2, 37));
    CHECK(g_trezor_eth_sign_calls == 3);
    CHECK(g_last_trezor_eth_sign_request.has_token_definition);
    CHECK(g_last_trezor_eth_sign_request.token_definition.chain_id == 1);
    CHECK(g_last_trezor_eth_sign_request.token_definition.decimals == 6);
    CHECK(strcmp(g_last_trezor_eth_sign_request.token_definition.symbol, "USDT") == 0);
    CHECK(memcmp(g_last_trezor_eth_sign_request.token_definition.address, token_contract, sizeof(token_contract)) == 0);

    trezor_protobuf_writer_init(&trezor_sign_writer, trezor_sign_payload, sizeof(trezor_sign_payload));
    for (size_t i = 0; i < ARRAY_LEN(eth_bip44); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_sign_writer, 1, eth_bip44[i]));
    }
    CHECK(trezor_protobuf_write_bytes_field(&trezor_sign_writer, 3, (const uint8_t*)"\x09", 1));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_sign_writer, 4, (const uint8_t*)"\x52\x08", 2));
    CHECK(trezor_protobuf_write_string_field(&trezor_sign_writer, 11, (const char*)trezor_sign_to));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_sign_writer, 6, trezor_sign_value, sizeof(trezor_sign_value)));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_writer, 8, 0));
    CHECK(trezor_protobuf_write_varint_field(&trezor_sign_writer, 9, 1));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_sign_writer, 12, (const uint8_t*)"\x0a\x01x", 3));
    CHECK(trezor_wire_encode_message(TREZOR_MSG_ETHEREUM_SIGN_TX, trezor_sign_payload, trezor_sign_writer.len,
        session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_DATA_ERROR));

    const size_t trezor_eth_sign_calls_before_typed_hash = g_trezor_eth_sign_calls;
    trezor_protobuf_writer_init(&trezor_sign_writer, trezor_sign_payload, sizeof(trezor_sign_payload));
    for (size_t i = 0; i < ARRAY_LEN(eth_bip44); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_sign_writer, 1, eth_bip44[i]));
    }
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_sign_writer, 2, EXPECTED_SAFE_DOMAIN_HASH, sizeof(EXPECTED_SAFE_DOMAIN_HASH)));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_sign_writer, 3, EXPECTED_SAFE_MESSAGE_HASH, sizeof(EXPECTED_SAFE_MESSAGE_HASH)));
    CHECK(trezor_wire_encode_message(TREZOR_MSG_ETHEREUM_SIGN_TYPED_HASH, trezor_sign_payload,
        trezor_sign_writer.len, session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    session_response_event = TREZOR_SESSION_RESPONSE_EVENT_SIGNED_RESULT;
    CHECK(trezor_session_handle_wire_ex(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len, &session_response_event));
    CHECK(session_response_event == TREZOR_SESSION_RESPONSE_EVENT_NONE);
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_ETHEREUM_GNOSIS_SAFE_TX_REQUEST);
    CHECK(session_response_payload_len == 0);
    CHECK(!trezor_session_state.has_pending_eth_signing);
    CHECK(trezor_session_state.has_pending_eth_safe_typed_hash);
    CHECK(g_trezor_eth_sign_calls == trezor_eth_sign_calls_before_typed_hash);
    CHECK(trezor_trace_format_latest(trace_text, sizeof(trace_text)));
    CHECK(strstr(trace_text, "EthereumSignTypedHash") != NULL);
    CHECK(strstr(trace_text, "EthereumGnosisSafeTxRequest") != NULL);

    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_ETHEREUM_TX_ACK, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));
    CHECK(trezor_session_state.has_pending_eth_safe_typed_hash);
    CHECK(g_trezor_eth_sign_calls == trezor_eth_sign_calls_before_typed_hash);
    CHECK(g_trezor_eth_safe_sign_calls == 0);

    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_TX_ACK, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));
    CHECK(trezor_session_state.has_pending_eth_safe_typed_hash);
    CHECK(g_trezor_eth_sign_calls == trezor_eth_sign_calls_before_typed_hash);
    CHECK(g_trezor_eth_safe_sign_calls == 0);

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, 16));
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_GET_ENTROPY, trezor_payload, trezor_writer.len,
        &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));
    CHECK(trezor_session_state.has_pending_eth_safe_typed_hash);
    CHECK(g_trezor_entropy_calls == 0);
    CHECK(g_trezor_eth_safe_sign_calls == 0);

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, 0));
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_APPLY_FLAGS, trezor_payload, trezor_writer.len,
        &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));
    CHECK(trezor_session_state.has_pending_eth_safe_typed_hash);
    CHECK(g_trezor_eth_safe_sign_calls == 0);

    CHECK(trezor_wire_encode_message(TREZOR_MSG_ETHEREUM_GNOSIS_SAFE_TX_ACK, safe_ack_payload, safe_ack_payload_len,
        session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    session_response_event = TREZOR_SESSION_RESPONSE_EVENT_SIGNED_RESULT;
    g_ui_calls = 0;
    CHECK(trezor_session_handle_wire_ex(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len, &session_response_event));
    CHECK(session_response_event == TREZOR_SESSION_RESPONSE_EVENT_SIGNED_RESULT);
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_ETHEREUM_TYPED_DATA_SIGNATURE);
    CHECK(trezor_payload_has_bytes(session_response_payload, session_response_payload_len, 1, EC_SIGNATURE_RECOVERABLE_LEN));
    CHECK(!trezor_session_state.has_pending_eth_safe_typed_hash);
    CHECK(g_trezor_eth_sign_calls == trezor_eth_sign_calls_before_typed_hash);
    CHECK(g_trezor_eth_safe_sign_calls == 1);
    CHECK(g_ui_calls == 1);
    CHECK(g_last_ui_summary.chain == CHAIN_CONFIRM_CHAIN_ETHEREUM);
    CHECK(g_last_ui_summary.operation == CHAIN_CONFIRM_OPERATION_TOKEN_TRANSFER);
    CHECK(chain_confirm_summary_has_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_SAFE));
    CHECK(chain_confirm_summary_has_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_TOKEN_CONTRACT));
    CHECK(chain_confirm_summary_has_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_TOKEN_RECIPIENT));
    CHECK(chain_confirm_summary_has_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_TOKEN_AMOUNT));
    CHECK(chain_confirm_summary_has_field(&g_last_ui_summary, CHAIN_CONFIRM_FIELD_SAFE_TX_HASH));
    CHECK(test_confirm_summary_fits_tdisplay_s3(&g_last_ui_summary));
    CHECK(memcmp(g_last_trezor_eth_safe_signing_hash, EXPECTED_SAFE_SIGNING_HASH,
              sizeof(g_last_trezor_eth_safe_signing_hash))
        == 0);
    CHECK(trezor_trace_format_latest(trace_text, sizeof(trace_text)));
    CHECK(strstr(trace_text, "EthereumGnosisSafeTxAck") != NULL);
    CHECK(strstr(trace_text, "EthereumTypedDataSignature") != NULL);

    CHECK(trezor_wire_encode_message(TREZOR_MSG_ETHEREUM_SIGN_TX, NULL, 0, session_request_chunks,
        sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_DATA_ERROR));

    session_request_chunks[0] = 0;
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_INVALID_PROTOCOL));
    CHECK(trezor_trace_format_latest(trace_text, sizeof(trace_text)));
    CHECK(strstr(trace_text, "wire decode failed") != NULL);
    CHECK(strstr(trace_text, "InvalidProtocol") != NULL);
    CHECK(strstr(trace_text, "wire=bad") != NULL);
    CHECK(trezor_trace_format_history(trace_text, sizeof(trace_text)));
    CHECK(strstr(trace_text, "Recent USB messages") != NULL);
    CHECK(strstr(trace_text, "EthTyped?>SafeReq") != NULL);
    CHECK(strstr(trace_text, "SafeAck>EthTypedSig") != NULL);
    CHECK(strstr(trace_text, "BadWire>Fail") != NULL);
    CHECK(strstr(trace_text, "xpub-test-only") == NULL);
    CHECK(strstr(trace_text, "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r") == NULL);

    uint8_t trailing_wire_chunks[2U * TREZOR_WIRE_CHUNK_SIZE];
    size_t trailing_wire_len = 0;
    CHECK(trezor_wire_encode_message(TREZOR_MSG_GET_FEATURES, NULL, 0, trailing_wire_chunks,
        sizeof(trailing_wire_chunks), &trailing_wire_len));
    CHECK(trailing_wire_len == TREZOR_WIRE_CHUNK_SIZE);
    memset(trailing_wire_chunks + trailing_wire_len, 0x3f, TREZOR_WIRE_CHUNK_SIZE);
    CHECK(!trezor_wire_decode_message(trailing_wire_chunks, trailing_wire_len + TREZOR_WIRE_CHUNK_SIZE,
        &session_response_type, session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(trezor_session_handle_wire(&trezor_session, trailing_wire_chunks, trailing_wire_len + TREZOR_WIRE_CHUNK_SIZE,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_INVALID_PROTOCOL));

    uint8_t oversized_session_payload[TREZOR_SESSION_MAX_REQUEST_PAYLOAD_LEN + 1];
    memset(oversized_session_payload, 0x5a, sizeof(oversized_session_payload));
    CHECK(trezor_wire_encode_message(TREZOR_MSG_GET_FEATURES, oversized_session_payload,
        sizeof(oversized_session_payload), session_request_chunks, sizeof(session_request_chunks),
        &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_INVALID_PROTOCOL));

    g_trezor_eth_address_ok = false;
    CHECK(trezor_wire_encode_message(TREZOR_MSG_ETHEREUM_GET_ADDRESS, trezor_payload, trezor_writer.len,
        session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_ACTION_CANCELLED));
    g_trezor_eth_address_ok = true;

    g_trezor_public_key_ok = false;
    CHECK(trezor_wire_encode_message(TREZOR_MSG_ETHEREUM_GET_PUBLIC_KEY, trezor_eth_public_key_payload,
        trezor_eth_public_key_payload_len, session_request_chunks, sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_ACTION_CANCELLED));
    g_trezor_public_key_ok = true;

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    for (size_t i = 0; i < WALLET_CORE_MAX_PATH_LEN + 1; ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, i));
    }
    CHECK(!trezor_ethereum_get_address_decode(trezor_payload, trezor_writer.len, &trezor_get_address));

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, eth_bip44[0]));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 2, 2));
    CHECK(!trezor_ethereum_get_address_decode(trezor_payload, trezor_writer.len, &trezor_get_address));

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, eth_bip44[0]));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_writer, 3, (const uint8_t*)"net", 3));
    CHECK(!trezor_ethereum_get_address_decode(trezor_payload, trezor_writer.len, &trezor_get_address));

    trezor_ethereum_sign_typed_hash_t trezor_typed_hash;
    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    for (size_t i = 0; i < ARRAY_LEN(eth_bip44); ++i) {
        CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, eth_bip44[i]));
    }
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_writer, 2, EXPECTED_SAFE_DOMAIN_HASH, sizeof(EXPECTED_SAFE_DOMAIN_HASH)));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_writer, 3, EXPECTED_SAFE_MESSAGE_HASH, sizeof(EXPECTED_SAFE_MESSAGE_HASH)));
    CHECK(trezor_ethereum_sign_typed_hash_decode(trezor_payload, trezor_writer.len, &trezor_typed_hash));
    CHECK(trezor_typed_hash.address_n_len == ARRAY_LEN(eth_bip44));
    CHECK(memcmp(trezor_typed_hash.address_n, eth_bip44, sizeof(eth_bip44)) == 0);
    CHECK(trezor_typed_hash.has_domain_separator_hash);
    CHECK(memcmp(trezor_typed_hash.domain_separator_hash, EXPECTED_SAFE_DOMAIN_HASH,
              sizeof(EXPECTED_SAFE_DOMAIN_HASH))
        == 0);
    CHECK(trezor_typed_hash.has_message_hash);
    CHECK(memcmp(trezor_typed_hash.message_hash, EXPECTED_SAFE_MESSAGE_HASH, sizeof(EXPECTED_SAFE_MESSAGE_HASH))
        == 0);
    CHECK(!trezor_typed_hash.has_encoded_network);

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, eth_bip44[0]));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_writer, 2, EXPECTED_SAFE_DOMAIN_HASH, sizeof(EXPECTED_SAFE_DOMAIN_HASH) - 1U));
    CHECK(!trezor_ethereum_sign_typed_hash_decode(trezor_payload, trezor_writer.len, &trezor_typed_hash));

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, eth_bip44[0]));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_writer, 2, EXPECTED_SAFE_DOMAIN_HASH, sizeof(EXPECTED_SAFE_DOMAIN_HASH)));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_writer, 3, EXPECTED_SAFE_MESSAGE_HASH, sizeof(EXPECTED_SAFE_MESSAGE_HASH) - 1U));
    CHECK(!trezor_ethereum_sign_typed_hash_decode(trezor_payload, trezor_writer.len, &trezor_typed_hash));

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, eth_bip44[0]));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_writer, 2, EXPECTED_SAFE_DOMAIN_HASH, sizeof(EXPECTED_SAFE_DOMAIN_HASH)));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_writer, 4, (const uint8_t*)"network", 7));
    CHECK(trezor_ethereum_sign_typed_hash_decode(trezor_payload, trezor_writer.len, &trezor_typed_hash));
    CHECK(trezor_typed_hash.has_encoded_network);

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, eth_bip44[0]));
    CHECK(trezor_protobuf_write_bytes_field(
        &trezor_writer, 2, EXPECTED_SAFE_DOMAIN_HASH, sizeof(EXPECTED_SAFE_DOMAIN_HASH)));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 99, 1));
    CHECK(!trezor_ethereum_sign_typed_hash_decode(trezor_payload, trezor_writer.len, &trezor_typed_hash));

    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_INITIALIZE));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_GET_FEATURES));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_END_SESSION));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_APPLY_FLAGS));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_BUTTON_ACK));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_GET_ENTROPY));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_GET_ADDRESS));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_ETHEREUM_GET_ADDRESS));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_GET_PUBLIC_KEY));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_ETHEREUM_GET_PUBLIC_KEY));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_ETHEREUM_SIGN_TX));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_ETHEREUM_SIGN_TX_EIP1559));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_ETHEREUM_SIGN_TYPED_HASH));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_ETHEREUM_GNOSIS_SAFE_TX_ACK));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_ETHEREUM_TX_ACK));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_SIGN_TX));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_TX_ACK));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_ONEKEY_SIGN_PSBT));
    CHECK(trezor_dispatcher_message_sensitive_or_unsupported(TREZOR_MSG_LOAD_DEVICE));
    CHECK(trezor_dispatcher_message_sensitive_or_unsupported(TREZOR_MSG_RESET_DEVICE));
    CHECK(trezor_dispatcher_message_sensitive_or_unsupported(TREZOR_MSG_RECOVERY_DEVICE));
    CHECK(trezor_dispatcher_message_sensitive_or_unsupported(TREZOR_MSG_TX_ACK_PAYMENT_REQUEST));
    CHECK(trezor_dispatcher_message_sensitive_or_unsupported(TREZOR_MSG_CIPHER_KEY_VALUE));
    CHECK(trezor_dispatcher_message_sensitive_or_unsupported(TREZOR_MSG_BACKUP_DEVICE));
    CHECK(trezor_dispatcher_message_sensitive_or_unsupported(TREZOR_MSG_SIGN_MESSAGE));
    CHECK(trezor_dispatcher_message_sensitive_or_unsupported(TREZOR_MSG_PASSPHRASE_ACK));
    CHECK(trezor_dispatcher_message_sensitive_or_unsupported(TREZOR_MSG_SIGN_IDENTITY));
    CHECK(trezor_dispatcher_message_sensitive_or_unsupported(TREZOR_MSG_GET_ECDH_SESSION_KEY));
    CHECK(trezor_dispatcher_message_sensitive_or_unsupported(TREZOR_MSG_UNLOCK_PATH));

    CHECK(trezor_test_control_messages_clear_pending(
        &trezor_session, session_response_payload, sizeof(session_response_payload)) == 0);

    g_trezor_entropy_calls = 0;
    g_trezor_entropy_last_size = 0;
    g_trezor_entropy_ok = true;
    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, 16));
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_GET_ENTROPY, trezor_payload, trezor_writer.len,
        &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_BUTTON_REQUEST);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_BUTTON_REQUEST_PROTECT_CALL));
    CHECK(g_trezor_entropy_calls == 0);

    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_GET_FEATURES, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FEATURES);
    CHECK(trezor_session_state.has_pending_get_entropy);
    CHECK(g_trezor_entropy_calls == 0);

    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_GET_ENTROPY, trezor_payload, trezor_writer.len,
        &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));
    CHECK(trezor_session_state.has_pending_get_entropy);

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, 0));
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_APPLY_FLAGS, trezor_payload, trezor_writer.len,
        &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));
    CHECK(trezor_session_state.has_pending_get_entropy);

    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_BUTTON_ACK, (const uint8_t*)"\x01", 1,
        &session_response_type, session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_DATA_ERROR));
    CHECK(trezor_session_state.has_pending_get_entropy);
    CHECK(g_trezor_entropy_calls == 0);

    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_CANCEL, (const uint8_t*)"\x01", 1,
        &session_response_type, session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_DATA_ERROR));
    CHECK(trezor_session_state.has_pending_get_entropy);
    CHECK(g_trezor_entropy_calls == 0);

    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_BUTTON_ACK, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_ENTROPY);
    CHECK(trezor_payload_has_bytes(session_response_payload, session_response_payload_len, 1, 16));
    CHECK(g_trezor_entropy_calls == 1);
    CHECK(g_trezor_entropy_last_size == 16);

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, 16));
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_GET_ENTROPY, trezor_payload, trezor_writer.len,
        &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_BUTTON_REQUEST);
    CHECK(trezor_session_state.has_pending_get_entropy);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_CANCEL, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(!trezor_session_state.has_pending_get_entropy);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_BUTTON_ACK, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, 16));
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_GET_ENTROPY, trezor_payload, trezor_writer.len,
        &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_BUTTON_REQUEST);
    CHECK(trezor_session_state.has_pending_get_entropy);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_END_SESSION, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_SUCCESS);
    CHECK(!trezor_session_state.has_pending_get_entropy);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_BUTTON_ACK, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, 16));
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_GET_ENTROPY, trezor_payload, trezor_writer.len,
        &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_BUTTON_REQUEST);
    CHECK(trezor_session_state.has_pending_get_entropy);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_INITIALIZE, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FEATURES);
    CHECK(!trezor_session_state.has_pending_get_entropy);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_BUTTON_ACK, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, 2048));
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_GET_ENTROPY, trezor_payload, trezor_writer.len,
        &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_BUTTON_REQUEST);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_BUTTON_ACK, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_ENTROPY);
    CHECK(trezor_payload_has_bytes(session_response_payload, session_response_payload_len, 1, 1024));
    CHECK(g_trezor_entropy_last_size == TREZOR_GET_ENTROPY_MAX_SIZE);

    g_trezor_needs_local_unlock = true;
    g_trezor_local_unlock_ok = true;
    g_trezor_local_unlock_calls = 0;
    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, 8));
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_GET_ENTROPY, trezor_payload, trezor_writer.len,
        &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_BUTTON_REQUEST);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_BUTTON_REQUEST_PIN_ENTRY));
    CHECK(g_trezor_local_unlock_calls == 0);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_BUTTON_ACK, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_BUTTON_REQUEST);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_BUTTON_REQUEST_PROTECT_CALL));
    CHECK(g_trezor_local_unlock_calls == 1);
    CHECK(!g_trezor_needs_local_unlock);
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_BUTTON_ACK, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_ENTROPY);
    CHECK(trezor_payload_has_bytes(session_response_payload, session_response_payload_len, 1, 8));

    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_GET_ENTROPY, NULL, 0, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_DATA_ERROR));

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_bytes_field(&trezor_writer, 1, (const uint8_t*)"bad", 3));
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_GET_ENTROPY, trezor_payload, trezor_writer.len,
        &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_DATA_ERROR));

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, 16));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, 16));
    CHECK(trezor_session_handle_payload(&trezor_session, TREZOR_MSG_GET_ENTROPY, trezor_payload, trezor_writer.len,
        &session_response_type, session_response_payload, sizeof(session_response_payload),
        &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_DATA_ERROR));

    CHECK(!trezor_check_rejected_message(&trezor_session, TREZOR_MSG_LOAD_DEVICE, "LoadDevice"));
    CHECK(!trezor_check_rejected_message(&trezor_session, TREZOR_MSG_RESET_DEVICE, "ResetDevice"));
    CHECK(!trezor_check_rejected_message(&trezor_session, TREZOR_MSG_TX_ACK_PAYMENT_REQUEST, "TxAckPaymentRequest"));
    CHECK(!trezor_check_rejected_message(&trezor_session, TREZOR_MSG_CIPHER_KEY_VALUE, "CipherKeyValue"));
    CHECK(!trezor_check_rejected_message(&trezor_session, TREZOR_MSG_BACKUP_DEVICE, "BackupDevice"));
    CHECK(!trezor_check_rejected_message(&trezor_session, TREZOR_MSG_SIGN_MESSAGE, "SignMessage"));
    CHECK(!trezor_check_rejected_message(&trezor_session, TREZOR_MSG_PASSPHRASE_ACK, "PassphraseAck"));
    CHECK(!trezor_check_rejected_message(&trezor_session, TREZOR_MSG_RECOVERY_DEVICE, "RecoveryDevice"));
    CHECK(!trezor_check_rejected_message(&trezor_session, TREZOR_MSG_SIGN_IDENTITY, "SignIdentity"));
    CHECK(!trezor_check_rejected_message(&trezor_session, TREZOR_MSG_GET_ECDH_SESSION_KEY, "GetECDHSessionKey"));
    CHECK(!trezor_check_rejected_message(&trezor_session, TREZOR_MSG_UNLOCK_PATH, "UnlockPath"));

    CHECK(trezor_wire_encode_message(TREZOR_MSG_ONEKEY_SIGN_PSBT, NULL, 0, session_request_chunks,
        sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_DATA_ERROR));
    CHECK(trezor_trace_format_latest(trace_text, sizeof(trace_text)));
    CHECK(strstr(trace_text, "OneKeySignPsbt") != NULL);

    trezor_protobuf_writer_init(&trezor_writer, trezor_payload, sizeof(trezor_payload));
    CHECK(trezor_protobuf_write_varint_field(&trezor_writer, 1, 16));
    CHECK(trezor_wire_encode_message(TREZOR_MSG_GET_ENTROPY, trezor_payload, trezor_writer.len, session_request_chunks,
        sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_BUTTON_REQUEST);
    CHECK(trezor_trace_format_latest(trace_text, sizeof(trace_text)));
    CHECK(strstr(trace_text, "GetEntropy") != NULL);
    CHECK(trezor_wire_encode_message(TREZOR_MSG_BUTTON_ACK, NULL, 0, session_request_chunks,
        sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_ENTROPY);
    CHECK(trezor_payload_has_bytes(session_response_payload, session_response_payload_len, 1, 16));
    const size_t entropy_calls_after_wire = g_trezor_entropy_calls;
    for (size_t entropy_round = 0; entropy_round < 3; ++entropy_round) {
        CHECK(trezor_wire_encode_message(TREZOR_MSG_GET_ENTROPY, trezor_payload, trezor_writer.len,
            session_request_chunks, sizeof(session_request_chunks), &session_request_len));
        CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
            session_response_chunks, sizeof(session_response_chunks), &session_response_len));
        CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
            session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
        CHECK(session_response_type == TREZOR_MSG_BUTTON_REQUEST);
        CHECK(trezor_wire_encode_message(TREZOR_MSG_BUTTON_ACK, NULL, 0, session_request_chunks,
            sizeof(session_request_chunks), &session_request_len));
        session_response_event = TREZOR_SESSION_RESPONSE_EVENT_NONE;
        CHECK(trezor_session_handle_wire_ex(&trezor_session, session_request_chunks, session_request_len,
            session_response_chunks, sizeof(session_response_chunks), &session_response_len, &session_response_event));
        CHECK(session_response_event == TREZOR_SESSION_RESPONSE_EVENT_ENTROPY_RESULT);
        CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
            session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
        CHECK(session_response_type == TREZOR_MSG_ENTROPY);
        CHECK(trezor_payload_has_bytes(session_response_payload, session_response_payload_len, 1, 16));
    }
    CHECK(g_trezor_entropy_calls == entropy_calls_after_wire + 3);
    CHECK(!trezor_check_rejected_wire_message(&trezor_session, TREZOR_MSG_LOAD_DEVICE, "LoadDevice"));
    CHECK(!trezor_check_rejected_wire_message(&trezor_session, TREZOR_MSG_RESET_DEVICE, "ResetDevice"));
    CHECK(!trezor_check_rejected_wire_message(
        &trezor_session, TREZOR_MSG_TX_ACK_PAYMENT_REQUEST, "TxAckPaymentRequest"));
    CHECK(!trezor_check_rejected_wire_message(&trezor_session, TREZOR_MSG_CIPHER_KEY_VALUE, "CipherKeyValue"));
    CHECK(!trezor_check_rejected_wire_message(&trezor_session, TREZOR_MSG_BACKUP_DEVICE, "BackupDevice"));
    CHECK(!trezor_check_rejected_wire_message(&trezor_session, TREZOR_MSG_RECOVERY_DEVICE, "RecoveryDevice"));
    CHECK(!trezor_check_rejected_wire_message(&trezor_session, TREZOR_MSG_UNLOCK_PATH, "UnlockPath"));
    CHECK(trezor_check_invalid_wire_failure(&trezor_session));

    return 0;
}
