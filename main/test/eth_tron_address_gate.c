#include "chains/bitcoin/address.h"
#include "chains/bitcoin/path.h"
#include "chains/bitcoin/wallet.h"
#include "chains/ethereum/address.h"
#include "chains/ethereum/authorize.h"
#include "chains/ethereum/confirm.h"
#include "chains/ethereum/digest.h"
#include "chains/ethereum/path.h"
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
#include "protocols/trezor/bitcoin.h"
#include "protocols/trezor/dispatcher.h"
#include "protocols/trezor/ethereum.h"
#include "protocols/trezor/failure.h"
#include "protocols/trezor/features.h"
#include "protocols/trezor/protobuf.h"
#include "protocols/trezor/public_key.h"
#include "protocols/trezor/session.h"
#include "protocols/trezor/trace.h"
#include "protocols/trezor/wire.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>
#include <wally_crypto.h>

#define CHECK(cond)                                                                                                    \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            fprintf(stderr, "ETH/TRON address gate failed at %s:%d\n", __FILE__, __LINE__);                            \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (false)

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

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

static const uint8_t EXPECTED_ETH_ADDRESS[ETHEREUM_ADDRESS_LEN] = { 0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12,
    0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2, 0x65, 0x90, 0x29, 0x39, 0x5b, 0xdf };

static const uint8_t EXPECTED_TRON_ADDRESS[TRON_ADDRESS_LEN] = { 0x41, 0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12,
    0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2, 0x65, 0x90, 0x29, 0x39, 0x5b, 0xdf };

static const uint8_t EXPECTED_KECCAK256_EMPTY[KECCAK256_LEN]
    = { 0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0, 0xe5, 0x00,
          0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70 };

static const uint8_t EXPECTED_KECCAK256_ABC[KECCAK256_LEN]
    = { 0x4e, 0x03, 0x65, 0x7a, 0xea, 0x45, 0xa9, 0x4f, 0xc7, 0xd4, 0x7b, 0xa8, 0x26, 0xc8, 0xd6, 0x67, 0xc0, 0xd1,
          0xe6, 0xe3, 0x3a, 0x64, 0xa0, 0x36, 0xec, 0x44, 0xf5, 0x8f, 0xa1, 0x2d, 0x6c, 0x45 };

static bool g_wallet_pubkey_ok = true;
static bool g_ui_accept = true;
static size_t g_ui_calls = 0;
static chain_confirm_summary_t g_last_ui_summary;
static bool g_wallet_sign_ok = true;
static uint8_t g_wallet_signature_header = 31;
static bool g_trezor_eth_address_ok = true;
static bool g_trezor_bitcoin_address_ok = true;
static trezor_bitcoin_get_address_t g_last_trezor_bitcoin_address_request;
static trezor_ethereum_get_address_t g_last_trezor_eth_address_request;
static bool g_trezor_public_key_ok = true;
static trezor_public_key_request_t g_last_trezor_public_key_request;
static bool g_trezor_needs_local_unlock = false;
static bool g_trezor_local_unlock_ok = true;
static size_t g_trezor_local_unlock_calls = 0;
static bool g_trezor_initialize_session_ok = true;
static uint8_t g_trezor_last_initialize_session_id[TREZOR_FEATURES_SESSION_ID_LEN];
static size_t g_trezor_last_initialize_session_id_len = 0;

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
    const char expected[] = "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r";
    if (!g_trezor_bitcoin_address_ok || !request || !address || address_len < sizeof(expected)
        || (request->has_show_display && request->show_display)) {
        return false;
    }

    memcpy(&g_last_trezor_bitcoin_address_request, request, sizeof(g_last_trezor_bitcoin_address_request));
    memcpy(address, expected, sizeof(expected));
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
    memcpy(response->xpub, "xpub-test-only", sizeof("xpub-test-only"));
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

    signature[0] = g_wallet_signature_header;
    memset(signature + 1, 0xaa, ETHEREUM_SIGNATURE_R_LEN);
    memset(signature + 1 + ETHEREUM_SIGNATURE_R_LEN, 0xbb, ETHEREUM_SIGNATURE_S_LEN);
    return true;
}

bool show_chain_confirm_summary_activity(const chain_confirm_summary_t* summary)
{
    if (!summary || (summary->flags & CHAIN_CONFIRM_FLAG_USER_CONFIRM) == 0) {
        return false;
    }

    ++g_ui_calls;
    memcpy(&g_last_ui_summary, summary, sizeof(g_last_ui_summary));
    return g_ui_accept;
}

int wally_ec_public_key_verify(const unsigned char* pub_key, size_t pub_key_len)
{
    if (pub_key && pub_key_len == sizeof(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY)
        && memcmp(pub_key, PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_UNCOMPRESSED_PUBKEY)) == 0) {
        return WALLY_OK;
    }
    return WALLY_EINVAL;
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

int wally_hash160(const unsigned char* bytes, size_t bytes_len, unsigned char* bytes_out, size_t len)
{
    if (!bytes || bytes_len != sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY) || !bytes_out || len != HASH160_LEN
        || memcmp(bytes, PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY)) != 0) {
        return WALLY_EINVAL;
    }

    memcpy(bytes_out, EXPECTED_BTC_TESTNET_HASH160, sizeof(EXPECTED_BTC_TESTNET_HASH160));
    return WALLY_OK;
}

int wally_sha256(const unsigned char* bytes, size_t bytes_len, unsigned char* bytes_out, size_t len)
{
    if ((!bytes && bytes_len) || !bytes_out || len != SHA256_LEN) {
        return WALLY_EINVAL;
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

int main(void)
{
    CHECK(PRIVATE_KEY_ONE[EC_PRIVATE_KEY_LEN - 1] == 1);

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

    const uint32_t btc_state_path[]
        = { chain_path_harden(44), chain_path_harden(1), chain_path_harden(0), 0, 0 };
    const uint32_t btc_wrong_coin[]
        = { chain_path_harden(44), chain_path_harden(0), chain_path_harden(0), 0, 0 };
    CHECK(bitcoin_path_is_trezor_connect_state_testnet_p2pkh(btc_state_path, ARRAY_LEN(btc_state_path)));
    CHECK(!bitcoin_path_is_trezor_connect_state_testnet_p2pkh(btc_wrong_coin, ARRAY_LEN(btc_wrong_coin)));

    char btc_address[BITCOIN_P2PKH_ADDRESS_MAX_LEN];
    CHECK(bitcoin_p2pkh_testnet_address_from_compressed_pubkey(
        PRIVATE_KEY_ONE_COMPRESSED_PUBKEY, sizeof(PRIVATE_KEY_ONE_COMPRESSED_PUBKEY), btc_address, sizeof(btc_address)));
    CHECK(strcmp(btc_address, "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r") == 0);

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
    CHECK((confirm_summary.flags & CHAIN_CONFIRM_FLAG_USER_CONFIRM) != 0);
    CHECK((confirm_summary.flags & CHAIN_CONFIRM_FLAG_EXTRA_CONFIRM) == 0);
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_PATH));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_FROM));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TO));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_MAX_FEE));

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

    eth_req.data = erc20_transfer_data;
    eth_req.data_len = sizeof(erc20_transfer_data);
    CHECK(ethereum_tx_preflight(&eth_req, &eth_res));
    CHECK(eth_res.type == ETHEREUM_TX_SUMMARY_ERC20_TRANSFER);
    CHECK(memcmp(eth_res.token_contract, token_contract, sizeof(token_contract)) == 0);
    CHECK(memcmp(eth_res.token_recipient, EXPECTED_ETH_ADDRESS, sizeof(EXPECTED_ETH_ADDRESS)) == 0);
    CHECK(memcmp(eth_res.token_amount, token_amount, sizeof(token_amount)) == 0);
    CHECK(ethereum_confirm_summary_from_preflight(&eth_req, &eth_res, &confirm_summary));
    CHECK(confirm_summary.operation == CHAIN_CONFIRM_OPERATION_TOKEN_TRANSFER);
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_CONTRACT));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_RECIPIENT));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_AMOUNT));

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
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_CONTRACT));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_RECIPIENT));
    CHECK(chain_confirm_summary_has_field(&confirm_summary, CHAIN_CONFIRM_FIELD_TOKEN_AMOUNT));

    tron_req.contract_data = erc20_approve_data;
    tron_req.contract_data_len = sizeof(erc20_approve_data);
    CHECK(tron_tx_preflight(&tron_req, &tron_res));
    CHECK(tron_res.type == TRON_TX_SUMMARY_TRC20_APPROVE);
    CHECK(tron_confirm_summary_from_preflight(&tron_req, &tron_res, &confirm_summary));
    CHECK(confirm_summary.operation == CHAIN_CONFIRM_OPERATION_TOKEN_APPROVE);
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

    uint8_t trezor_bitcoin_address_payload[64];
    size_t trezor_bitcoin_address_payload_len = 0;
    CHECK(trezor_bitcoin_address_encode("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r", trezor_bitcoin_address_payload,
        sizeof(trezor_bitcoin_address_payload), &trezor_bitcoin_address_payload_len));
    CHECK(trezor_bitcoin_address_payload_len == 36);
    CHECK(trezor_bitcoin_address_payload[0] == ((1 << 3) | TREZOR_PROTOBUF_WIRE_LEN));
    CHECK(trezor_bitcoin_address_payload[1] == 34);

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
        .model = "Jade",
        .internal_model = "UNKNOWN",
        .session_id = trezor_session_id,
        .session_id_len = sizeof(trezor_session_id),
        .major_version = 2,
        .minor_version = 0,
        .patch_version = 0,
        .initialized = true,
        .has_unlocked = true,
        .unlocked = false,
        .pin_protection = true,
        .expose_private_fields = true,
        .passphrase_protection = false,
        .capabilities = { TREZOR_CAPABILITY_BITCOIN, TREZOR_CAPABILITY_BITCOIN_LIKE, TREZOR_CAPABILITY_ETHEREUM,
            TREZOR_CAPABILITY_TRON },
        .capabilities_len = 4 };
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
            saw_minor_version = version == 0;
        } else if (field_number == 4) {
            uint64_t version = 1;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &version));
            saw_patch_version = version == 0;
        } else if (field_number == 5) {
            uint64_t bool_value = 1;
            CHECK(trezor_protobuf_read_varint_value(value, value_len, &bool_value));
            saw_bootloader_mode = bool_value == 0;
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
            saw_model = wire_type_field == TREZOR_PROTOBUF_WIRE_LEN && value_len == strlen("Jade")
                && memcmp(value, "Jade", value_len) == 0;
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
            saw_internal_model = wire_type_field == TREZOR_PROTOBUF_WIRE_LEN && value_len == strlen("UNKNOWN")
                && memcmp(value, "UNKNOWN", value_len) == 0;
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
    CHECK(saw_bootloader_mode);
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
    CHECK(saw_tron);

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
    };
    uint8_t session_request_chunks[1408];
    uint8_t session_response_chunks[512];
    uint8_t session_response_payload[256];
    size_t session_request_len = 0;
    size_t session_response_len = 0;
    size_t session_response_payload_len = 0;
    uint16_t session_response_type = 0;
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
        trezor_payload_has_varint(session_response_payload, session_response_payload_len, 30, TREZOR_CAPABILITY_TRON));
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

    CHECK(trezor_wire_encode_message(TREZOR_MSG_ETHEREUM_SIGN_TX, NULL, 0, session_request_chunks,
        sizeof(session_request_chunks), &session_request_len));
    CHECK(trezor_session_handle_wire(&trezor_session, session_request_chunks, session_request_len,
        session_response_chunks, sizeof(session_response_chunks), &session_response_len));
    CHECK(trezor_wire_decode_message(session_response_chunks, session_response_len, &session_response_type,
        session_response_payload, sizeof(session_response_payload), &session_response_payload_len));
    CHECK(session_response_type == TREZOR_MSG_FAILURE);
    CHECK(trezor_payload_has_varint(
        session_response_payload, session_response_payload_len, 1, TREZOR_FAILURE_UNEXPECTED_MESSAGE));

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
    CHECK(strstr(trace_text, "GetPub>Pub") != NULL);
    CHECK(strstr(trace_text, "EthPub?>EthPub") != NULL);
    CHECK(strstr(trace_text, "EthSign>Fail") != NULL);
    CHECK(strstr(trace_text, "BadWire>Fail") != NULL);
    CHECK(strstr(trace_text, "xpub-test-only") == NULL);
    CHECK(strstr(trace_text, "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r") == NULL);

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

    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_INITIALIZE));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_GET_FEATURES));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_END_SESSION));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_BUTTON_ACK));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_GET_ADDRESS));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_ETHEREUM_GET_ADDRESS));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_GET_PUBLIC_KEY));
    CHECK(trezor_dispatcher_message_allowed(TREZOR_MSG_ETHEREUM_GET_PUBLIC_KEY));
    CHECK(trezor_dispatcher_message_sensitive_or_unsupported(TREZOR_MSG_LOAD_DEVICE));
    CHECK(trezor_dispatcher_message_sensitive_or_unsupported(TREZOR_MSG_RECOVERY_DEVICE));
    CHECK(trezor_dispatcher_message_sensitive_or_unsupported(TREZOR_MSG_GET_ENTROPY));
    CHECK(trezor_dispatcher_message_sensitive_or_unsupported(TREZOR_MSG_CIPHER_KEY_VALUE));
    CHECK(trezor_dispatcher_message_sensitive_or_unsupported(TREZOR_MSG_GET_ECDH_SESSION_KEY));
    CHECK(trezor_dispatcher_message_sensitive_or_unsupported(TREZOR_MSG_ETHEREUM_SIGN_TX));
    CHECK(trezor_dispatcher_message_sensitive_or_unsupported(TREZOR_MSG_ETHEREUM_SIGN_TX_EIP1559));

    return 0;
}
