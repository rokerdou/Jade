#include "wallet_core/wallet_core.h"

#include "keychain.h"
#include "wallet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_crypto.h>

#define CHECK(cond)                                                                                                    \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            fprintf(stderr, "wallet_core public node gate failed at %s:%d\n", __FILE__, __LINE__);                     \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (false)

static const uint8_t TEST_PARENT160[HASH160_LEN]
    = { 0x11, 0x22, 0x33, 0x44, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
          0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f };
static const uint8_t TEST_HASH160[HASH160_LEN]
    = { 0x99, 0x88, 0x77, 0x66, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65,
          0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f };
static const uint8_t TEST_ROOT_FINGERPRINT[BIP32_KEY_FINGERPRINT_LEN] = { 0xaa, 0xbb, 0xcc, 0xdd };
static const char TEST_XPUB[] = "xpub-serialized-public-node-test";

static keychain_t s_keychain;
static uint8_t s_last_base58_payload[BIP32_SERIALIZED_LEN];
static size_t s_last_base58_payload_len = 0;
static uint32_t s_last_base58_version = 0;

static uint32_t read_be32(const uint8_t* const bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

const keychain_t* keychain_get(void) { return &s_keychain; }

bool keychain_has_pin(void) { return true; }

void keychain_lock(void) {}

void keychain_unlock(void) {}

void wallet_get_fingerprint(uint8_t* const output, const size_t output_len)
{
    if (output && output_len == sizeof(TEST_ROOT_FINGERPRINT)) {
        memcpy(output, TEST_ROOT_FINGERPRINT, sizeof(TEST_ROOT_FINGERPRINT));
    }
}

bool wallet_get_hdkey(const uint32_t* const path, const size_t path_len, const uint32_t flags, struct ext_key* const output)
{
    if (!path || path_len == 0 || !output || flags != BIP32_FLAG_KEY_PUBLIC) {
        return false;
    }

    memset(output, 0, sizeof(*output));
    output->version = BIP32_VER_TEST_PUBLIC;
    output->depth = 5;
    output->child_num = path[path_len - 1];
    memcpy(output->parent160, TEST_PARENT160, sizeof(TEST_PARENT160));
    memcpy(output->hash160, TEST_HASH160, sizeof(TEST_HASH160));
    for (size_t i = 0; i < sizeof(output->chain_code); ++i) {
        output->chain_code[i] = (uint8_t)(0xc0 + i);
    }
    output->pub_key[0] = 0x02;
    for (size_t i = 1; i < sizeof(output->pub_key); ++i) {
        output->pub_key[i] = (uint8_t)i;
    }
    return true;
}

int wally_base58_from_bytes(const unsigned char* const bytes, const size_t bytes_len, const uint32_t flags,
    char** const output)
{
    if (!bytes || bytes_len != BIP32_SERIALIZED_LEN || flags != BASE58_FLAG_CHECKSUM || !output) {
        return WALLY_EINVAL;
    }

    memcpy(s_last_base58_payload, bytes, bytes_len);
    s_last_base58_payload_len = bytes_len;
    s_last_base58_version = read_be32(bytes);
    *output = malloc(sizeof(TEST_XPUB));
    if (!*output) {
        return WALLY_ENOMEM;
    }
    memcpy(*output, TEST_XPUB, sizeof(TEST_XPUB));
    return WALLY_OK;
}

static bool last_serialized_public_node_matches(
    const uint32_t version, const uint32_t child_num, const uint8_t depth)
{
    return s_last_base58_payload_len == BIP32_SERIALIZED_LEN && s_last_base58_version == version
        && s_last_base58_payload[4] == depth
        && memcmp(s_last_base58_payload + 5, TEST_PARENT160, BIP32_KEY_FINGERPRINT_LEN) == 0
        && read_be32(s_last_base58_payload + 9) == child_num
        && s_last_base58_payload[13] == 0xc0 && s_last_base58_payload[44] == 0xdf
        && s_last_base58_payload[45] == 0x02 && s_last_base58_payload[46] == 0x01
        && s_last_base58_payload[77] == 0x20;
}

int wally_free_string(char* const str)
{
    free(str);
    return WALLY_OK;
}

int wally_bzero(void* const bytes, const size_t bytes_len)
{
    if (!bytes && bytes_len) {
        return WALLY_EINVAL;
    }
    if (bytes) {
        memset(bytes, 0, bytes_len);
    }
    return WALLY_OK;
}

void sensitive_push(const char* file, int line, void* addr, size_t size)
{
    (void)file;
    (void)line;
    (void)addr;
    (void)size;
}

void sensitive_pop(const char* file, int line, void* addr)
{
    (void)file;
    (void)line;
    (void)addr;
}

void jade_abort(const char* file, const int line_n)
{
    (void)file;
    (void)line_n;
    _exit(1);
}

int wally_ec_public_key_decompress(
    const unsigned char* pub_key, size_t pub_key_len, unsigned char* bytes_out, size_t len)
{
    (void)pub_key;
    (void)pub_key_len;
    (void)bytes_out;
    (void)len;
    return WALLY_EINVAL;
}

int wally_ec_sig_from_bytes(const unsigned char* priv_key, size_t priv_key_len, const unsigned char* bytes,
    size_t bytes_len, uint32_t flags, unsigned char* bytes_out, size_t len)
{
    (void)priv_key;
    (void)priv_key_len;
    (void)bytes;
    (void)bytes_len;
    (void)flags;
    (void)bytes_out;
    (void)len;
    return WALLY_EINVAL;
}

int main(void)
{
    wallet_core_path_t path = {
        .parts = { BIP32_INITIAL_HARDENED_CHILD + 44, BIP32_INITIAL_HARDENED_CHILD + 60,
            BIP32_INITIAL_HARDENED_CHILD, 0, 7 },
        .len = 5,
    };
    wallet_core_public_node_t node;
    memset(&node, 0, sizeof(node));

    CHECK(wallet_core_get_public_node(&path, &node));
    CHECK(node.depth == 5);
    CHECK(node.child_num == 7);
    CHECK(node.fingerprint == 0x11223344);
    CHECK(node.fingerprint != 0x99887766);
    CHECK(node.root_fingerprint == 0xaabbccdd);
    CHECK(node.public_key[0] == 0x02);
    CHECK(node.public_key[1] == 0x01);
    CHECK(node.public_key[32] == 0x20);
    CHECK(strcmp(node.xpub, TEST_XPUB) == 0);
    CHECK(node.chain_code[0] == 0xc0);
    CHECK(node.chain_code[31] == 0xdf);
    CHECK(last_serialized_public_node_matches(BIP32_VER_TEST_PUBLIC, 7, 5));

    memset(&node, 0, sizeof(node));
    CHECK(wallet_core_get_public_node_with_version(&path, BIP32_VER_TEST_PUBLIC, &node));
    CHECK(strcmp(node.xpub, TEST_XPUB) == 0);
    CHECK(last_serialized_public_node_matches(BIP32_VER_TEST_PUBLIC, 7, 5));
    CHECK(wallet_core_get_public_node_with_version(&path, 0x04B24746U, &node));
    CHECK(strcmp(node.xpub, TEST_XPUB) == 0);
    CHECK(last_serialized_public_node_matches(0x04B24746U, 7, 5));
    CHECK(wallet_core_get_public_node_with_version(&path, 0x049D7CB2U, &node));
    CHECK(strcmp(node.xpub, TEST_XPUB) == 0);
    CHECK(last_serialized_public_node_matches(0x049D7CB2U, 7, 5));
    CHECK(wallet_core_get_public_node_with_version(&path, 0x045F1CF6U, &node));
    CHECK(strcmp(node.xpub, TEST_XPUB) == 0);
    CHECK(last_serialized_public_node_matches(0x045F1CF6U, 7, 5));
    CHECK(wallet_core_get_public_node_with_version(&path, 0x044A5262U, &node));
    CHECK(strcmp(node.xpub, TEST_XPUB) == 0);
    CHECK(last_serialized_public_node_matches(0x044A5262U, 7, 5));
    CHECK(wallet_core_get_public_node_with_version(&path, 0x0295B43FU, &node));
    CHECK(strcmp(node.xpub, TEST_XPUB) == 0);
    CHECK(last_serialized_public_node_matches(0x0295B43FU, 7, 5));
    CHECK(wallet_core_get_public_node_with_version(&path, 0x02AA7ED3U, &node));
    CHECK(strcmp(node.xpub, TEST_XPUB) == 0);
    CHECK(last_serialized_public_node_matches(0x02AA7ED3U, 7, 5));
    CHECK(wallet_core_get_public_node_with_version(&path, 0x024289EFU, &node));
    CHECK(strcmp(node.xpub, TEST_XPUB) == 0);
    CHECK(last_serialized_public_node_matches(0x024289EFU, 7, 5));
    CHECK(wallet_core_get_public_node_with_version(&path, 0x02575483U, &node));
    CHECK(strcmp(node.xpub, TEST_XPUB) == 0);
    CHECK(last_serialized_public_node_matches(0x02575483U, 7, 5));
    CHECK(!wallet_core_get_public_node_with_version(&path, 0x0488ADE4U, &node));
    CHECK(!wallet_core_get_public_node_with_version(&path, BIP32_VER_TEST_PRIVATE, &node));

    return 0;
}
