#include "wallet_core.h"

#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../sensitive.h"
#ifdef CONFIG_TREZOR_USB_HID
#include "../protocols/trezor/trace.h"
#define WALLET_CORE_TRACE(stage) trezor_trace_set_stage(stage)
#else
#define WALLET_CORE_TRACE(stage) ((void)0)
#endif
#include "../utils/util.h"
#include "../wallet.h"

#include <string.h>
#include <wally_core.h>
#include <wally_bip32.h>

void wallet_core_init(void)
{
    keychain_lock();
    keychain_unlock();
}

static void wallet_core_lock(void) { keychain_lock(); }
static void wallet_core_unlock(void) { keychain_unlock(); }

bool wallet_core_is_unlocked(void)
{
    wallet_core_lock();
    const bool ret = keychain_get() != NULL;
    wallet_core_unlock();
    return ret;
}

bool wallet_core_is_initialized(void)
{
    wallet_core_lock();
    const bool ret = keychain_has_pin();
    wallet_core_unlock();
    return ret;
}

bool wallet_core_is_ready(void)
{
    wallet_core_lock();
    const bool ret = keychain_has_pin() && keychain_get() != NULL;
    wallet_core_unlock();
    return ret;
}

bool wallet_core_path_valid(const wallet_core_path_t* const path)
{
    return path && path->len > 0 && path->len <= WALLET_CORE_MAX_PATH_LEN;
}

bool wallet_core_get_fingerprint(uint8_t* const output, const size_t output_len)
{
    wallet_core_lock();
    if (!wallet_core_is_unlocked() || !output || output_len != BIP32_KEY_FINGERPRINT_LEN) {
        wallet_core_unlock();
        return false;
    }

    wallet_get_fingerprint(output, output_len);
    wallet_core_unlock();
    return true;
}

static bool derive_private_key(const wallet_core_path_t* const path, uint8_t* const private_key, const size_t key_len)
{
    wallet_core_lock();
    if (!wallet_core_is_unlocked() || !wallet_core_path_valid(path) || !private_key || key_len != EC_PRIVATE_KEY_LEN) {
        wallet_core_unlock();
        return false;
    }

    struct ext_key derived;
    WALLET_CORE_TRACE("wcore:derive_push");
    SENSITIVE_PUSH(&derived, sizeof(derived));

    WALLET_CORE_TRACE("wcore:derive_hdkey");
    const bool ok = wallet_get_hdkey(path->parts, path->len, BIP32_FLAG_KEY_PRIVATE | BIP32_FLAG_SKIP_HASH, &derived);
    if (ok) {
        memcpy(private_key, derived.priv_key + 1, key_len);
    }

    WALLET_CORE_TRACE("wcore:derive_pop");
    SENSITIVE_POP(&derived);
    WALLET_CORE_TRACE(ok ? "wcore:derive_ok" : "wcore:derive_fail");
    wallet_core_unlock();
    return ok;
}

bool wallet_core_get_public_key(const wallet_core_path_t* const path, const wallet_core_pubkey_format_t format,
    uint8_t* const output, const size_t output_len)
{
    wallet_core_lock();
    if (!wallet_core_is_unlocked() || !wallet_core_path_valid(path) || !output || output_len != (size_t)format) {
        wallet_core_unlock();
        return false;
    }

    if (format == WALLET_CORE_PUBKEY_COMPRESSED) {
        struct ext_key derived;
        WALLET_CORE_TRACE("wcore:pubc_hdkey");
        if (!wallet_get_hdkey(path->parts, path->len, BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH, &derived)) {
            WALLET_CORE_TRACE("wcore:pubc_fail");
            wallet_core_unlock();
            return false;
        }
        memcpy(output, derived.pub_key, output_len);
        JADE_WALLY_VERIFY(wally_bzero(&derived, sizeof(derived)));
        WALLET_CORE_TRACE("wcore:pubc_ok");
        wallet_core_unlock();
        return true;
    }

    if (format == WALLET_CORE_PUBKEY_UNCOMPRESSED) {
        uint8_t compressed_pubkey[EC_PUBLIC_KEY_LEN];
        WALLET_CORE_TRACE("wcore:pubu_push");
        SENSITIVE_PUSH(compressed_pubkey, sizeof(compressed_pubkey));

        WALLET_CORE_TRACE("wcore:pubu_core");
        const bool ok = wallet_core_get_public_key(
                            path, WALLET_CORE_PUBKEY_COMPRESSED, compressed_pubkey, sizeof(compressed_pubkey))
            && wally_ec_public_key_decompress(compressed_pubkey, sizeof(compressed_pubkey), output, output_len)
                == WALLY_OK;

        WALLET_CORE_TRACE("wcore:pubu_pop");
        SENSITIVE_POP(compressed_pubkey);
        WALLET_CORE_TRACE(ok ? "wcore:pubu_ok" : "wcore:pubu_fail");
        wallet_core_unlock();
        return ok;
    }

    wallet_core_unlock();
    return false;
}

static uint32_t wallet_core_fingerprint_to_u32(const uint8_t fingerprint[BIP32_KEY_FINGERPRINT_LEN])
{
    return ((uint32_t)fingerprint[0] << 24) | ((uint32_t)fingerprint[1] << 16) | ((uint32_t)fingerprint[2] << 8)
        | (uint32_t)fingerprint[3];
}

static bool wallet_core_bip32_public_version_allowed(const uint32_t version)
{
    return version == 0 || version == BIP32_VER_MAIN_PUBLIC || version == BIP32_VER_TEST_PUBLIC
        || version == 0x049D7CB2U || version == 0x04B24746U || version == 0x044A5262U || version == 0x045F1CF6U
        || version == 0x0295B43FU || version == 0x02AA7ED3U || version == 0x024289EFU || version == 0x02575483U;
}

static void wallet_core_write_be32(uint8_t* const output, const uint32_t value)
{
    output[0] = (uint8_t)(value >> 24);
    output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8);
    output[3] = (uint8_t)value;
}

static bool wallet_core_public_node_to_base58(
    const struct ext_key* const node, const uint32_t public_version, char** const output)
{
    if (!node || !output || !wallet_core_bip32_public_version_allowed(public_version)
        || (node->pub_key[0] != 0x02 && node->pub_key[0] != 0x03)) {
        return false;
    }

    uint8_t serialized[BIP32_SERIALIZED_LEN];
    size_t offset = 0;
    wallet_core_write_be32(serialized + offset, public_version);
    offset += sizeof(uint32_t);
    serialized[offset++] = node->depth;
    memcpy(serialized + offset, node->parent160, BIP32_KEY_FINGERPRINT_LEN);
    offset += BIP32_KEY_FINGERPRINT_LEN;
    wallet_core_write_be32(serialized + offset, node->child_num);
    offset += sizeof(uint32_t);
    memcpy(serialized + offset, node->chain_code, sizeof(node->chain_code));
    offset += sizeof(node->chain_code);
    memcpy(serialized + offset, node->pub_key, sizeof(node->pub_key));
    offset += sizeof(node->pub_key);

    const bool ok = offset == sizeof(serialized)
        && wally_base58_from_bytes(serialized, sizeof(serialized), BASE58_FLAG_CHECKSUM, output) == WALLY_OK && *output;
    JADE_WALLY_VERIFY(wally_bzero(serialized, sizeof(serialized)));
    return ok;
}

bool wallet_core_get_public_node_with_version(
    const wallet_core_path_t* const path, const uint32_t bip32_public_version, wallet_core_public_node_t* const output)
{
    wallet_core_lock();
    if (!wallet_core_is_unlocked() || !wallet_core_path_valid(path) || !output
        || !wallet_core_bip32_public_version_allowed(bip32_public_version)) {
        wallet_core_unlock();
        return false;
    }

    struct ext_key derived;
    char* xpub = NULL;
    wally_bzero(output, sizeof(*output));

    bool ok = wallet_get_hdkey(path->parts, path->len, BIP32_FLAG_KEY_PUBLIC, &derived);
    if (ok) {
        const uint32_t public_version = bip32_public_version != 0 ? bip32_public_version : derived.version;
        ok = wallet_core_public_node_to_base58(&derived, public_version, &xpub) && strlen(xpub) < sizeof(output->xpub);
    }
    if (ok) {
        output->depth = derived.depth;
        output->fingerprint = wallet_core_fingerprint_to_u32(derived.parent160);
        output->child_num = derived.child_num;
        memcpy(output->chain_code, derived.chain_code, sizeof(output->chain_code));
        memcpy(output->public_key, derived.pub_key, sizeof(output->public_key));
        memcpy(output->xpub, xpub, strlen(xpub) + 1);

        uint8_t root_fingerprint[BIP32_KEY_FINGERPRINT_LEN];
        if (wallet_core_get_fingerprint(root_fingerprint, sizeof(root_fingerprint))) {
            output->root_fingerprint = wallet_core_fingerprint_to_u32(root_fingerprint);
        }
        wally_bzero(root_fingerprint, sizeof(root_fingerprint));
    } else {
        wally_bzero(output, sizeof(*output));
    }

    if (xpub) {
        JADE_WALLY_VERIFY(wally_free_string(xpub));
    }
    JADE_WALLY_VERIFY(wally_bzero(&derived, sizeof(derived)));
    wallet_core_unlock();
    return ok;
}

bool wallet_core_get_public_node(const wallet_core_path_t* const path, wallet_core_public_node_t* const output)
{
    return wallet_core_get_public_node_with_version(path, 0, output);
}

bool wallet_core_sign_digest_ecdsa_recoverable(const wallet_core_path_t* const path, const uint8_t* const digest,
    const size_t digest_len, uint8_t* const signature, const size_t signature_len)
{
    wallet_core_lock();
    if (!wallet_core_is_unlocked() || !wallet_core_path_valid(path) || !digest || digest_len != SHA256_LEN || !signature
        || signature_len != EC_SIGNATURE_RECOVERABLE_LEN) {
        wallet_core_unlock();
        return false;
    }

    uint8_t private_key[EC_PRIVATE_KEY_LEN];
    WALLET_CORE_TRACE("wcore:sign_priv_push");
    SENSITIVE_PUSH(private_key, sizeof(private_key));

    WALLET_CORE_TRACE("wcore:sign_derive");
    const bool ok = derive_private_key(path, private_key, sizeof(private_key))
        && (WALLET_CORE_TRACE("wcore:sign_crypto"), true)
        && wally_ec_sig_from_bytes(private_key, sizeof(private_key), digest, digest_len,
               EC_FLAG_ECDSA | EC_FLAG_RECOVERABLE, signature, signature_len)
            == WALLY_OK;

    WALLET_CORE_TRACE("wcore:sign_pop");
    SENSITIVE_POP(private_key);
    WALLET_CORE_TRACE(ok ? "wcore:sign_ok" : "wcore:sign_fail");
    wallet_core_unlock();
    return ok;
}
