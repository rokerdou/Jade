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

bool wallet_core_is_unlocked(void) { return keychain_get() != NULL; }

bool wallet_core_is_initialized(void) { return keychain_has_pin(); }

bool wallet_core_is_ready(void) { return wallet_core_is_initialized() && wallet_core_is_unlocked(); }

bool wallet_core_path_valid(const wallet_core_path_t* const path)
{
    return path && path->len > 0 && path->len <= WALLET_CORE_MAX_PATH_LEN;
}

bool wallet_core_get_fingerprint(uint8_t* const output, const size_t output_len)
{
    if (!wallet_core_is_unlocked() || !output || output_len != BIP32_KEY_FINGERPRINT_LEN) {
        return false;
    }

    wallet_get_fingerprint(output, output_len);
    return true;
}

static bool derive_private_key(const wallet_core_path_t* const path, uint8_t* const private_key, const size_t key_len)
{
    if (!wallet_core_is_unlocked() || !wallet_core_path_valid(path) || !private_key || key_len != EC_PRIVATE_KEY_LEN) {
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
    return ok;
}

bool wallet_core_get_public_key(const wallet_core_path_t* const path, const wallet_core_pubkey_format_t format,
    uint8_t* const output, const size_t output_len)
{
    if (!wallet_core_is_unlocked() || !wallet_core_path_valid(path) || !output || output_len != (size_t)format) {
        return false;
    }

    if (format == WALLET_CORE_PUBKEY_COMPRESSED) {
        struct ext_key derived;
        WALLET_CORE_TRACE("wcore:pubc_hdkey");
        if (!wallet_get_hdkey(path->parts, path->len, BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH, &derived)) {
            WALLET_CORE_TRACE("wcore:pubc_fail");
            return false;
        }
        memcpy(output, derived.pub_key, output_len);
        JADE_WALLY_VERIFY(wally_bzero(&derived, sizeof(derived)));
        WALLET_CORE_TRACE("wcore:pubc_ok");
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
        return ok;
    }

    return false;
}

static uint32_t wallet_core_fingerprint_to_u32(const uint8_t fingerprint[BIP32_KEY_FINGERPRINT_LEN])
{
    return ((uint32_t)fingerprint[0] << 24) | ((uint32_t)fingerprint[1] << 16) | ((uint32_t)fingerprint[2] << 8)
        | (uint32_t)fingerprint[3];
}

bool wallet_core_get_public_node_with_version(
    const wallet_core_path_t* const path, const uint32_t bip32_public_version, wallet_core_public_node_t* const output)
{
    if (!wallet_core_is_unlocked() || !wallet_core_path_valid(path) || !output
        || (bip32_public_version != 0 && bip32_public_version != BIP32_VER_MAIN_PUBLIC
            && bip32_public_version != BIP32_VER_TEST_PUBLIC)) {
        return false;
    }

    struct ext_key derived;
    char* xpub = NULL;
    wally_bzero(output, sizeof(*output));

    bool ok = wallet_get_hdkey(path->parts, path->len, BIP32_FLAG_KEY_PUBLIC, &derived);
    if (ok && bip32_public_version != 0) {
        derived.version = bip32_public_version;
    }
    if (ok) {
        ok = bip32_key_to_base58(&derived, BIP32_FLAG_KEY_PUBLIC, &xpub) == WALLY_OK && xpub
            && strlen(xpub) < sizeof(output->xpub);
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
    return ok;
}

bool wallet_core_get_public_node(const wallet_core_path_t* const path, wallet_core_public_node_t* const output)
{
    return wallet_core_get_public_node_with_version(path, 0, output);
}

bool wallet_core_sign_digest_ecdsa_recoverable(const wallet_core_path_t* const path, const uint8_t* const digest,
    const size_t digest_len, uint8_t* const signature, const size_t signature_len)
{
    if (!wallet_core_is_unlocked() || !wallet_core_path_valid(path) || !digest || digest_len != SHA256_LEN || !signature
        || signature_len != EC_SIGNATURE_RECOVERABLE_LEN) {
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
    return ok;
}
