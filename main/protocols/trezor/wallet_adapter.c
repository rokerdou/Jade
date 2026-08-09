#ifndef AMALGAMATED_BUILD
#include "wallet_adapter.h"

#ifdef CONFIG_TREZOR_USB_HID

#include "auth_bridge.h"
#include "public_key.h"
#include "trace.h"

#include "../../chains/bitcoin/confirm.h"
#include "../../chains/bitcoin/path.h"
#include "../../chains/bitcoin/wallet.h"
#include "../../chains/ethereum/address.h"
#include "../../chains/ethereum/path.h"
#include "../../chains/ethereum/sign.h"
#include "../../chains/ethereum/wallet.h"
#include "../../idletimer.h"
#include "../../ui/chain_confirm.h"
#include "../../wallet_core/wallet_core.h"

#include <string.h>
#include <wally_bip32.h>
#include <wally_crypto.h>

#define TREZOR_WALLET_ADAPTER_INTERACTIVE_TIMEOUT_SECS 600

bool show_confirm_address_activity(const char* address, bool default_selection);

static bool trezor_wallet_get_eth_address(
    void* ctx, const trezor_ethereum_get_address_t* const request, char* const address, const size_t address_len)
{
    (void)ctx;
    trezor_trace_set_stage("eth:req");
    if (!request || !address || address_len != ETHEREUM_CHECKSUM_ADDRESS_STRING_LEN
        || !trezor_auth_bridge_wallet_ready()
        || !ethereum_path_is_supported(request->address_n, request->address_n_len)) {
        trezor_trace_set_stage("eth:reject");
        return false;
    }

    trezor_trace_set_stage("eth:path");
    wallet_core_path_t path;
    memset(&path, 0, sizeof(path));
    path.len = request->address_n_len;
    memcpy(path.parts, request->address_n, request->address_n_len * sizeof(request->address_n[0]));

    trezor_trace_set_stage("eth:derive");
    uint8_t raw_address[ETHEREUM_ADDRESS_LEN];
    bool ok = ethereum_wallet_address_from_path(&path, raw_address, sizeof(raw_address));
    trezor_trace_set_stage(ok ? "eth:checksum" : "eth:derive_fail");
    ok = ok && ethereum_address_to_checksum_string(raw_address, sizeof(raw_address), address, address_len);
    wally_bzero(&path, sizeof(path));
    wally_bzero(raw_address, sizeof(raw_address));
    if (!ok) {
        trezor_trace_set_stage("eth:fail");
        return false;
    }

    trezor_trace_set_stage("eth:display");
    if (request->has_show_display && request->show_display) {
        idletimer_set_min_timeout_secs(TREZOR_WALLET_ADAPTER_INTERACTIVE_TIMEOUT_SECS);
        const bool accepted = show_confirm_address_activity(address, false);
        idletimer_set_min_timeout_secs(0);
        if (!accepted) {
            wally_bzero(address, address_len);
            trezor_trace_set_stage("eth:cancel");
            return false;
        }
    }
    trezor_trace_set_stage("eth:done");
    return true;
}

static bool trezor_wallet_get_bitcoin_address(
    void* ctx, const trezor_bitcoin_get_address_t* const request, char* const address, const size_t address_len)
{
    (void)ctx;
    if (!request || !address || !trezor_auth_bridge_wallet_ready() || !request->has_coin_name
        || (strcmp(request->coin_name, "Testnet") != 0 && strcmp(request->coin_name, "Bitcoin") != 0)
        || (request->has_script_type && request->script_type != BITCOIN_P2PKH_SPENDADDRESS
            && request->script_type != BITCOIN_P2WPKH_SPENDWITNESS
            && request->script_type != BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS)) {
        return false;
    }

    wallet_core_path_t path;
    memset(&path, 0, sizeof(path));
    path.len = request->address_n_len;
    memcpy(path.parts, request->address_n, request->address_n_len * sizeof(request->address_n[0]));

    const uint32_t script_type = request->has_script_type ? request->script_type : BITCOIN_P2PKH_SPENDADDRESS;
    const bool mainnet = strcmp(request->coin_name, "Bitcoin") == 0;
    bool ok = false;
    if (script_type == BITCOIN_P2PKH_SPENDADDRESS && !mainnet) {
        ok = bitcoin_wallet_p2pkh_testnet_address_from_path(&path, address, address_len);
    } else if (script_type == BITCOIN_P2WPKH_SPENDWITNESS) {
        ok = mainnet ? bitcoin_wallet_p2wpkh_mainnet_address_from_path(&path, address, address_len)
                     : bitcoin_wallet_p2wpkh_testnet_address_from_path(&path, address, address_len);
    } else if (script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS && !mainnet) {
        ok = bitcoin_wallet_p2sh_p2wpkh_testnet_address_from_path(&path, address, address_len);
    }
    wally_bzero(&path, sizeof(path));
    if (!ok) {
        wally_bzero(address, address_len);
        return false;
    }
    if (request->has_show_display && request->show_display) {
        idletimer_set_min_timeout_secs(TREZOR_WALLET_ADAPTER_INTERACTIVE_TIMEOUT_SECS);
        const bool accepted = show_confirm_address_activity(address, false);
        idletimer_set_min_timeout_secs(0);
        if (!accepted) {
            wally_bzero(address, address_len);
            return false;
        }
    }
    return true;
}

static bool trezor_wallet_get_public_key(
    void* ctx, const trezor_public_key_request_t* const request, trezor_public_key_response_t* const response)
{
    (void)ctx;
    const bool root_fingerprint_probe = trezor_public_key_is_root_fingerprint_probe(request);
    const bool supported_eth_public_node
        = request && ethereum_path_is_public_key_export_supported(request->address_n, request->address_n_len);
    const bool supported_btc_testnet_public_node = request && request->kind == TREZOR_PUBLIC_KEY_REQUEST_GENERIC
        && request->has_coin_name && strcmp(request->coin_name, "Testnet") == 0
        && (!request->has_script_type || request->script_type == BITCOIN_P2PKH_SPENDADDRESS)
        && bitcoin_path_is_testnet_p2pkh_account_public_node(request->address_n, request->address_n_len);
    if (!request || !response || !trezor_auth_bridge_wallet_ready()
        || (!root_fingerprint_probe && !supported_eth_public_node && !supported_btc_testnet_public_node)
        || (request->has_show_display && request->show_display)) {
        return false;
    }

    wallet_core_path_t path;
    memset(&path, 0, sizeof(path));
    path.len = request->address_n_len;
    memcpy(path.parts, request->address_n, request->address_n_len * sizeof(request->address_n[0]));

    wallet_core_public_node_t node;
    const uint32_t bip32_public_version = supported_btc_testnet_public_node ? BIP32_VER_TEST_PUBLIC : 0;
    bool ok = wallet_core_get_public_node_with_version(&path, bip32_public_version, &node);
    if (ok) {
        response->depth = node.depth;
        response->fingerprint = node.fingerprint;
        response->child_num = node.child_num;
        memcpy(response->chain_code, node.chain_code, sizeof(response->chain_code));
        memcpy(response->public_key, node.public_key, sizeof(response->public_key));
        memcpy(response->xpub, node.xpub, sizeof(response->xpub));
        response->root_fingerprint = node.root_fingerprint;
        response->has_root_fingerprint = true;
    }

    wally_bzero(&path, sizeof(path));
    wally_bzero(&node, sizeof(node));
    if (!ok) {
        wally_bzero(response, sizeof(*response));
    }
    return ok;
}

static bool trezor_wallet_sign_eth_tx(
    void* ctx, const ethereum_tx_preflight_request_t* const request, ethereum_signature_t* const signature)
{
    (void)ctx;
    if (!request || !signature || !trezor_auth_bridge_wallet_ready()) {
        trezor_trace_set_stage("ethsign:reject");
        return false;
    }
    trezor_trace_set_stage("ethsign:core");
    idletimer_set_min_timeout_secs(TREZOR_WALLET_ADAPTER_INTERACTIVE_TIMEOUT_SECS);
    const bool ok = ethereum_sign_tx(request, signature);
    idletimer_set_min_timeout_secs(0);
    trezor_trace_set_stage(ok ? "ethsign:core_ok" : "ethsign:core_fail");
    return ok;
}

static bool trezor_wallet_confirm_btc_tx(void* ctx, const bitcoin_confirm_request_t* const request)
{
    (void)ctx;
    if (!request || !trezor_auth_bridge_wallet_ready()) {
        trezor_trace_set_stage("btcsign:confirm_reject");
        return false;
    }

    chain_confirm_summary_t summary;
    if (!bitcoin_confirm_summary_from_request(request, &summary)) {
        trezor_trace_set_stage("btcsign:summary_fail");
        return false;
    }

    trezor_trace_set_stage("btcsign:display");
    idletimer_set_min_timeout_secs(TREZOR_WALLET_ADAPTER_INTERACTIVE_TIMEOUT_SECS);
    const bool ok = show_chain_confirm_summary_activity(&summary);
    idletimer_set_min_timeout_secs(0);
    trezor_trace_set_stage(ok ? "btcsign:display_ok" : "btcsign:display_cancel");
    return ok;
}

static bool trezor_wallet_sign_btc_digest(void* ctx, const wallet_core_path_t* const path, const uint8_t* const digest,
    const size_t digest_len, uint8_t* const signature, const size_t signature_len)
{
    (void)ctx;
    if (!path || !digest || !signature || !trezor_auth_bridge_wallet_ready()) {
        trezor_trace_set_stage("btcsign:sign_reject");
        return false;
    }

    trezor_trace_set_stage("btcsign:wallet_sign");
    const bool ok = wallet_core_sign_digest_ecdsa_recoverable(path, digest, digest_len, signature, signature_len);
    trezor_trace_set_stage(ok ? "btcsign:wallet_ok" : "btcsign:wallet_fail");
    return ok;
}

trezor_session_t trezor_wallet_adapter_session(const trezor_wallet_adapter_config_t* const config)
{
    const bool initialized = wallet_core_is_initialized();
    const bool ready = wallet_core_is_ready();
    const uint8_t* const session_id = config ? config->session_id : NULL;
    const size_t session_id_len = config ? config->session_id_len : 0;
    const bool has_session_id = session_id && session_id_len == TREZOR_FEATURES_SESSION_ID_LEN;

    trezor_session_t session = {
        .features = {
            // trezorlib accepts unknown/custom models only when the protocol vendor is one of
            // the official Trezor vendor strings. Keep the custom device identity in fw_vendor,
            // label, model, and internal_model instead of leaking it through the protocol vendor.
            .vendor = "trezor.io",
            .fw_vendor = "Jade T-Display-S3",
            .device_id = config ? config->device_id : NULL,
            .language = "en-US",
            .label = "Jade T-Display-S3",
            .model = "Jade",
            .internal_model = "UNKNOWN",
            .session_id = has_session_id ? session_id : NULL,
            .session_id_len = has_session_id ? session_id_len : 0,
            // Custom firmware compatibility version. Keep major 2 for the Core/WebUSB-style
            // host path, but do not claim conformance with any official Trezor 2.8.x release.
            .major_version = 2,
            .minor_version = 0,
            .patch_version = 0,
            .initialized = initialized,
            .has_unlocked = ready,
            .unlocked = ready,
            .pin_protection = initialized,
            .expose_private_fields = ready,
            .passphrase_protection = false,
            .capabilities = { TREZOR_CAPABILITY_BITCOIN, TREZOR_CAPABILITY_BITCOIN_LIKE, TREZOR_CAPABILITY_ETHEREUM },
            .capabilities_len = 3,
        },
        .state = config ? config->state : NULL,
        .initialize_session = config ? config->initialize_session : NULL,
        .initialize_session_ctx = config ? config->initialize_session_ctx : NULL,
        .needs_local_unlock = trezor_auth_bridge_needs_local_unlock,
        .needs_local_unlock_ctx = NULL,
        .perform_local_unlock = trezor_auth_bridge_perform_local_unlock,
        .perform_local_unlock_ctx = NULL,
        .get_bitcoin_address = trezor_wallet_get_bitcoin_address,
        .get_bitcoin_address_ctx = NULL,
        .get_eth_address = trezor_wallet_get_eth_address,
        .get_eth_address_ctx = NULL,
        .get_public_key = trezor_wallet_get_public_key,
        .get_public_key_ctx = NULL,
        .sign_eth_tx = trezor_wallet_sign_eth_tx,
        .sign_eth_tx_ctx = NULL,
        .confirm_btc_tx = trezor_wallet_confirm_btc_tx,
        .confirm_btc_tx_ctx = NULL,
        .sign_btc_digest = trezor_wallet_sign_btc_digest,
        .sign_btc_digest_ctx = NULL,
    };
    return session;
}

#endif /* CONFIG_TREZOR_USB_HID */
#endif /* AMALGAMATED_BUILD */
