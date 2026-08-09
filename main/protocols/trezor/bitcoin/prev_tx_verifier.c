#ifndef AMALGAMATED_BUILD
#include "prev_tx_verifier.h"

#include <string.h>
#include <wally_crypto.h>
#include <wally_transaction.h>

void trezor_bitcoin_prev_tx_verifier_reset(trezor_bitcoin_prev_tx_verifier_t* const verifier)
{
    if (!verifier) {
        return;
    }
    if (verifier->tx) {
        wally_tx_free(verifier->tx);
    }
    wally_bzero(verifier, sizeof(*verifier));
}

bool trezor_bitcoin_prev_tx_verifier_init(trezor_bitcoin_prev_tx_verifier_t* const verifier,
    const trezor_bitcoin_transaction_t* const meta, const uint8_t* const expected_txid,
    const size_t expected_txid_len, const uint32_t prev_index)
{
    if (!verifier || !meta || !expected_txid || expected_txid_len != SHA256_LEN || meta->inputs_len != 0
        || meta->outputs_len != 0 || !meta->has_version || !meta->has_lock_time || !meta->has_inputs_cnt
        || !meta->has_outputs_cnt || meta->inputs_cnt == 0 || meta->outputs_cnt == 0
        || meta->inputs_cnt > TREZOR_BITCOIN_TX_INPUTS_MAX || meta->outputs_cnt > TREZOR_BITCOIN_TX_OUTPUTS_MAX
        || prev_index >= meta->outputs_cnt) {
        return false;
    }

    wally_bzero(verifier, sizeof(*verifier));
    struct wally_tx* tx = NULL;
    if (wally_tx_init_alloc(meta->version, meta->lock_time, meta->inputs_cnt, meta->outputs_cnt, &tx) != WALLY_OK
        || !tx) {
        return false;
    }

    verifier->tx = tx;
    verifier->initialized = true;
    memcpy(verifier->expected_txid, expected_txid, SHA256_LEN);
    verifier->inputs_count = meta->inputs_cnt;
    verifier->outputs_count = meta->outputs_cnt;
    verifier->prev_index = prev_index;
    return true;
}

bool trezor_bitcoin_prev_tx_verifier_apply_input(
    trezor_bitcoin_prev_tx_verifier_t* const verifier, const trezor_bitcoin_prev_input_t* const input)
{
    if (!verifier || !verifier->initialized || !verifier->tx || !input || !input->has_prev_hash
        || !input->has_prev_index || !input->has_script_sig || !input->has_sequence
        || input->script_sig_len > TREZOR_BITCOIN_PREV_SCRIPT_MAX_LEN || verifier->inputs_seen >= verifier->inputs_count
        || verifier->outputs_seen != 0) {
        return false;
    }

    if (wally_tx_add_raw_input(verifier->tx, input->prev_hash, sizeof(input->prev_hash), input->prev_index,
            input->sequence, input->script_sig, input->script_sig_len, NULL, 0)
        != WALLY_OK) {
        return false;
    }
    ++verifier->inputs_seen;
    return true;
}

bool trezor_bitcoin_prev_tx_verifier_apply_output(
    trezor_bitcoin_prev_tx_verifier_t* const verifier, const trezor_bitcoin_prev_output_t* const output)
{
    if (!verifier || !verifier->initialized || !verifier->tx || !output || !output->has_amount
        || !output->has_script_pubkey || output->script_pubkey_len == 0
        || output->script_pubkey_len > TREZOR_BITCOIN_PREV_SCRIPT_MAX_LEN
        || verifier->inputs_seen != verifier->inputs_count || verifier->outputs_seen >= verifier->outputs_count) {
        return false;
    }

    if (wally_tx_add_raw_output(verifier->tx, output->amount, output->script_pubkey, output->script_pubkey_len, 0)
        != WALLY_OK) {
        return false;
    }
    if (verifier->outputs_seen == verifier->prev_index) {
        verifier->prevout_amount = output->amount;
        memcpy(verifier->prevout_script, output->script_pubkey, output->script_pubkey_len);
        verifier->prevout_script_len = output->script_pubkey_len;
        verifier->has_prevout = true;
    }
    ++verifier->outputs_seen;
    return true;
}

bool trezor_bitcoin_prev_tx_verifier_finish(trezor_bitcoin_prev_tx_verifier_t* const verifier, uint64_t* const amount,
    uint8_t* const script_pubkey, const size_t script_pubkey_len, size_t* const script_pubkey_written)
{
    bool ok = false;
    uint8_t txid[SHA256_LEN];
    wally_bzero(txid, sizeof(txid));
    if (!verifier || !verifier->initialized || !verifier->tx || !amount || !script_pubkey || !script_pubkey_written
        || verifier->inputs_seen != verifier->inputs_count || verifier->outputs_seen != verifier->outputs_count
        || !verifier->has_prevout || verifier->prevout_script_len == 0
        || verifier->prevout_script_len > script_pubkey_len) {
        goto cleanup;
    }

    ok = wally_tx_get_txid(verifier->tx, txid, sizeof(txid)) == WALLY_OK
        && memcmp(txid, verifier->expected_txid, sizeof(txid)) == 0;
    if (ok) {
        *amount = verifier->prevout_amount;
        memcpy(script_pubkey, verifier->prevout_script, verifier->prevout_script_len);
        *script_pubkey_written = verifier->prevout_script_len;
    }

cleanup:
    if (!ok) {
        if (amount) {
            *amount = 0;
        }
        if (script_pubkey && script_pubkey_len) {
            wally_bzero(script_pubkey, script_pubkey_len);
        }
        if (script_pubkey_written) {
            *script_pubkey_written = 0;
        }
    }
    wally_bzero(txid, sizeof(txid));
    trezor_bitcoin_prev_tx_verifier_reset(verifier);
    return ok;
}
#endif /* AMALGAMATED_BUILD */
