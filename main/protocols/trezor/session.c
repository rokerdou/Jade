#ifndef AMALGAMATED_BUILD
#include "session.h"

#include "bitcoin.h"
#include "dispatcher.h"
#include "failure.h"
#include "messages.h"
#include "protobuf.h"
#include "public_key.h"
#include "trace.h"
#include "wire.h"

#include <string.h>
#include <wally_crypto.h>

static uint8_t s_trezor_session_request_payload[TREZOR_SESSION_MAX_REQUEST_PAYLOAD_LEN];
static uint8_t s_trezor_session_response_payload[TREZOR_SESSION_MAX_RESPONSE_PAYLOAD_LEN];
static uint8_t s_trezor_session_pending_payload[TREZOR_SESSION_MAX_REQUEST_PAYLOAD_LEN];

static bool trezor_session_handle_payload_ex(const trezor_session_t* session, uint16_t request_type,
    const uint8_t* request_payload, size_t request_payload_len, uint16_t* response_type, uint8_t* response_payload,
    size_t response_payload_len, size_t* response_payload_written, trezor_session_response_event_t* response_event);

static bool trezor_session_failure_payload(const trezor_failure_type_t code, const char* const message,
    uint16_t* const response_type, uint8_t* const response_payload, const size_t response_payload_len,
    size_t* const response_payload_written)
{
    if (!response_type) {
        return false;
    }

    *response_type = TREZOR_MSG_FAILURE;
    return trezor_failure_encode(code, message, response_payload, response_payload_len, response_payload_written);
}

static void trezor_session_clear_pending(trezor_session_state_t* const state)
{
    if (!state) {
        return;
    }
    wally_bzero(state, sizeof(*state));
}

static bool trezor_session_button_request_payload(const trezor_button_request_type_t code, const char* const name,
    uint16_t* const response_type, uint8_t* const response_payload, const size_t response_payload_len,
    size_t* const response_payload_written)
{
    if (!response_type || !response_payload || !response_payload_written || !name) {
        return false;
    }

    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, response_payload, response_payload_len);
    if (!trezor_protobuf_write_varint_field(&writer, 1, code)
        || !trezor_protobuf_write_string_field(&writer, 4, name)) {
        wally_bzero(response_payload, response_payload_len);
        return false;
    }

    *response_type = TREZOR_MSG_BUTTON_REQUEST;
    *response_payload_written = writer.len;
    return true;
}

static bool trezor_session_store_pending_local_unlock(const trezor_session_t* const session,
    const uint16_t request_type, const uint8_t* const request_payload, const size_t request_payload_len,
    uint16_t* const response_type, uint8_t* const response_payload, const size_t response_payload_len,
    size_t* const response_payload_written)
{
    if (!session || !session->state || !response_type || !response_payload || !response_payload_written
        || (!request_payload && request_payload_len) || request_payload_len > sizeof(session->state->pending_request_payload)) {
        return false;
    }

    if (!trezor_session_button_request_payload(TREZOR_BUTTON_REQUEST_PIN_ENTRY, "pin-entry", response_type,
            response_payload, response_payload_len, response_payload_written)) {
        return false;
    }

    trezor_trace_set_stage("unlock:defer");
    trezor_trace_set_note("unlock defer req=%u payload=%lu", (unsigned int)request_type, (unsigned long)request_payload_len);
    trezor_session_clear_pending(session->state);
    session->state->pending_request_type = request_type;
    session->state->pending_request_payload_len = request_payload_len;
    if (request_payload_len) {
        memcpy(session->state->pending_request_payload, request_payload, request_payload_len);
    }
    session->state->has_pending_local_unlock = true;
    return true;
}

static bool trezor_session_maybe_defer_for_local_unlock(const trezor_session_t* const session,
    const uint16_t request_type, const uint8_t* const request_payload, const size_t request_payload_len,
    uint16_t* const response_type, uint8_t* const response_payload, const size_t response_payload_len,
    size_t* const response_payload_written, bool* const deferred)
{
    if (!deferred) {
        return false;
    }
    *deferred = false;

    if (!session || !session->needs_local_unlock || !session->needs_local_unlock(session->needs_local_unlock_ctx)) {
        return true;
    }
    if (!session->state || !session->perform_local_unlock) {
        *deferred = true;
        return trezor_session_failure_payload(TREZOR_FAILURE_ACTION_CANCELLED, "Local unlock unavailable",
            response_type, response_payload, response_payload_len, response_payload_written);
    }

    *deferred = true;
    return trezor_session_store_pending_local_unlock(session, request_type, request_payload, request_payload_len,
        response_type, response_payload, response_payload_len, response_payload_written);
}

static bool trezor_session_handle_button_ack(const trezor_session_t* const session, const uint8_t* const request_payload,
    const size_t request_payload_len, uint16_t* const response_type, uint8_t* const response_payload,
    const size_t response_payload_len, size_t* const response_payload_written,
    trezor_session_response_event_t* const response_event)
{
    (void)request_payload;
    if (request_payload_len != 0) {
        return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Unexpected payload", response_type,
            response_payload, response_payload_len, response_payload_written);
    }
    if (!session || !session->state || !session->state->has_pending_local_unlock || !session->perform_local_unlock) {
        trezor_trace_set_stage("unlock:unexpected_ack");
        return trezor_session_failure_payload(TREZOR_FAILURE_UNEXPECTED_MESSAGE, "Button not expected", response_type,
            response_payload, response_payload_len, response_payload_written);
    }

    trezor_trace_set_stage("unlock:ack");
    const uint16_t pending_type = session->state->pending_request_type;
    uint8_t* const pending_payload = s_trezor_session_pending_payload;
    const size_t pending_payload_len = session->state->pending_request_payload_len;
    if (pending_payload_len > TREZOR_SESSION_MAX_REQUEST_PAYLOAD_LEN) {
        trezor_session_clear_pending(session->state);
        trezor_trace_set_stage("unlock:pending_big");
        return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Pending request too big", response_type,
            response_payload, response_payload_len, response_payload_written);
    }
    memcpy(pending_payload, session->state->pending_request_payload, pending_payload_len);
    trezor_session_clear_pending(session->state);

    trezor_trace_set_stage("unlock:perform");
    if (!session->perform_local_unlock(session->perform_local_unlock_ctx)) {
        wally_bzero(pending_payload, TREZOR_SESSION_MAX_REQUEST_PAYLOAD_LEN);
        trezor_trace_set_stage("unlock:rejected");
        return trezor_session_failure_payload(TREZOR_FAILURE_ACTION_CANCELLED, "Local unlock rejected", response_type,
            response_payload, response_payload_len, response_payload_written);
    }

    trezor_trace_set_stage("unlock:replay");
    const bool ok = trezor_session_handle_payload_ex(session, pending_type, pending_payload, pending_payload_len,
        response_type, response_payload, response_payload_len, response_payload_written, response_event);
    trezor_trace_set_stage(ok ? "unlock:replay_ok" : "unlock:replay_fail");
    wally_bzero(pending_payload, TREZOR_SESSION_MAX_REQUEST_PAYLOAD_LEN);
    return ok;
}

static bool trezor_session_bool_value(const uint8_t* const value, const size_t value_len)
{
    uint64_t raw = 0;
    return trezor_protobuf_read_varint_value(value, value_len, &raw) && raw <= 1;
}

static bool trezor_session_apply_flags_payload_is_noop(const uint8_t* const payload, const size_t payload_len)
{
    if (!payload_len) {
        return true;
    }
    if (!payload) {
        return false;
    }

    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    if (reader.len == 0) {
        return false;
    }

    while (reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        uint64_t flags = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)
            || field_number != 1 || wire_type != TREZOR_PROTOBUF_WIRE_VARINT
            || !trezor_protobuf_read_varint_value(value, value_len, &flags) || flags != 0) {
            return false;
        }
    }
    return true;
}

static bool trezor_session_initialize_payload_read_session_id(const uint8_t* const payload, const size_t payload_len,
    const uint8_t** const session_id, size_t* const session_id_len)
{
    if (!session_id || !session_id_len) {
        return false;
    }
    *session_id = NULL;
    *session_id_len = 0;

    if (!payload_len) {
        return true;
    }
    if (!payload) {
        return false;
    }

    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    if (reader.len == 0) {
        return false;
    }

    while (reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            return false;
        }

        if (field_number == 1) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || (value_len != 0 && value_len != TREZOR_FEATURES_SESSION_ID_LEN)) {
                return false;
            }
            *session_id = value;
            *session_id_len = value_len;
        } else if (field_number == 2 || field_number == 3) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT || !trezor_session_bool_value(value, value_len)) {
                return false;
            }
        }
    }

    return true;
}

static bool trezor_session_eth_signing_continue(const trezor_session_t* const session, uint16_t* const response_type,
    uint8_t* const response_payload, const size_t response_payload_len, size_t* const response_payload_written,
    trezor_session_response_event_t* const response_event)
{
    trezor_trace_set_stage("ethsign:cont");
    if (!session || !session->state || !response_type || !response_payload || !response_payload_written
        || !session->state->has_pending_eth_signing) {
        trezor_trace_set_stage("ethsign:no_pending");
        return trezor_session_failure_payload(TREZOR_FAILURE_UNEXPECTED_MESSAGE, "Ethereum signing not active",
            response_type, response_payload, response_payload_len, response_payload_written);
    }

    if (!trezor_ethereum_signing_state_ready(&session->state->pending_eth_signing)) {
        trezor_trace_set_stage("ethsign:need_data");
        *response_type = TREZOR_MSG_ETHEREUM_TX_REQUEST;
        return trezor_ethereum_tx_request_encode_data(session->state->pending_eth_signing.next_chunk_len,
            response_payload, response_payload_len, response_payload_written);
    }

    ethereum_tx_preflight_request_t request;
    ethereum_signature_t signature;
    wally_bzero(&request, sizeof(request));
    wally_bzero(&signature, sizeof(signature));

    trezor_trace_set_stage("ethsign:to_req");
    bool ok = session->sign_eth_tx && trezor_ethereum_signing_state_to_request(&session->state->pending_eth_signing, &request);
    trezor_trace_set_note("ethsign to_req ok=%u path_len=%lu data=%lu", ok ? 1 : 0, (unsigned long)request.path_len,
        (unsigned long)request.data_len);
    if (ok) {
        trezor_trace_set_stage("ethsign:sign");
        ok = session->sign_eth_tx(session->sign_eth_tx_ctx, &request, &signature);
    }
    trezor_trace_set_stage(ok ? "ethsign:signed" : "ethsign:sign_fail");

    session->state->has_pending_eth_signing = false;
    wally_bzero(&session->state->pending_eth_signing, sizeof(session->state->pending_eth_signing));
    wally_bzero(&request, sizeof(request));

    if (!ok) {
        wally_bzero(&signature, sizeof(signature));
        return trezor_session_failure_payload(TREZOR_FAILURE_ACTION_CANCELLED, "Ethereum signing rejected",
            response_type, response_payload, response_payload_len, response_payload_written);
    }

    *response_type = TREZOR_MSG_ETHEREUM_TX_REQUEST;
    trezor_trace_set_stage("ethsign:encode_sig");
    const bool encoded
        = trezor_ethereum_tx_request_encode_signature(&signature, response_payload, response_payload_len,
            response_payload_written);
    trezor_trace_set_note("ethsign encode_sig ok=%u out=%lu", encoded ? 1 : 0,
        (unsigned long)(response_payload_written ? *response_payload_written : 0));
    trezor_trace_set_stage(encoded ? "ethsign:encoded" : "ethsign:encode_fail");
    trezor_trace_checkpoint(encoded ? "ethsign:encoded" : "ethsign:encode_fail", "out=%lu",
        (unsigned long)(response_payload_written ? *response_payload_written : 0));
    if (encoded && response_event) {
        *response_event = TREZOR_SESSION_RESPONSE_EVENT_SIGNED_RESULT;
    }
    wally_bzero(&signature, sizeof(signature));
    return encoded;
}

static bool trezor_session_btc_signing_continue(const trezor_session_t* const session, uint16_t* const response_type,
    uint8_t* const response_payload, const size_t response_payload_len, size_t* const response_payload_written,
    trezor_session_response_event_t* const response_event)
{
    trezor_trace_set_stage("btcsign:cont");
    if (!session || !session->state || !response_type || !response_payload || !response_payload_written
        || !session->state->has_pending_btc_signing) {
        trezor_trace_set_stage("btcsign:no_pending");
        return trezor_session_failure_payload(TREZOR_FAILURE_UNEXPECTED_MESSAGE, "Bitcoin signing not active",
            response_type, response_payload, response_payload_len, response_payload_written);
    }

    if (trezor_bitcoin_signing_ready(&session->state->pending_btc_signing)) {
        bitcoin_confirm_request_t confirm_request;
        wally_bzero(&confirm_request, sizeof(confirm_request));
        const bool confirm_request_ok
            = trezor_bitcoin_signing_to_confirm_request(&session->state->pending_btc_signing, &confirm_request);
        trezor_trace_set_note("btc preflight inputs=%lu outputs=%lu fee=%llu",
            (unsigned long)session->state->pending_btc_signing.inputs_len,
            (unsigned long)session->state->pending_btc_signing.outputs_len,
            (unsigned long long)session->state->pending_btc_signing.fee);
        trezor_trace_set_stage(confirm_request_ok ? "btcsign:confirm" : "btcsign:confirm_req_fail");
        const bool confirmed = confirm_request_ok && session->confirm_btc_tx
            && session->confirm_btc_tx(session->confirm_btc_tx_ctx, &confirm_request);
        wally_bzero(&confirm_request, sizeof(confirm_request));
        if (!confirmed) {
            trezor_trace_set_stage("btcsign:confirm_cancel");
            wally_bzero(&session->state->pending_btc_signing, sizeof(session->state->pending_btc_signing));
            session->state->has_pending_btc_signing = false;
            return trezor_session_failure_payload(TREZOR_FAILURE_ACTION_CANCELLED, "Bitcoin transaction rejected",
                response_type, response_payload, response_payload_len, response_payload_written);
        }

        trezor_bitcoin_signed_tx_t signed_tx;
        uint8_t digest[SHA256_LEN];
        uint8_t compact_signature[EC_SIGNATURE_RECOVERABLE_LEN];
        wally_bzero(&signed_tx, sizeof(signed_tx));
        wally_bzero(digest, sizeof(digest));
        wally_bzero(compact_signature, sizeof(compact_signature));

        bool ok = session->sign_btc_digest && session->state->pending_btc_signing.inputs_len > 0
            && session->state->pending_btc_signing.inputs_len <= TREZOR_BITCOIN_TX_INPUTS_MAX;
        signed_tx.signatures_len = ok ? session->state->pending_btc_signing.inputs_len : 0;
        for (size_t i = 0; ok && i < signed_tx.signatures_len; ++i) {
            wallet_core_path_t signing_path;
            wally_bzero(&signing_path, sizeof(signing_path));
            ok = trezor_bitcoin_signing_build_p2wpkh_hash(
                &session->state->pending_btc_signing, i, &signing_path, digest, sizeof(digest));
            trezor_trace_set_stage(ok ? "btcsign:digest_ok" : "btcsign:digest_fail");
            ok = ok
                && session->sign_btc_digest(session->sign_btc_digest_ctx, &signing_path, digest, sizeof(digest),
                    compact_signature, sizeof(compact_signature));
            trezor_trace_set_stage(ok ? "btcsign:sign_ok" : "btcsign:sign_fail");
            ok = ok
                && wally_ec_sig_to_der(compact_signature + 1, EC_SIGNATURE_LEN, signed_tx.signatures[i].bytes,
                       EC_SIGNATURE_DER_MAX_LEN, &signed_tx.signatures[i].len)
                    == WALLY_OK
                && signed_tx.signatures[i].len < sizeof(signed_tx.signatures[i].bytes);
            if (ok) {
                signed_tx.signatures[i].bytes[signed_tx.signatures[i].len++] = 1U;
            }
            trezor_trace_set_stage(ok ? "btcsign:der_ok" : "btcsign:der_fail");
            wally_bzero(&signing_path, sizeof(signing_path));
            wally_bzero(digest, sizeof(digest));
            wally_bzero(compact_signature, sizeof(compact_signature));
        }
        ok = ok
            && trezor_bitcoin_signing_build_p2wpkh_signed_tx(&session->state->pending_btc_signing,
                signed_tx.signatures, signed_tx.signatures_len, signed_tx.serialized_tx,
                sizeof(signed_tx.serialized_tx), &signed_tx.serialized_tx_len);
        trezor_trace_set_stage(ok ? "btcsign:tx_ok" : "btcsign:tx_fail");
        *response_type = TREZOR_MSG_TX_REQUEST;
        ok = ok && trezor_bitcoin_signed_tx_encode_next(&signed_tx, response_payload, response_payload_len,
                       response_payload_written);
        const bool final_signed_response = ok && signed_tx.next_signature_index >= signed_tx.signatures_len;
        trezor_trace_set_stage(ok ? "btcsign:encoded" : "btcsign:encode_fail");

        wally_bzero(&session->state->pending_btc_signing, sizeof(session->state->pending_btc_signing));
        session->state->has_pending_btc_signing = false;
        if (!ok) {
            wally_bzero(&signed_tx, sizeof(signed_tx));
            return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Bitcoin signing unsupported",
                response_type, response_payload, response_payload_len, response_payload_written);
        }
        if (signed_tx.next_signature_index < signed_tx.signatures_len) {
            session->state->pending_btc_signed_tx = signed_tx;
            session->state->has_pending_btc_signed_tx = true;
        }
        if (final_signed_response && response_event) {
            *response_event = TREZOR_SESSION_RESPONSE_EVENT_SIGNED_RESULT;
        }
        wally_bzero(&signed_tx, sizeof(signed_tx));
        return true;
    }

    *response_type = TREZOR_MSG_TX_REQUEST;
    const bool ok = trezor_bitcoin_signing_encode_next_request(&session->state->pending_btc_signing, response_payload,
        response_payload_len, response_payload_written);
    trezor_trace_set_stage(ok ? "btcsign:req" : "btcsign:req_fail");
    return ok;
}

static bool trezor_session_btc_signed_tx_continue(const trezor_session_t* const session, uint16_t* const response_type,
    uint8_t* const response_payload, const size_t response_payload_len, size_t* const response_payload_written,
    trezor_session_response_event_t* const response_event)
{
    if (!session || !session->state || !session->state->has_pending_btc_signed_tx || !response_type
        || !response_payload || !response_payload_written) {
        return trezor_session_failure_payload(TREZOR_FAILURE_UNEXPECTED_MESSAGE, "Bitcoin signing not active",
            response_type, response_payload, response_payload_len, response_payload_written);
    }

    *response_type = TREZOR_MSG_TX_REQUEST;
    const bool ok = trezor_bitcoin_signed_tx_encode_next(
        &session->state->pending_btc_signed_tx, response_payload, response_payload_len, response_payload_written);
    trezor_trace_set_stage(ok ? "btcsign:emit" : "btcsign:emit_fail");
    const bool final_signed_response = ok && session->state->pending_btc_signed_tx.next_signature_index
        >= session->state->pending_btc_signed_tx.signatures_len;
    if (final_signed_response) {
        wally_bzero(&session->state->pending_btc_signed_tx, sizeof(session->state->pending_btc_signed_tx));
        session->state->has_pending_btc_signed_tx = false;
    }
    if (!ok) {
        trezor_session_clear_pending(session->state);
        return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Bitcoin signed response failed",
            response_type, response_payload, response_payload_len, response_payload_written);
    }
    if (final_signed_response && response_event) {
        *response_event = TREZOR_SESSION_RESPONSE_EVENT_SIGNED_RESULT;
    }
    return true;
}

static bool trezor_session_handle_payload_ex(const trezor_session_t* const session, const uint16_t request_type,
    const uint8_t* const request_payload, const size_t request_payload_len, uint16_t* const response_type,
    uint8_t* const response_payload, const size_t response_payload_len, size_t* const response_payload_written,
    trezor_session_response_event_t* const response_event)
{
    if (!session || !response_type || !response_payload || !response_payload_written
        || (!request_payload && request_payload_len) || request_payload_len > TREZOR_SESSION_MAX_REQUEST_PAYLOAD_LEN) {
        return false;
    }

    if (response_event) {
        *response_event = TREZOR_SESSION_RESPONSE_EVENT_NONE;
    }
    *response_payload_written = 0;
    if (!trezor_dispatcher_message_allowed(request_type)) {
        return trezor_session_failure_payload(TREZOR_FAILURE_UNEXPECTED_MESSAGE, "Unsupported message", response_type,
            response_payload, response_payload_len, response_payload_written);
    }

    if (request_type == TREZOR_MSG_INITIALIZE || request_type == TREZOR_MSG_GET_FEATURES) {
        const uint8_t* initialize_session_id = NULL;
        size_t initialize_session_id_len = 0;
        if ((request_type == TREZOR_MSG_GET_FEATURES && request_payload_len != 0)
            || (request_type == TREZOR_MSG_INITIALIZE
                && !trezor_session_initialize_payload_read_session_id(
                    request_payload, request_payload_len, &initialize_session_id, &initialize_session_id_len))) {
            return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Unexpected payload", response_type,
                response_payload, response_payload_len, response_payload_written);
        }

        if (request_type == TREZOR_MSG_INITIALIZE) {
            trezor_session_clear_pending(session->state);
            if (session->initialize_session
                && !session->initialize_session(
                    session->initialize_session_ctx, initialize_session_id, initialize_session_id_len)) {
                return trezor_session_failure_payload(TREZOR_FAILURE_INVALID_SESSION, "Invalid session", response_type,
                    response_payload, response_payload_len, response_payload_written);
            }
        }
        *response_type = TREZOR_MSG_FEATURES;
        return trezor_features_encode(
            &session->features, response_payload, response_payload_len, response_payload_written);
    }

    if (request_type == TREZOR_MSG_CANCEL) {
        if (request_payload_len != 0) {
            return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Unexpected payload", response_type,
                response_payload, response_payload_len, response_payload_written);
        }
        trezor_session_clear_pending(session->state);
        return trezor_session_failure_payload(TREZOR_FAILURE_ACTION_CANCELLED, "Action cancelled", response_type,
            response_payload, response_payload_len, response_payload_written);
    }

    if (request_type == TREZOR_MSG_END_SESSION) {
        if (request_payload_len != 0) {
            return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Unexpected payload", response_type,
                response_payload, response_payload_len, response_payload_written);
        }
        trezor_session_clear_pending(session->state);
        *response_type = TREZOR_MSG_SUCCESS;
        *response_payload_written = 0;
        return true;
    }

    if (request_type == TREZOR_MSG_APPLY_FLAGS) {
        if (!trezor_session_apply_flags_payload_is_noop(request_payload, request_payload_len)) {
            return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Unsupported flags", response_type,
                response_payload, response_payload_len, response_payload_written);
        }
        *response_type = TREZOR_MSG_SUCCESS;
        *response_payload_written = 0;
        return true;
    }

    if (request_type == TREZOR_MSG_BUTTON_ACK) {
        return trezor_session_handle_button_ack(session, request_payload, request_payload_len, response_type,
            response_payload, response_payload_len, response_payload_written, response_event);
    }

    if (request_type == TREZOR_MSG_GET_ADDRESS) {
        trezor_bitcoin_get_address_t request;
        if (!session->get_bitcoin_address
            || !trezor_bitcoin_get_address_decode(request_payload, request_payload_len, &request)) {
            return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Invalid Bitcoin address request",
                response_type, response_payload, response_payload_len, response_payload_written);
        }

        bool deferred = false;
        if (!trezor_session_maybe_defer_for_local_unlock(session, request_type, request_payload, request_payload_len,
                response_type, response_payload, response_payload_len, response_payload_written, &deferred)) {
            wally_bzero(&request, sizeof(request));
            return false;
        }
        if (deferred) {
            wally_bzero(&request, sizeof(request));
            return true;
        }

        char address[TREZOR_SESSION_BITCOIN_ADDRESS_STRING_LEN];
        memset(address, 0, sizeof(address));
        if (!session->get_bitcoin_address(session->get_bitcoin_address_ctx, &request, address, sizeof(address))) {
            wally_bzero(&request, sizeof(request));
            wally_bzero(address, sizeof(address));
            return trezor_session_failure_payload(TREZOR_FAILURE_ACTION_CANCELLED, "Address request rejected",
                response_type, response_payload, response_payload_len, response_payload_written);
        }

        *response_type = TREZOR_MSG_ADDRESS;
        const bool ok
            = trezor_bitcoin_address_encode(address, response_payload, response_payload_len, response_payload_written);
        wally_bzero(&request, sizeof(request));
        wally_bzero(address, sizeof(address));
        return ok;
    }

    if (request_type == TREZOR_MSG_ETHEREUM_GET_ADDRESS) {
        trezor_ethereum_get_address_t request;
        trezor_trace_set_stage("eth:decode");
        if (!session->get_eth_address
            || !trezor_ethereum_get_address_decode(request_payload, request_payload_len, &request)) {
            trezor_trace_set_stage("eth:decode_fail");
            return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Invalid Ethereum address request",
                response_type, response_payload, response_payload_len, response_payload_written);
        }
        trezor_trace_set_stage("eth:decoded");

        bool deferred = false;
        if (!trezor_session_maybe_defer_for_local_unlock(session, request_type, request_payload, request_payload_len,
                response_type, response_payload, response_payload_len, response_payload_written, &deferred)) {
            wally_bzero(&request, sizeof(request));
            return false;
        }
        if (deferred) {
            wally_bzero(&request, sizeof(request));
            return true;
        }

        char address[TREZOR_SESSION_ETH_ADDRESS_STRING_LEN];
        memset(address, 0, sizeof(address));
        if (!session->get_eth_address(session->get_eth_address_ctx, &request, address, sizeof(address))) {
            wally_bzero(&request, sizeof(request));
            wally_bzero(address, sizeof(address));
            return trezor_session_failure_payload(TREZOR_FAILURE_ACTION_CANCELLED, "Address request rejected",
                response_type, response_payload, response_payload_len, response_payload_written);
        }

        *response_type = TREZOR_MSG_ETHEREUM_ADDRESS;
        const bool ok
            = trezor_ethereum_address_encode(address, response_payload, response_payload_len, response_payload_written);
        wally_bzero(&request, sizeof(request));
        wally_bzero(address, sizeof(address));
        return ok;
    }

    if (request_type == TREZOR_MSG_ETHEREUM_SIGN_TX || request_type == TREZOR_MSG_ETHEREUM_SIGN_TX_EIP1559) {
        trezor_trace_set_stage("ethsign:init");
        if (!session->state || !session->sign_eth_tx) {
            return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Invalid Ethereum signing request",
                response_type, response_payload, response_payload_len, response_payload_written);
        }

        session->state->has_pending_eth_signing = false;
        wally_bzero(&session->state->pending_eth_signing, sizeof(session->state->pending_eth_signing));
        if (!trezor_ethereum_sign_tx_init(
                &session->state->pending_eth_signing, request_type, request_payload, request_payload_len)) {
            trezor_trace_set_stage("ethsign:init_fail");
            return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Invalid Ethereum signing request",
                response_type, response_payload, response_payload_len, response_payload_written);
        }
        trezor_trace_set_stage("ethsign:inited");

        bool deferred = false;
        if (!trezor_session_maybe_defer_for_local_unlock(session, request_type, request_payload, request_payload_len,
                response_type, response_payload, response_payload_len, response_payload_written, &deferred)) {
            wally_bzero(&session->state->pending_eth_signing, sizeof(session->state->pending_eth_signing));
            return false;
        }
        if (deferred) {
            wally_bzero(&session->state->pending_eth_signing, sizeof(session->state->pending_eth_signing));
            return true;
        }

        session->state->has_pending_eth_signing = true;
        trezor_trace_set_stage("ethsign:continue");
        return trezor_session_eth_signing_continue(
            session, response_type, response_payload, response_payload_len, response_payload_written, response_event);
    }

    if (request_type == TREZOR_MSG_ETHEREUM_TX_ACK) {
        if (!session->state || !session->state->has_pending_eth_signing
            || !trezor_ethereum_tx_ack_apply(
                &session->state->pending_eth_signing, request_payload, request_payload_len)) {
            trezor_session_clear_pending(session->state);
            return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Invalid Ethereum data chunk",
                response_type, response_payload, response_payload_len, response_payload_written);
        }
        return trezor_session_eth_signing_continue(
            session, response_type, response_payload, response_payload_len, response_payload_written, response_event);
    }

    if (request_type == TREZOR_MSG_SIGN_TX) {
        trezor_trace_set_stage("btcsign:init");
        if (!session->state) {
            return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Invalid Bitcoin signing request",
                response_type, response_payload, response_payload_len, response_payload_written);
        }

        session->state->has_pending_btc_signing = false;
        wally_bzero(&session->state->pending_btc_signing, sizeof(session->state->pending_btc_signing));
        if (!trezor_bitcoin_signing_init(&session->state->pending_btc_signing, request_payload, request_payload_len)) {
            trezor_trace_set_stage("btcsign:init_fail");
            return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Invalid Bitcoin signing request",
                response_type, response_payload, response_payload_len, response_payload_written);
        }
        trezor_trace_set_stage("btcsign:inited");

        bool deferred = false;
        if (!trezor_session_maybe_defer_for_local_unlock(session, request_type, request_payload, request_payload_len,
                response_type, response_payload, response_payload_len, response_payload_written, &deferred)) {
            wally_bzero(&session->state->pending_btc_signing, sizeof(session->state->pending_btc_signing));
            return false;
        }
        if (deferred) {
            wally_bzero(&session->state->pending_btc_signing, sizeof(session->state->pending_btc_signing));
            return true;
        }

        session->state->has_pending_btc_signing = true;
        return trezor_session_btc_signing_continue(
            session, response_type, response_payload, response_payload_len, response_payload_written, response_event);
    }

    if (request_type == TREZOR_MSG_TX_ACK) {
        trezor_trace_set_stage("btcsign:ack");
        if (session->state && session->state->has_pending_btc_signed_tx) {
            trezor_bitcoin_transaction_t discard_tx_ack;
            if (!trezor_bitcoin_tx_ack_decode(request_payload, request_payload_len, &discard_tx_ack)) {
                trezor_session_clear_pending(session->state);
                trezor_trace_set_stage("btcsign:emit_ack_fail");
                return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Invalid Bitcoin transaction data",
                    response_type, response_payload, response_payload_len, response_payload_written);
            }
            wally_bzero(&discard_tx_ack, sizeof(discard_tx_ack));
            return trezor_session_btc_signed_tx_continue(
                session, response_type, response_payload, response_payload_len, response_payload_written,
                response_event);
        }
        if (!session->state || !session->state->has_pending_btc_signing
            || !trezor_bitcoin_signing_apply_tx_ack(
                &session->state->pending_btc_signing, request_payload, request_payload_len)) {
            trezor_session_clear_pending(session->state);
            trezor_trace_set_stage("btcsign:ack_fail");
            return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Invalid Bitcoin transaction data",
                response_type, response_payload, response_payload_len, response_payload_written);
        }
        return trezor_session_btc_signing_continue(
            session, response_type, response_payload, response_payload_len, response_payload_written, response_event);
    }

    if (request_type == TREZOR_MSG_GET_PUBLIC_KEY || request_type == TREZOR_MSG_ETHEREUM_GET_PUBLIC_KEY) {
        trezor_public_key_request_t request;
        const bool decoded = request_type == TREZOR_MSG_GET_PUBLIC_KEY
            ? trezor_public_key_decode_generic(request_payload, request_payload_len, &request)
            : trezor_public_key_decode_ethereum(request_payload, request_payload_len, &request);
        if (!session->get_public_key || !decoded) {
            return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Invalid public key request",
                response_type, response_payload, response_payload_len, response_payload_written);
        }

        bool deferred = false;
        if (!trezor_session_maybe_defer_for_local_unlock(session, request_type, request_payload, request_payload_len,
                response_type, response_payload, response_payload_len, response_payload_written, &deferred)) {
            wally_bzero(&request, sizeof(request));
            return false;
        }
        if (deferred) {
            wally_bzero(&request, sizeof(request));
            return true;
        }

        trezor_public_key_response_t public_key;
        wally_bzero(&public_key, sizeof(public_key));
        if (!session->get_public_key(session->get_public_key_ctx, &request, &public_key)) {
            wally_bzero(&request, sizeof(request));
            wally_bzero(&public_key, sizeof(public_key));
            return trezor_session_failure_payload(TREZOR_FAILURE_ACTION_CANCELLED, "Public key request rejected",
                response_type, response_payload, response_payload_len, response_payload_written);
        }

        *response_type = request_type == TREZOR_MSG_GET_PUBLIC_KEY ? TREZOR_MSG_PUBLIC_KEY : TREZOR_MSG_ETHEREUM_PUBLIC_KEY;
        const bool ok = request_type == TREZOR_MSG_GET_PUBLIC_KEY
            ? trezor_public_key_encode_generic(&public_key, response_payload, response_payload_len,
                  response_payload_written)
            : trezor_public_key_encode_ethereum(&public_key, response_payload, response_payload_len,
                  response_payload_written);
        wally_bzero(&request, sizeof(request));
        wally_bzero(&public_key, sizeof(public_key));
        return ok;
    }

    return trezor_session_failure_payload(TREZOR_FAILURE_UNEXPECTED_MESSAGE, "Unsupported message", response_type,
        response_payload, response_payload_len, response_payload_written);
}

bool trezor_session_handle_payload(const trezor_session_t* const session, const uint16_t request_type,
    const uint8_t* const request_payload, const size_t request_payload_len, uint16_t* const response_type,
    uint8_t* const response_payload, const size_t response_payload_len, size_t* const response_payload_written)
{
    return trezor_session_handle_payload_ex(session, request_type, request_payload, request_payload_len, response_type,
        response_payload, response_payload_len, response_payload_written, NULL);
}

bool trezor_session_handle_wire_ex(const trezor_session_t* const session, const uint8_t* const request_chunks,
    const size_t request_chunks_len, uint8_t* const response_chunks, const size_t response_chunks_len,
    size_t* const response_chunks_written, trezor_session_response_event_t* const response_event)
{
    if (!response_chunks || !response_chunks_written) {
        return false;
    }

    if (response_event) {
        *response_event = TREZOR_SESSION_RESPONSE_EVENT_NONE;
    }
    uint16_t request_type = 0;
    uint8_t* const request_payload = s_trezor_session_request_payload;
    size_t request_payload_len = 0;
    uint8_t* const response_payload = s_trezor_session_response_payload;
    size_t response_payload_len = 0;
    uint16_t response_type = TREZOR_MSG_FAILURE;
    bool wire_ok = false;

    bool ok = false;
    trezor_trace_set_stage("wire:decode");
    if (trezor_wire_decode_message(request_chunks, request_chunks_len, &request_type, request_payload,
            TREZOR_SESSION_MAX_REQUEST_PAYLOAD_LEN, &request_payload_len)) {
        wire_ok = true;
        trezor_trace_set_note("wire req=%u payload=%lu", (unsigned int)request_type, (unsigned long)request_payload_len);
        trezor_trace_set_stage("wire:trace_start");
        trezor_trace_record_request_start(request_type, request_payload, request_payload_len);
        trezor_trace_set_stage("wire:payload");
        ok = trezor_session_handle_payload_ex(session, request_type, request_payload, request_payload_len,
            &response_type, response_payload, TREZOR_SESSION_MAX_RESPONSE_PAYLOAD_LEN, &response_payload_len,
            response_event);
        trezor_trace_set_note("wire handled ok=%u resp=%u payload=%lu", ok ? 1 : 0, (unsigned int)response_type,
            (unsigned long)response_payload_len);
        trezor_trace_set_stage(ok ? "wire:handled_ok" : "wire:handled_fail");
    } else {
        trezor_trace_set_stage("wire:decode_fail");
        ok = trezor_session_failure_payload(TREZOR_FAILURE_INVALID_PROTOCOL, "Invalid wire message", &response_type,
            response_payload, TREZOR_SESSION_MAX_RESPONSE_PAYLOAD_LEN, &response_payload_len);
    }

    trezor_trace_record_exchange(request_type, request_payload, request_payload_len, response_type, response_payload,
        response_payload_len, wire_ok, ok);

    wally_bzero(request_payload, TREZOR_SESSION_MAX_REQUEST_PAYLOAD_LEN);
    if (!ok) {
        wally_bzero(response_payload, TREZOR_SESSION_MAX_RESPONSE_PAYLOAD_LEN);
        return false;
    }

    ok = trezor_wire_encode_message(response_type, response_payload, response_payload_len, response_chunks,
        response_chunks_len, response_chunks_written);
    trezor_trace_set_note("wire encode ok=%u resp=%u chunks=%lu", ok ? 1 : 0, (unsigned int)response_type,
        (unsigned long)(response_chunks_written ? *response_chunks_written : 0));
    trezor_trace_set_stage(ok ? "wire:encode_ok" : "wire:encode_fail");
    if (response_event && *response_event == TREZOR_SESSION_RESPONSE_EVENT_SIGNED_RESULT) {
        trezor_trace_checkpoint(ok ? "wire:encode_ok" : "wire:encode_fail", "resp=%u payload=%lu chunks=%lu",
            (unsigned int)response_type, (unsigned long)response_payload_len,
            (unsigned long)(response_chunks_written ? *response_chunks_written : 0));
    }
    wally_bzero(response_payload, TREZOR_SESSION_MAX_RESPONSE_PAYLOAD_LEN);
    return ok;
}

bool trezor_session_handle_wire(const trezor_session_t* const session, const uint8_t* const request_chunks,
    const size_t request_chunks_len, uint8_t* const response_chunks, const size_t response_chunks_len,
    size_t* const response_chunks_written)
{
    return trezor_session_handle_wire_ex(
        session, request_chunks, request_chunks_len, response_chunks, response_chunks_len, response_chunks_written, NULL);
}
#endif /* AMALGAMATED_BUILD */
