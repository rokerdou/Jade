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
    const size_t response_payload_len, size_t* const response_payload_written)
{
    (void)request_payload;
    if (request_payload_len != 0) {
        return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Unexpected payload", response_type,
            response_payload, response_payload_len, response_payload_written);
    }
    if (!session || !session->state || !session->state->has_pending_local_unlock || !session->perform_local_unlock) {
        return trezor_session_failure_payload(TREZOR_FAILURE_UNEXPECTED_MESSAGE, "Button not expected", response_type,
            response_payload, response_payload_len, response_payload_written);
    }

    const uint16_t pending_type = session->state->pending_request_type;
    uint8_t pending_payload[TREZOR_SESSION_MAX_REQUEST_PAYLOAD_LEN];
    const size_t pending_payload_len = session->state->pending_request_payload_len;
    if (pending_payload_len > sizeof(pending_payload)) {
        trezor_session_clear_pending(session->state);
        return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Pending request too big", response_type,
            response_payload, response_payload_len, response_payload_written);
    }
    memcpy(pending_payload, session->state->pending_request_payload, pending_payload_len);
    trezor_session_clear_pending(session->state);

    if (!session->perform_local_unlock(session->perform_local_unlock_ctx)) {
        wally_bzero(pending_payload, sizeof(pending_payload));
        return trezor_session_failure_payload(TREZOR_FAILURE_ACTION_CANCELLED, "Local unlock rejected", response_type,
            response_payload, response_payload_len, response_payload_written);
    }

    const bool ok = trezor_session_handle_payload(session, pending_type, pending_payload, pending_payload_len,
        response_type, response_payload, response_payload_len, response_payload_written);
    wally_bzero(pending_payload, sizeof(pending_payload));
    return ok;
}

static bool trezor_session_bool_value(const uint8_t* const value, const size_t value_len)
{
    uint64_t raw = 0;
    return trezor_protobuf_read_varint_value(value, value_len, &raw) && raw <= 1;
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

bool trezor_session_handle_payload(const trezor_session_t* const session, const uint16_t request_type,
    const uint8_t* const request_payload, const size_t request_payload_len, uint16_t* const response_type,
    uint8_t* const response_payload, const size_t response_payload_len, size_t* const response_payload_written)
{
    if (!session || !response_type || !response_payload || !response_payload_written
        || (!request_payload && request_payload_len) || request_payload_len > TREZOR_SESSION_MAX_REQUEST_PAYLOAD_LEN) {
        return false;
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

    if (request_type == TREZOR_MSG_BUTTON_ACK) {
        return trezor_session_handle_button_ack(session, request_payload, request_payload_len, response_type,
            response_payload, response_payload_len, response_payload_written);
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
        if (!session->get_eth_address
            || !trezor_ethereum_get_address_decode(request_payload, request_payload_len, &request)) {
            return trezor_session_failure_payload(TREZOR_FAILURE_DATA_ERROR, "Invalid Ethereum address request",
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

bool trezor_session_handle_wire(const trezor_session_t* const session, const uint8_t* const request_chunks,
    const size_t request_chunks_len, uint8_t* const response_chunks, const size_t response_chunks_len,
    size_t* const response_chunks_written)
{
    if (!response_chunks || !response_chunks_written) {
        return false;
    }

    uint16_t request_type = 0;
    uint8_t request_payload[TREZOR_SESSION_MAX_REQUEST_PAYLOAD_LEN];
    size_t request_payload_len = 0;
    uint8_t response_payload[TREZOR_SESSION_MAX_RESPONSE_PAYLOAD_LEN];
    size_t response_payload_len = 0;
    uint16_t response_type = TREZOR_MSG_FAILURE;
    bool wire_ok = false;

    bool ok = false;
    if (trezor_wire_decode_message(request_chunks, request_chunks_len, &request_type, request_payload,
            sizeof(request_payload), &request_payload_len)) {
        wire_ok = true;
        trezor_trace_record_request_start(request_type, request_payload, request_payload_len);
        ok = trezor_session_handle_payload(session, request_type, request_payload, request_payload_len, &response_type,
            response_payload, sizeof(response_payload), &response_payload_len);
    } else {
        ok = trezor_session_failure_payload(TREZOR_FAILURE_INVALID_PROTOCOL, "Invalid wire message", &response_type,
            response_payload, sizeof(response_payload), &response_payload_len);
    }

    trezor_trace_record_exchange(request_type, request_payload, request_payload_len, response_type, response_payload,
        response_payload_len, wire_ok, ok);

    wally_bzero(request_payload, sizeof(request_payload));
    if (!ok) {
        wally_bzero(response_payload, sizeof(response_payload));
        return false;
    }

    ok = trezor_wire_encode_message(response_type, response_payload, response_payload_len, response_chunks,
        response_chunks_len, response_chunks_written);
    wally_bzero(response_payload, sizeof(response_payload));
    return ok;
}
#endif /* AMALGAMATED_BUILD */
