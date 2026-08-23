// Fuzz harness for the Trezor protocol parsing stack.
// Business sources are compiled unmodified; this file only drives the
// externally-reachable decode entry points with attacker-controlled bytes.
// Target selection: data[0] % NUM_TARGETS selects the entry point, the rest
// of the input is the payload. Output structs are heap-allocated so ASAN
// redzones guard every overflow past struct ends.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "protocols/trezor/protobuf.h"
#include "protocols/trezor/wire.h"
#include "protocols/trezor/bitcoin/messages.h"
#include "protocols/trezor/bitcoin/multisig.h"
#include "protocols/trezor/ethereum/protocol.h"
#include "protocols/trezor/ethereum/safe_normalizer.h"
#include "protocols/trezor/ethereum/definitions.h"

#define NUM_TARGETS 13

static void* checked_malloc(const size_t len)
{
    // malloc(0) is implementation-defined; always allocate at least 1 byte
    void* const p = malloc(len ? len : 1);
    if (!p) {
        abort();
    }
    memset(p, 0, len ? len : 1);
    return p;
}

// Structure-aware generator: interpret the fuzz bytes as a sequence of write
// instructions and emit a well-formed protobuf stream via the real writer.
// This reaches deep parse paths that random bytes cannot (they fail early
// validation). Used for roughly half the decode-target executions.
static uint8_t g_built[8192];

static size_t build_protobuf(const uint8_t* const spec, const size_t spec_len)
{
    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, g_built, sizeof(g_built));

    size_t i = 0;
    while (i + 2 <= spec_len && writer.len + 64 < sizeof(g_built)) {
        const uint8_t selector = spec[i++];
        const uint32_t field = 1 + (uint32_t)(selector % 24);
        if (selector & 0x80) {
            uint64_t value = 0;
            for (int k = 0; k < 8 && i < spec_len; ++k) {
                value |= ((uint64_t)spec[i++]) << (8 * k);
            }
            if (!trezor_protobuf_write_varint_field(&writer, field, value)) {
                break;
            }
        } else {
            const uint8_t content_len = spec[i++] % 40;
            if (i + content_len > spec_len) {
                break;
            }
            if (!trezor_protobuf_write_bytes_field(&writer, field, spec + i, content_len)) {
                break;
            }
            i += content_len;
        }
    }
    return writer.len;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, const size_t size)
{
    if (size < 3) {
        return 0;
    }

    const uint8_t target = data[0] % NUM_TARGETS;
    const uint8_t* payload = data + 1;
    size_t payload_len = size - 1;

    // For decode targets: alternate between raw fuzz bytes (malformed paths)
    // and writer-generated well-formed streams (deep parse paths).
    if (target >= 3 && (payload[0] & 1)) {
        const size_t built_len = build_protobuf(payload + 1, payload_len - 1);
        if (built_len) {
            payload = g_built;
            payload_len = built_len;
        }
    }

    switch (target) {
    case 0: {
        // Raw protobuf reader drain
        trezor_protobuf_reader_t reader;
        trezor_protobuf_reader_init(&reader, payload, payload_len);
        for (;;) {
            uint32_t field_number = 0;
            uint8_t wire_type = 0;
            const uint8_t* value = NULL;
            size_t value_len = 0;
            if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
                break;
            }
        }
        break;
    }
    case 1: {
        // Wire roundtrip: encode (fuzz type, fuzz payload) then decode into a
        // heap buffer sized exactly to the declared payload length.
        const uint16_t message_type = (uint16_t)(((uint16_t)payload[0] << 8) | payload[1]);
        const uint8_t* body = payload + 2;
        const size_t body_len = payload_len - 2;

        size_t encoded_len = 0;
        if (!trezor_wire_encoded_len(body_len, &encoded_len)) {
            break;
        }
        uint8_t* const encoded = checked_malloc(encoded_len);
        size_t written = 0;
        if (trezor_wire_encode_message(message_type, body, body_len, encoded, encoded_len, &written)) {
            uint16_t decoded_type = 0;
            size_t decoded_len = 0;
            uint8_t* const out = checked_malloc(body_len);
            (void)trezor_wire_decode_message(
                encoded, written, &decoded_type, out, body_len, &decoded_len);
            free(out);
        }
        free(encoded);
        break;
    }
    case 2: {
        // Unframed garbage straight into wire decode (bad-wire path)
        uint16_t decoded_type = 0;
        size_t decoded_len = 0;
        uint8_t* const out = checked_malloc(payload_len);
        (void)trezor_wire_decode_message(payload, payload_len, &decoded_type, out, payload_len, &decoded_len);
        free(out);
        break;
    }
    case 3: {
        trezor_bitcoin_get_address_t* const output = checked_malloc(sizeof(*output));
        (void)trezor_bitcoin_get_address_decode(payload, payload_len, output);
        free(output);
        break;
    }
    case 4: {
        trezor_bitcoin_sign_tx_t* const output = checked_malloc(sizeof(*output));
        (void)trezor_bitcoin_sign_tx_decode(payload, payload_len, output);
        free(output);
        break;
    }
    case 5: {
        trezor_bitcoin_transaction_t* const output = checked_malloc(sizeof(*output));
        (void)trezor_bitcoin_tx_ack_decode(payload, payload_len, output);
        free(output);
        break;
    }
    case 6: {
        trezor_bitcoin_transaction_t* const output = checked_malloc(sizeof(*output));
        trezor_bitcoin_tx_ack_multisig_fingerprints_t* const fingerprints
            = checked_malloc(sizeof(*fingerprints));
        (void)trezor_bitcoin_tx_ack_decode_with_multisig_fingerprints(payload, payload_len, output, fingerprints);
        trezor_bitcoin_tx_ack_multisig_fingerprints_clear(fingerprints);
        trezor_bitcoin_tx_ack_multisig_fingerprints_clear(fingerprints);
        free(fingerprints);
        free(output);
        break;
    }
    case 7: {
        trezor_bitcoin_prev_input_t* const prev_input = checked_malloc(sizeof(*prev_input));
        (void)trezor_bitcoin_prev_input_decode(payload, payload_len, prev_input);
        free(prev_input);

        trezor_bitcoin_prev_output_t* const prev_output = checked_malloc(sizeof(*prev_output));
        (void)trezor_bitcoin_prev_output_decode(payload, payload_len, prev_output);
        free(prev_output);
        break;
    }
    case 8: {
        trezor_bitcoin_multisig_t* const output = checked_malloc(sizeof(*output));
        if (trezor_bitcoin_multisig_decode(payload, payload_len, output)) {
            // Exercise the post-parse helpers on the decoded result
            uint8_t fingerprint[SHA256_LEN];
            (void)trezor_bitcoin_multisig_fingerprint(output, fingerprint);

            trezor_bitcoin_multisig_policy_t* const policy = checked_malloc(sizeof(*policy));
            if (trezor_bitcoin_multisig_normalize(output, 0, policy)) {
                (void)trezor_bitcoin_multisig_policy_contains_pubkey(
                    policy, output->nodes_len ? output->nodes[0].public_key : output->pubkeys[0].node.public_key,
                    EC_PUBLIC_KEY_LEN);
                trezor_bitcoin_multisig_descriptor_t* const descriptor = checked_malloc(sizeof(*descriptor));
                (void)trezor_bitcoin_multisig_policy_to_descriptor(
                    policy, output->nodes_len ? output->nodes[0].public_key : output->pubkeys[0].node.public_key,
                    EC_PUBLIC_KEY_LEN, descriptor);
                free(descriptor);
            }
            free(policy);
        }
        free(output);
        break;
    }
    case 9: {
        trezor_ethereum_get_address_t* const output = checked_malloc(sizeof(*output));
        (void)trezor_ethereum_get_address_decode(payload, payload_len, output);
        free(output);

        trezor_ethereum_sign_typed_hash_t* const typed = checked_malloc(sizeof(*typed));
        (void)trezor_ethereum_sign_typed_hash_decode(payload, payload_len, typed);
        free(typed);
        break;
    }
    case 10: {
        trezor_ethereum_safe_tx_ack_t* const output = checked_malloc(sizeof(*output));
        (void)trezor_ethereum_safe_tx_ack_decode(payload, payload_len, output);
        free(output);
        break;
    }
    case 11: {
        trezor_ethereum_definitions_t* const output = checked_malloc(sizeof(*output));
        (void)trezor_ethereum_definitions_decode(payload, payload_len, output);
        free(output);
        break;
    }
    case 12: {
        // Ethereum signing state machine: init then feed ack payloads
        trezor_ethereum_signing_state_t* const state = checked_malloc(sizeof(*state));
        if (trezor_ethereum_sign_tx_init(state, 0x68 /* placeholder type */, payload, payload_len)) {
            trezor_ethereum_tx_ack_apply(state, payload, payload_len);
        }
        free(state);
        break;
    }
    default:
        break;
    }

    return 0;
}
