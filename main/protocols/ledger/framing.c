#ifndef AMALGAMATED_BUILD
#include "framing.h"

#include <string.h>

static uint16_t ledger_read_u16_be(const uint8_t* const data)
{
    return ((uint16_t)data[0] << 8) | (uint16_t)data[1];
}

static void ledger_write_u16_be(uint8_t* const data, const uint16_t value)
{
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)value;
}

void ledger_framing_rx_reset(ledger_framing_rx_t* const rx)
{
    if (rx) {
        memset(rx, 0, sizeof(*rx));
    }
}

ledger_framing_result_t ledger_framing_rx_chunk(ledger_framing_rx_t* const rx, const uint8_t* const chunk,
    const size_t chunk_len, const uint8_t** const apdu, size_t* const apdu_len)
{
    if (!rx || !chunk || chunk_len != LEDGER_HID_PACKET_SIZE || !apdu || !apdu_len) {
        return LEDGER_FRAMING_ERROR;
    }

    *apdu = NULL;
    *apdu_len = 0;

    const uint16_t channel = ledger_read_u16_be(chunk);
    if (chunk[2] != LEDGER_HID_TAG_APDU) {
        ledger_framing_rx_reset(rx);
        return LEDGER_FRAMING_ERROR;
    }

    const uint16_t sequence = ledger_read_u16_be(chunk + 3);
    if (sequence == 0) {
        const size_t expected_len = ledger_read_u16_be(chunk + 5);
        if (expected_len < 5 || expected_len > sizeof(rx->apdu)) {
            ledger_framing_rx_reset(rx);
            return LEDGER_FRAMING_ERROR;
        }

        ledger_framing_rx_reset(rx);
        rx->active = true;
        rx->channel = channel;
        rx->sequence = 1;
        rx->expected_len = expected_len;

        size_t copy_len = expected_len < LEDGER_HID_FIRST_DATA_LEN ? expected_len : LEDGER_HID_FIRST_DATA_LEN;
        memcpy(rx->apdu, chunk + LEDGER_HID_HEADER_LEN + 2, copy_len);
        rx->copied_len = copy_len;
    } else {
        if (!rx->active || channel != rx->channel || sequence != rx->sequence) {
            ledger_framing_rx_reset(rx);
            return LEDGER_FRAMING_ERROR;
        }
        ++rx->sequence;

        const size_t remaining = rx->expected_len - rx->copied_len;
        const size_t copy_len = remaining < LEDGER_HID_CONT_DATA_LEN ? remaining : LEDGER_HID_CONT_DATA_LEN;
        memcpy(rx->apdu + rx->copied_len, chunk + LEDGER_HID_HEADER_LEN, copy_len);
        rx->copied_len += copy_len;
    }

    if (rx->copied_len == rx->expected_len) {
        *apdu = rx->apdu;
        *apdu_len = rx->copied_len;
        return LEDGER_FRAMING_COMPLETE;
    }

    return LEDGER_FRAMING_NEED_MORE;
}

bool ledger_framing_encode_response(const uint16_t channel, const uint8_t* const payload, const size_t payload_len,
    const uint16_t status_word, uint8_t* const output, const size_t output_len, size_t* const written)
{
    if (!output || !written || (!payload && payload_len) || payload_len > LEDGER_RESPONSE_MAX_PAYLOAD_LEN) {
        return false;
    }

    const size_t response_len = payload_len + 2;
    const size_t framed_data_len = response_len + 2;
    const size_t packet_count = (framed_data_len + LEDGER_HID_CONT_DATA_LEN - 1) / LEDGER_HID_CONT_DATA_LEN;
    const size_t required_len = packet_count * LEDGER_HID_PACKET_SIZE;
    if (!packet_count || required_len > output_len) {
        return false;
    }

    uint8_t response[LEDGER_RESPONSE_MAX_PAYLOAD_LEN + 2];
    if (payload_len > 0) {
        memcpy(response, payload, payload_len);
    }
    response[payload_len] = (uint8_t)(status_word >> 8);
    response[payload_len + 1] = (uint8_t)status_word;

    memset(output, 0, required_len);
    size_t response_offset = 0;
    for (size_t packet = 0; packet < packet_count; ++packet) {
        uint8_t* const chunk = output + (packet * LEDGER_HID_PACKET_SIZE);
        ledger_write_u16_be(chunk, channel);
        chunk[2] = LEDGER_HID_TAG_APDU;
        ledger_write_u16_be(chunk + 3, (uint16_t)packet);

        size_t data_offset = LEDGER_HID_HEADER_LEN;
        size_t data_cap = LEDGER_HID_CONT_DATA_LEN;
        if (packet == 0) {
            ledger_write_u16_be(chunk + data_offset, (uint16_t)response_len);
            data_offset += 2;
            data_cap -= 2;
        }

        const size_t remaining = response_len - response_offset;
        const size_t copy_len = remaining < data_cap ? remaining : data_cap;
        if (copy_len > 0) {
            memcpy(chunk + data_offset, response + response_offset, copy_len);
            response_offset += copy_len;
        }
    }

    memset(response, 0, sizeof(response));
    *written = required_len;
    return response_offset == response_len;
}
#endif /* AMALGAMATED_BUILD */
