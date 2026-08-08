#ifndef LEDGER_FRAMING_H_
#define LEDGER_FRAMING_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LEDGER_HID_PACKET_SIZE 64
#define LEDGER_HID_TAG_APDU 0x05
#define LEDGER_HID_HEADER_LEN 5
#define LEDGER_HID_FIRST_DATA_LEN (LEDGER_HID_PACKET_SIZE - LEDGER_HID_HEADER_LEN - 2)
#define LEDGER_HID_CONT_DATA_LEN (LEDGER_HID_PACKET_SIZE - LEDGER_HID_HEADER_LEN)
#define LEDGER_APDU_MAX_LEN 260
#define LEDGER_RESPONSE_MAX_PAYLOAD_LEN 128

typedef enum {
    LEDGER_FRAMING_NEED_MORE,
    LEDGER_FRAMING_COMPLETE,
    LEDGER_FRAMING_ERROR,
} ledger_framing_result_t;

typedef struct {
    bool active;
    uint16_t channel;
    uint16_t sequence;
    size_t expected_len;
    size_t copied_len;
    uint8_t apdu[LEDGER_APDU_MAX_LEN];
} ledger_framing_rx_t;

void ledger_framing_rx_reset(ledger_framing_rx_t* rx);
ledger_framing_result_t ledger_framing_rx_chunk(
    ledger_framing_rx_t* rx, const uint8_t* chunk, size_t chunk_len, const uint8_t** apdu, size_t* apdu_len);
bool ledger_framing_encode_response(uint16_t channel, const uint8_t* payload, size_t payload_len, uint16_t status_word,
    uint8_t* output, size_t output_len, size_t* written);

#endif /* LEDGER_FRAMING_H_ */
