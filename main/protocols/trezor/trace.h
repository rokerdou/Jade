#ifndef TREZOR_TRACE_H_
#define TREZOR_TRACE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TREZOR_TRACE_HISTORY_LEN 8
#define TREZOR_TRACE_DETAIL_LEN 160
#define TREZOR_TRACE_FORMATTED_LEN 640

typedef struct {
    uint32_t seq;
    uint16_t request_type;
    uint16_t response_type;
    uint16_t request_payload_len;
    uint16_t response_payload_len;
    uint16_t transport_len;
    uint16_t transport_available;
    uint16_t transport_written;
    uint8_t failure_code;
    bool wire_ok;
    bool handler_ok;
    bool transport_recorded;
    bool transport_ok;
    char request_detail[TREZOR_TRACE_DETAIL_LEN];
    char response_detail[TREZOR_TRACE_DETAIL_LEN];
} trezor_trace_entry_t;

typedef struct {
    uint32_t total;
    size_t count;
    trezor_trace_entry_t latest;
    trezor_trace_entry_t entries[TREZOR_TRACE_HISTORY_LEN];
} trezor_trace_snapshot_t;

void trezor_trace_record_exchange(uint16_t request_type, const uint8_t* request_payload, size_t request_payload_len,
    uint16_t response_type, const uint8_t* response_payload, size_t response_payload_len, bool wire_ok,
    bool handler_ok);
void trezor_trace_record_request_start(uint16_t request_type, const uint8_t* request_payload, size_t request_payload_len);
void trezor_trace_record_transport_result(bool ok, size_t len, uint32_t available, uint32_t written);
bool trezor_trace_snapshot(trezor_trace_snapshot_t* output);
bool trezor_trace_format_latest(char* output, size_t output_len);
bool trezor_trace_format_history(char* output, size_t output_len);
const char* trezor_trace_message_name(uint16_t message_type);
const char* trezor_trace_failure_name(uint8_t failure_code);

#endif /* TREZOR_TRACE_H_ */
