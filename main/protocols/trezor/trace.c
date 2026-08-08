#ifndef AMALGAMATED_BUILD
#include "trace.h"

#include "messages.h"
#include "protobuf.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#ifdef ESP_PLATFORM
#include <esp_attr.h>
#include <esp_system.h>
#include <freertos/FreeRTOS.h>
#include <freertos/portmacro.h>
#endif

#define TREZOR_TRACE_HARDENED 0x80000000u
#define TREZOR_TRACE_PENDING_RESPONSE UINT16_MAX
#define TREZOR_TRACE_DIAG_MAGIC 0x54524447u
#define TREZOR_TRACE_STAGE_LEN 32

typedef struct {
    uint32_t magic;
    uint32_t boot_count;
    uint32_t reset_reason;
    char last_stage[TREZOR_TRACE_STAGE_LEN];
} trezor_trace_diag_t;

#ifdef ESP_PLATFORM
static portMUX_TYPE s_trace_mux = portMUX_INITIALIZER_UNLOCKED;
#define TREZOR_TRACE_LOCK() taskENTER_CRITICAL(&s_trace_mux)
#define TREZOR_TRACE_UNLOCK() taskEXIT_CRITICAL(&s_trace_mux)
static __NOINIT_ATTR trezor_trace_diag_t s_trace_diag;
static bool s_trace_diag_checked;
#else
#define TREZOR_TRACE_LOCK()
#define TREZOR_TRACE_UNLOCK()
static trezor_trace_diag_t s_trace_diag;
static bool s_trace_diag_checked;
#endif

static trezor_trace_entry_t s_trace_entries[TREZOR_TRACE_HISTORY_LEN];
static uint32_t s_trace_total;

static void trezor_trace_append(char* output, size_t output_len, const char* fmt, ...);

static void trezor_trace_diag_init_once(void)
{
    if (s_trace_diag_checked) {
        return;
    }

    if (s_trace_diag.magic != TREZOR_TRACE_DIAG_MAGIC) {
        memset(&s_trace_diag, 0, sizeof(s_trace_diag));
        s_trace_diag.magic = TREZOR_TRACE_DIAG_MAGIC;
    }
#ifdef ESP_PLATFORM
    s_trace_diag.reset_reason = (uint32_t)esp_reset_reason();
#else
    s_trace_diag.reset_reason = 0;
#endif
    ++s_trace_diag.boot_count;
    s_trace_diag_checked = true;
}

void trezor_trace_set_stage(const char* const stage)
{
    if (!stage) {
        return;
    }

    trezor_trace_diag_init_once();
    TREZOR_TRACE_LOCK();
    size_t i = 0;
    while (stage[i] != '\0' && i + 1 < sizeof(s_trace_diag.last_stage)) {
        s_trace_diag.last_stage[i] = stage[i];
        ++i;
    }
    s_trace_diag.last_stage[i] = '\0';
    TREZOR_TRACE_UNLOCK();
}

static void trezor_trace_append_diag(char* const output, const size_t output_len)
{
    trezor_trace_diag_init_once();
    if (s_trace_diag.last_stage[0] != '\0') {
        trezor_trace_append(output, output_len, "boot=%lu rr=%lu last=%s\n", (unsigned long)s_trace_diag.boot_count,
            (unsigned long)s_trace_diag.reset_reason, s_trace_diag.last_stage);
    } else {
        trezor_trace_append(output, output_len, "boot=%lu rr=%lu\n", (unsigned long)s_trace_diag.boot_count,
            (unsigned long)s_trace_diag.reset_reason);
    }
}

const char* trezor_trace_message_name(const uint16_t message_type)
{
    switch (message_type) {
    case TREZOR_MSG_INITIALIZE:
        return "Initialize";
    case TREZOR_MSG_SUCCESS:
        return "Success";
    case TREZOR_MSG_FAILURE:
        return "Failure";
    case TREZOR_MSG_GET_PUBLIC_KEY:
        return "GetPublicKey";
    case TREZOR_MSG_PUBLIC_KEY:
        return "PublicKey";
    case TREZOR_MSG_FEATURES:
        return "Features";
    case TREZOR_MSG_CANCEL:
        return "Cancel";
    case TREZOR_MSG_BUTTON_REQUEST:
        return "ButtonRequest";
    case TREZOR_MSG_BUTTON_ACK:
        return "ButtonAck";
    case TREZOR_MSG_GET_ADDRESS:
        return "GetAddress";
    case TREZOR_MSG_ADDRESS:
        return "Address";
    case TREZOR_MSG_GET_FEATURES:
        return "GetFeatures";
    case TREZOR_MSG_END_SESSION:
        return "EndSession";
    case TREZOR_MSG_ETHEREUM_GET_ADDRESS:
        return "EthereumGetAddress";
    case TREZOR_MSG_ETHEREUM_ADDRESS:
        return "EthereumAddress";
    case TREZOR_MSG_ETHEREUM_SIGN_TX:
        return "EthereumSignTx";
    case TREZOR_MSG_ETHEREUM_GET_PUBLIC_KEY:
        return "EthereumGetPublicKey";
    case TREZOR_MSG_ETHEREUM_PUBLIC_KEY:
        return "EthereumPublicKey";
    case TREZOR_MSG_ETHEREUM_SIGN_TX_EIP1559:
        return "EthereumSignTxEIP1559";
    default:
        return "Unknown";
    }
}

const char* trezor_trace_failure_name(const uint8_t failure_code)
{
    switch (failure_code) {
    case 0:
        return "None";
    case TREZOR_FAILURE_UNEXPECTED_MESSAGE:
        return "UnexpectedMessage";
    case TREZOR_FAILURE_DATA_ERROR:
        return "DataError";
    case TREZOR_FAILURE_ACTION_CANCELLED:
        return "ActionCancelled";
    case TREZOR_FAILURE_NOT_INITIALIZED:
        return "NotInitialized";
    case TREZOR_FAILURE_INVALID_SESSION:
        return "InvalidSession";
    case TREZOR_FAILURE_INVALID_PROTOCOL:
        return "InvalidProtocol";
    default:
        return "Unknown";
    }
}

static const char* trezor_trace_message_short_name(const uint16_t message_type)
{
    switch (message_type) {
    case TREZOR_TRACE_PENDING_RESPONSE:
        return "Pending";
    case TREZOR_MSG_INITIALIZE:
        return "Init";
    case TREZOR_MSG_SUCCESS:
        return "Success";
    case TREZOR_MSG_FAILURE:
        return "Fail";
    case TREZOR_MSG_GET_PUBLIC_KEY:
        return "GetPub";
    case TREZOR_MSG_PUBLIC_KEY:
        return "Pub";
    case TREZOR_MSG_FEATURES:
        return "Feat";
    case TREZOR_MSG_CANCEL:
        return "Cancel";
    case TREZOR_MSG_BUTTON_REQUEST:
        return "ButtonReq";
    case TREZOR_MSG_BUTTON_ACK:
        return "ButtonAck";
    case TREZOR_MSG_GET_ADDRESS:
        return "GetAddr";
    case TREZOR_MSG_ADDRESS:
        return "Addr";
    case TREZOR_MSG_GET_FEATURES:
        return "GetFeat";
    case TREZOR_MSG_END_SESSION:
        return "End";
    case TREZOR_MSG_ETHEREUM_GET_ADDRESS:
        return "EthAddr?";
    case TREZOR_MSG_ETHEREUM_ADDRESS:
        return "EthAddr";
    case TREZOR_MSG_ETHEREUM_SIGN_TX:
        return "EthSign";
    case TREZOR_MSG_ETHEREUM_GET_PUBLIC_KEY:
        return "EthPub?";
    case TREZOR_MSG_ETHEREUM_PUBLIC_KEY:
        return "EthPub";
    case TREZOR_MSG_ETHEREUM_SIGN_TX_EIP1559:
        return "Eth1559";
    default:
        return "Unknown";
    }
}

static void trezor_trace_append(char* const output, const size_t output_len, const char* const fmt, ...)
{
    if (!output || !output_len || !fmt) {
        return;
    }

    const size_t current_len = strnlen(output, output_len);
    if (current_len >= output_len - 1) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    (void)vsnprintf(output + current_len, output_len - current_len, fmt, args);
    va_end(args);
}

static bool trezor_trace_read_bool(const uint8_t* const value, const size_t value_len, bool* const output)
{
    uint64_t raw = 0;
    if (!output || !trezor_protobuf_read_varint_value(value, value_len, &raw) || raw > 1) {
        return false;
    }
    *output = raw != 0;
    return true;
}

static void trezor_trace_copy_printable(
    char* const output, const size_t output_len, const uint8_t* const value, const size_t value_len)
{
    if (!output || !output_len) {
        return;
    }
    output[0] = '\0';
    if (!value) {
        return;
    }

    const size_t copy_len = value_len < output_len - 1 ? value_len : output_len - 1;
    for (size_t i = 0; i < copy_len; ++i) {
        const char ch = (char)value[i];
        output[i] = (ch >= 32 && ch <= 126) ? ch : '?';
    }
    output[copy_len] = '\0';
}

static void trezor_trace_append_path(char* const output, const size_t output_len,
    const uint32_t* const path, const size_t path_len)
{
    trezor_trace_append(output, output_len, " path=m");
    for (size_t i = 0; i < path_len; ++i) {
        const uint32_t part = path[i];
        trezor_trace_append(output, output_len, "/%lu%s", (unsigned long)(part & ~TREZOR_TRACE_HARDENED),
            (part & TREZOR_TRACE_HARDENED) ? "'" : "");
    }
}

static bool trezor_trace_parse_path_part(const uint8_t* const value, const size_t value_len,
    uint32_t* const path, size_t* const path_len, const size_t path_cap)
{
    uint64_t part = 0;
    if (!value || !path || !path_len || *path_len >= path_cap
        || !trezor_protobuf_read_varint_value(value, value_len, &part) || part > UINT32_MAX) {
        return false;
    }
    path[(*path_len)++] = (uint32_t)part;
    return true;
}

static void trezor_trace_format_initialize(
    const uint8_t* const payload, const size_t payload_len, char* const output, const size_t output_len)
{
    if (!payload_len) {
        trezor_trace_append(output, output_len, "empty");
        return;
    }

    size_t session_id_len = 0;
    bool has_field2 = false;
    bool field2 = false;
    bool has_field3 = false;
    bool field3 = false;
    size_t fields = 0;
    bool invalid = false;

    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    while (!invalid && reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            invalid = true;
            break;
        }
        ++fields;
        if (field_number == 1 && wire_type == TREZOR_PROTOBUF_WIRE_LEN) {
            session_id_len = value_len;
        } else if (field_number == 2 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT) {
            has_field2 = trezor_trace_read_bool(value, value_len, &field2);
            invalid = !has_field2;
        } else if (field_number == 3 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT) {
            has_field3 = trezor_trace_read_bool(value, value_len, &field3);
            invalid = !has_field3;
        }
    }

    trezor_trace_append(output, output_len, "fields=%lu sid_len=%lu", (unsigned long)fields,
        (unsigned long)session_id_len);
    if (has_field2) {
        trezor_trace_append(output, output_len, " f2=%u", field2 ? 1 : 0);
    }
    if (has_field3) {
        trezor_trace_append(output, output_len, " f3=%u", field3 ? 1 : 0);
    }
    if (invalid) {
        trezor_trace_append(output, output_len, " invalid");
    }
}

static void trezor_trace_format_get_address(
    const uint8_t* const payload, const size_t payload_len, char* const output, const size_t output_len)
{
    uint32_t path[10];
    size_t path_len = 0;
    char coin[24] = { 0 };
    bool has_show = false;
    bool show = false;
    bool has_script = false;
    uint64_t script = 0;
    size_t unknown = 0;
    bool invalid = false;

    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    while (!invalid && reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            invalid = true;
            break;
        }
        if (field_number == 1 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT) {
            invalid = !trezor_trace_parse_path_part(value, value_len, path, &path_len, sizeof(path) / sizeof(path[0]));
        } else if (field_number == 2 && wire_type == TREZOR_PROTOBUF_WIRE_LEN) {
            trezor_trace_copy_printable(coin, sizeof(coin), value, value_len);
        } else if (field_number == 3 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT) {
            has_show = trezor_trace_read_bool(value, value_len, &show);
            invalid = !has_show;
        } else if (field_number == 5 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT) {
            has_script = trezor_protobuf_read_varint_value(value, value_len, &script);
            invalid = !has_script;
        } else {
            ++unknown;
        }
    }

    trezor_trace_append_path(output, output_len, path, path_len);
    if (coin[0] != '\0') {
        trezor_trace_append(output, output_len, " coin=%s", coin);
    }
    if (has_show) {
        trezor_trace_append(output, output_len, " show=%u", show ? 1 : 0);
    }
    if (has_script) {
        trezor_trace_append(output, output_len, " script=%lu", (unsigned long)script);
    }
    if (unknown) {
        trezor_trace_append(output, output_len, " unk=%lu", (unsigned long)unknown);
    }
    if (invalid) {
        trezor_trace_append(output, output_len, " invalid");
    }
}

static void trezor_trace_format_public_key(
    const uint8_t* const payload, const size_t payload_len, const bool ethereum, char* const output,
    const size_t output_len)
{
    uint32_t path[10];
    size_t path_len = 0;
    char coin[24] = { 0 };
    bool has_show = false;
    bool show = false;
    bool has_script = false;
    uint64_t script = 0;
    size_t unknown = 0;
    bool invalid = false;

    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    while (!invalid && reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            invalid = true;
            break;
        }
        if (field_number == 1 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT) {
            invalid = !trezor_trace_parse_path_part(value, value_len, path, &path_len, sizeof(path) / sizeof(path[0]));
        } else if (!ethereum && field_number == 3 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT) {
            has_show = trezor_trace_read_bool(value, value_len, &show);
            invalid = !has_show;
        } else if (ethereum && field_number == 2 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT) {
            has_show = trezor_trace_read_bool(value, value_len, &show);
            invalid = !has_show;
        } else if (!ethereum && field_number == 4 && wire_type == TREZOR_PROTOBUF_WIRE_LEN) {
            trezor_trace_copy_printable(coin, sizeof(coin), value, value_len);
        } else if (!ethereum && field_number == 5 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT) {
            has_script = trezor_protobuf_read_varint_value(value, value_len, &script);
            invalid = !has_script;
        } else {
            ++unknown;
        }
    }

    trezor_trace_append_path(output, output_len, path, path_len);
    if (coin[0] != '\0') {
        trezor_trace_append(output, output_len, " coin=%s", coin);
    }
    if (has_show) {
        trezor_trace_append(output, output_len, " show=%u", show ? 1 : 0);
    }
    if (has_script) {
        trezor_trace_append(output, output_len, " script=%lu", (unsigned long)script);
    }
    if (unknown) {
        trezor_trace_append(output, output_len, " unk=%lu", (unsigned long)unknown);
    }
    if (invalid) {
        trezor_trace_append(output, output_len, " invalid");
    }
}

static void trezor_trace_format_eth_address(
    const uint8_t* const payload, const size_t payload_len, char* const output, const size_t output_len)
{
    uint32_t path[10];
    size_t path_len = 0;
    bool has_show = false;
    bool show = false;
    bool has_chunkify = false;
    bool chunkify = false;
    size_t unknown = 0;
    bool invalid = false;

    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    while (!invalid && reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            invalid = true;
            break;
        }
        if (field_number == 1 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT) {
            invalid = !trezor_trace_parse_path_part(value, value_len, path, &path_len, sizeof(path) / sizeof(path[0]));
        } else if (field_number == 2 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT) {
            has_show = trezor_trace_read_bool(value, value_len, &show);
            invalid = !has_show;
        } else if (field_number == 4 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT) {
            has_chunkify = trezor_trace_read_bool(value, value_len, &chunkify);
            invalid = !has_chunkify;
        } else {
            ++unknown;
        }
    }

    trezor_trace_append_path(output, output_len, path, path_len);
    if (has_show) {
        trezor_trace_append(output, output_len, " show=%u", show ? 1 : 0);
    }
    if (has_chunkify) {
        trezor_trace_append(output, output_len, " chunk=%u", chunkify ? 1 : 0);
    }
    if (unknown) {
        trezor_trace_append(output, output_len, " unk=%lu", (unsigned long)unknown);
    }
    if (invalid) {
        trezor_trace_append(output, output_len, " invalid");
    }
}

static uint8_t trezor_trace_failure_code_from_payload(const uint8_t* const payload, const size_t payload_len)
{
    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    while (reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        uint64_t code = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            return 0;
        }
        if (field_number == 1 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT
            && trezor_protobuf_read_varint_value(value, value_len, &code) && code <= UINT8_MAX) {
            return (uint8_t)code;
        }
    }
    return 0;
}

static void trezor_trace_format_features_response(
    const uint8_t* const payload, const size_t payload_len, char* const output, const size_t output_len)
{
    bool has_initialized = false;
    bool initialized = false;
    bool has_unlocked = false;
    bool unlocked = false;
    bool has_pin = false;
    bool pin = false;
    bool has_passphrase = false;
    bool passphrase = false;
    char fw_vendor[24] = { 0 };
    size_t session_id_len = 0;
    size_t capabilities = 0;
    bool invalid = false;

    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    while (!invalid && reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            invalid = true;
            break;
        }
        if (field_number == 7 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT) {
            has_pin = trezor_trace_read_bool(value, value_len, &pin);
            invalid = !has_pin;
        } else if (field_number == 8 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT) {
            has_passphrase = trezor_trace_read_bool(value, value_len, &passphrase);
            invalid = !has_passphrase;
        } else if (field_number == 12 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT) {
            has_initialized = trezor_trace_read_bool(value, value_len, &initialized);
            invalid = !has_initialized;
        } else if (field_number == 16 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT) {
            has_unlocked = trezor_trace_read_bool(value, value_len, &unlocked);
            invalid = !has_unlocked;
        } else if (field_number == 25 && wire_type == TREZOR_PROTOBUF_WIRE_LEN) {
            const size_t copy_len = value_len < sizeof(fw_vendor) - 1 ? value_len : sizeof(fw_vendor) - 1;
            memcpy(fw_vendor, value, copy_len);
            fw_vendor[copy_len] = '\0';
        } else if (field_number == 30 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT) {
            ++capabilities;
        } else if (field_number == 35 && wire_type == TREZOR_PROTOBUF_WIRE_LEN) {
            session_id_len = value_len;
        }
    }

    if (has_initialized) {
        trezor_trace_append(output, output_len, "init=%u ", initialized ? 1 : 0);
    }
    if (has_unlocked) {
        trezor_trace_append(output, output_len, "unlock=%u ", unlocked ? 1 : 0);
    }
    if (has_pin) {
        trezor_trace_append(output, output_len, "pin=%u ", pin ? 1 : 0);
    }
    if (has_passphrase) {
        trezor_trace_append(output, output_len, "pass=%u ", passphrase ? 1 : 0);
    }
    if (fw_vendor[0] != '\0') {
        trezor_trace_append(output, output_len, "fw=%s ", fw_vendor);
    }
    trezor_trace_append(output, output_len, "sid_len=%lu caps=%lu", (unsigned long)session_id_len,
        (unsigned long)capabilities);
    if (invalid) {
        trezor_trace_append(output, output_len, " invalid");
    }
}

static void trezor_trace_format_request(uint16_t request_type, const uint8_t* const payload,
    const size_t payload_len, const bool wire_ok, char* const output, const size_t output_len)
{
    if (!wire_ok) {
        trezor_trace_append(output, output_len, "wire decode failed");
        return;
    }

    switch (request_type) {
    case TREZOR_MSG_INITIALIZE:
        trezor_trace_format_initialize(payload, payload_len, output, output_len);
        break;
    case TREZOR_MSG_GET_FEATURES:
    case TREZOR_MSG_CANCEL:
    case TREZOR_MSG_END_SESSION:
    case TREZOR_MSG_BUTTON_ACK:
        trezor_trace_append(output, output_len, "%s", payload_len ? "unexpected payload" : "empty");
        break;
    case TREZOR_MSG_GET_ADDRESS:
        trezor_trace_format_get_address(payload, payload_len, output, output_len);
        break;
    case TREZOR_MSG_ETHEREUM_GET_ADDRESS:
        trezor_trace_format_eth_address(payload, payload_len, output, output_len);
        break;
    case TREZOR_MSG_GET_PUBLIC_KEY:
        trezor_trace_format_public_key(payload, payload_len, false, output, output_len);
        break;
    case TREZOR_MSG_ETHEREUM_GET_PUBLIC_KEY:
        trezor_trace_format_public_key(payload, payload_len, true, output, output_len);
        break;
    default:
        trezor_trace_append(output, output_len, "payload_len=%lu", (unsigned long)payload_len);
        break;
    }
}

static void trezor_trace_format_response(uint16_t response_type, const uint8_t* const payload,
    const size_t payload_len, char* const output, const size_t output_len)
{
    switch (response_type) {
    case TREZOR_MSG_FAILURE: {
        const uint8_t code = trezor_trace_failure_code_from_payload(payload, payload_len);
        trezor_trace_append(output, output_len, "code=%u %s", code, trezor_trace_failure_name(code));
        break;
    }
    case TREZOR_MSG_FEATURES:
        trezor_trace_format_features_response(payload, payload_len, output, output_len);
        break;
    case TREZOR_MSG_BUTTON_REQUEST:
        trezor_trace_append(output, output_len, "local device action requested");
        break;
    case TREZOR_MSG_ADDRESS:
    case TREZOR_MSG_ETHEREUM_ADDRESS:
        trezor_trace_append(output, output_len, "address omitted");
        break;
    case TREZOR_MSG_PUBLIC_KEY:
    case TREZOR_MSG_ETHEREUM_PUBLIC_KEY:
        trezor_trace_append(output, output_len, "node/xpub omitted");
        break;
    default:
        trezor_trace_append(output, output_len, "payload_len=%lu", (unsigned long)payload_len);
        break;
    }
}

void trezor_trace_record_exchange(const uint16_t request_type, const uint8_t* const request_payload,
    const size_t request_payload_len, const uint16_t response_type, const uint8_t* const response_payload,
    const size_t response_payload_len, const bool wire_ok, const bool handler_ok)
{
    trezor_trace_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.request_type = request_type;
    entry.response_type = response_type;
    entry.request_payload_len = request_payload_len <= UINT16_MAX ? (uint16_t)request_payload_len : UINT16_MAX;
    entry.response_payload_len = response_payload_len <= UINT16_MAX ? (uint16_t)response_payload_len : UINT16_MAX;
    entry.failure_code = response_type == TREZOR_MSG_FAILURE
        ? trezor_trace_failure_code_from_payload(response_payload, response_payload_len)
        : 0;
    entry.wire_ok = wire_ok;
    entry.handler_ok = handler_ok;
    trezor_trace_format_request(
        request_type, request_payload, request_payload_len, wire_ok, entry.request_detail, sizeof(entry.request_detail));
    trezor_trace_format_response(
        response_type, response_payload, response_payload_len, entry.response_detail, sizeof(entry.response_detail));

    TREZOR_TRACE_LOCK();
    entry.seq = ++s_trace_total;
    s_trace_entries[(entry.seq - 1) % TREZOR_TRACE_HISTORY_LEN] = entry;
    TREZOR_TRACE_UNLOCK();
}

void trezor_trace_record_request_start(
    const uint16_t request_type, const uint8_t* const request_payload, const size_t request_payload_len)
{
    trezor_trace_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.request_type = request_type;
    entry.response_type = TREZOR_TRACE_PENDING_RESPONSE;
    entry.request_payload_len = request_payload_len <= UINT16_MAX ? (uint16_t)request_payload_len : UINT16_MAX;
    entry.wire_ok = true;
    entry.handler_ok = false;
    trezor_trace_format_request(
        request_type, request_payload, request_payload_len, true, entry.request_detail, sizeof(entry.request_detail));
    trezor_trace_append(entry.response_detail, sizeof(entry.response_detail), "pending");

    TREZOR_TRACE_LOCK();
    entry.seq = ++s_trace_total;
    s_trace_entries[(entry.seq - 1) % TREZOR_TRACE_HISTORY_LEN] = entry;
    TREZOR_TRACE_UNLOCK();
}

void trezor_trace_record_transport_result(
    const bool ok, const size_t len, const uint32_t available, const uint32_t written)
{
    TREZOR_TRACE_LOCK();
    if (s_trace_total) {
        trezor_trace_entry_t* const entry = &s_trace_entries[(s_trace_total - 1) % TREZOR_TRACE_HISTORY_LEN];
        entry->transport_recorded = true;
        entry->transport_ok = ok;
        entry->transport_len = len <= UINT16_MAX ? (uint16_t)len : UINT16_MAX;
        entry->transport_available = available <= UINT16_MAX ? (uint16_t)available : UINT16_MAX;
        entry->transport_written = written <= UINT16_MAX ? (uint16_t)written : UINT16_MAX;
    }
    TREZOR_TRACE_UNLOCK();
}

bool trezor_trace_snapshot(trezor_trace_snapshot_t* const output)
{
    if (!output) {
        return false;
    }

    TREZOR_TRACE_LOCK();
    memset(output, 0, sizeof(*output));
    output->total = s_trace_total;
    output->count = s_trace_total < TREZOR_TRACE_HISTORY_LEN ? s_trace_total : TREZOR_TRACE_HISTORY_LEN;
    if (s_trace_total) {
        output->latest = s_trace_entries[(s_trace_total - 1) % TREZOR_TRACE_HISTORY_LEN];
    }
    for (size_t i = 0; i < output->count; ++i) {
        output->entries[i] = s_trace_entries[i];
    }
    TREZOR_TRACE_UNLOCK();

    return output->total > 0;
}

static const trezor_trace_entry_t* trezor_trace_entry_by_seq(
    const trezor_trace_snapshot_t* const snapshot, const uint32_t seq)
{
    if (!snapshot || !seq) {
        return NULL;
    }
    for (size_t i = 0; i < snapshot->count; ++i) {
        if (snapshot->entries[i].seq == seq) {
            return &snapshot->entries[i];
        }
    }
    return NULL;
}

bool trezor_trace_format_latest(char* const output, const size_t output_len)
{
    if (!output || output_len == 0) {
        return false;
    }
    output[0] = '\0';

    trezor_trace_snapshot_t snapshot;
    if (!trezor_trace_snapshot(&snapshot)) {
        trezor_trace_append_diag(output, output_len);
        trezor_trace_append(output, output_len, "No USB messages yet");
        return false;
    }

    const trezor_trace_entry_t* const entry = &snapshot.latest;
    trezor_trace_append_diag(output, output_len);
    trezor_trace_append(output, output_len, "#%lu total=%lu\nreq=%u %s\n%s\nresp=%u %s\n%s\nfail=%u %s\nwire=%s hdl=%s",
        (unsigned long)entry->seq, (unsigned long)snapshot.total, entry->request_type,
        entry->wire_ok ? trezor_trace_message_name(entry->request_type) : "BadWire", entry->request_detail, entry->response_type,
        entry->response_type != TREZOR_TRACE_PENDING_RESPONSE ? trezor_trace_message_name(entry->response_type) : "Pending",
        entry->response_detail, entry->failure_code,
        trezor_trace_failure_name(entry->failure_code), entry->wire_ok ? "ok" : "bad",
        entry->response_type != TREZOR_TRACE_PENDING_RESPONSE && entry->handler_ok ? "ok" : "bad");
    if (entry->transport_recorded) {
        trezor_trace_append(output, output_len, " tx=%s len=%u av=%u wr=%u", entry->transport_ok ? "ok" : "bad",
            entry->transport_len, entry->transport_available, entry->transport_written);
    }
    return true;
}

bool trezor_trace_format_history(char* const output, const size_t output_len)
{
    if (!output || output_len == 0) {
        return false;
    }
    output[0] = '\0';

    trezor_trace_snapshot_t snapshot;
    if (!trezor_trace_snapshot(&snapshot)) {
        trezor_trace_append_diag(output, output_len);
        trezor_trace_append(output, output_len, "No USB messages yet");
        return false;
    }

    trezor_trace_append_diag(output, output_len);
    trezor_trace_append(output, output_len, "Recent USB messages\n");
    for (size_t i = 0; i < snapshot.count; ++i) {
        const uint32_t seq = snapshot.total - (uint32_t)i;
        const trezor_trace_entry_t* const entry = trezor_trace_entry_by_seq(&snapshot, seq);
        if (!entry) {
            continue;
        }

        trezor_trace_append(output, output_len, "#%lu %s>%s f%u %s", (unsigned long)entry->seq,
            entry->wire_ok ? trezor_trace_message_short_name(entry->request_type) : "BadWire",
            trezor_trace_message_short_name(entry->response_type), entry->failure_code,
            entry->response_type != TREZOR_TRACE_PENDING_RESPONSE ? (entry->wire_ok && entry->handler_ok ? "ok" : "bad")
                                                                   : "pending");
        if (entry->transport_recorded) {
            trezor_trace_append(output, output_len, " tx%s l%u a%u w%u", entry->transport_ok ? "ok" : "bad",
                entry->transport_len, entry->transport_available, entry->transport_written);
        }
        trezor_trace_append(output, output_len, "\n");
    }
    return true;
}
#endif /* AMALGAMATED_BUILD */
