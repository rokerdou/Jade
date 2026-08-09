#ifndef AMALGAMATED_BUILD
#include "usb_hid.h"

#ifdef CONFIG_TREZOR_USB_HID

#include "messages.h"
#include "protobuf.h"
#include "public_key.h"
#include "session.h"
#include "trace.h"
#include "wire.h"

#include "../../chains/bitcoin/path.h"
#include "../../chains/bitcoin/wallet.h"
#include "../../chains/bitcoin/confirm.h"
#include "../../chains/ethereum/address.h"
#include "../../chains/ethereum/path.h"
#include "../../chains/ethereum/sign.h"
#include "../../chains/ethereum/wallet.h"
#include "../../idletimer.h"
#include "../../jade_assert.h"
#include "../../jade_tasks.h"
#include "../../process/auth_user.h"
#include "../../process.h"
#include "../../sensitive.h"
#include "../../ui.h"
#include "../../wallet_core/wallet_core.h"

#include <esp_err.h>
#include <esp_mac.h>
#include <esp_random.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>
#include <stdint.h>
#include <string.h>
#include <tinyusb.h>
#include <tusb.h>
#include <wally_bip32.h>
#include <wally_crypto.h>

#define TREZOR_USB_HID_VID 0x1209
#define TREZOR_USB_HID_PID 0x53C1
#define TREZOR_USB_HID_RELEASE 0x0200
#define TREZOR_USB_HID_ENDPOINT 0x01
#define TREZOR_USB_HID_QUEUE_LEN 16
#define TREZOR_USB_HID_TASK_STACK 16384
#define TREZOR_USB_HID_TASK_PRIORITY 5
#define TREZOR_USB_HID_RX_BUF_LEN 2304
#define TREZOR_USB_HID_TX_BUF_LEN 2304
#define TREZOR_USB_HID_INTERACTIVE_TIMEOUT_SECS 600
#define TREZOR_USB_HID_SIGNED_NOTICE_MS 1200
#define TREZOR_USB_WEBUSB_VENDOR_CODE 0x01
#define TREZOR_USB_WEBUSB_GET_URL 0x02
#define TREZOR_USB_WEBUSB_URL_INDEX 0x01
#define TREZOR_USB_WEBUSB_URL "trezor.io/start"

typedef struct {
    uint8_t bytes[TREZOR_WIRE_CHUNK_SIZE];
} trezor_usb_hid_chunk_t;

static QueueHandle_t s_hid_rx_queue = NULL;
static TaskHandle_t s_hid_task = NULL;
static volatile bool s_hid_enabled = false;
static uint8_t s_hid_rx_chunks[TREZOR_USB_HID_RX_BUF_LEN];
static uint8_t s_hid_tx_chunks[TREZOR_USB_HID_TX_BUF_LEN];
static uint8_t s_trezor_session_id[TREZOR_FEATURES_SESSION_ID_LEN];
static bool s_trezor_session_id_initialized = false;
static trezor_session_state_t s_trezor_session_state;
static char s_trezor_device_id[13];
static volatile bool s_signed_notice_active = false;

static const tusb_desc_device_t TREZOR_USB_HID_DEVICE_DESCRIPTOR = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0210,
    .bDeviceClass = 0x00,
    .bDeviceSubClass = 0x00,
    .bDeviceProtocol = 0x00,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = TREZOR_USB_HID_VID,
    .idProduct = TREZOR_USB_HID_PID,
    .bcdDevice = TREZOR_USB_HID_RELEASE,
    .iManufacturer = 0x01,
    .iProduct = 0x02,
    .iSerialNumber = 0x03,
    .bNumConfigurations = 0x01,
};

enum {
    TREZOR_USB_ITF_VENDOR = 0,
    TREZOR_USB_ITF_TOTAL,
};

#define TREZOR_USB_CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_VENDOR_DESC_LEN)
#define TREZOR_USB_BOS_TOTAL_LEN (TUD_BOS_DESC_LEN + TUD_BOS_WEBUSB_DESC_LEN)

static const uint8_t TREZOR_USB_HID_CONFIGURATION_DESCRIPTOR[] = {
    TUD_CONFIG_DESCRIPTOR(1, TREZOR_USB_ITF_TOTAL, 0, TREZOR_USB_CONFIG_TOTAL_LEN, 0x00, 100),
    // Match Trezor WebUSB wire: vendor-class interface with 64-byte interrupt IN/OUT endpoints.
    9, TUSB_DESC_INTERFACE, TREZOR_USB_ITF_VENDOR, 0, 2, TUSB_CLASS_VENDOR_SPECIFIC, 0x00, 0x00, 4,
    7, TUSB_DESC_ENDPOINT, TREZOR_USB_HID_ENDPOINT, TUSB_XFER_INTERRUPT, U16_TO_U8S_LE(TREZOR_WIRE_CHUNK_SIZE), 1,
    7, TUSB_DESC_ENDPOINT, 0x80 | TREZOR_USB_HID_ENDPOINT, TUSB_XFER_INTERRUPT,
    U16_TO_U8S_LE(TREZOR_WIRE_CHUNK_SIZE), 1,
};

static const uint8_t TREZOR_USB_HID_BOS_DESCRIPTOR[] = {
    TUD_BOS_DESCRIPTOR(TREZOR_USB_BOS_TOTAL_LEN, 1),
    TUD_BOS_WEBUSB_DESCRIPTOR(TREZOR_USB_WEBUSB_VENDOR_CODE, TREZOR_USB_WEBUSB_URL_INDEX),
};

static const char* TREZOR_USB_HID_STRINGS[] = {
    (const char[]){ 0x09, 0x04 },
    "SatoshiLabs",
    "TREZOR",
    s_trezor_device_id,
    "TREZOR Interface",
};

static const uint8_t TREZOR_USB_WEBUSB_URL_DESCRIPTOR[] = {
    3 + sizeof(TREZOR_USB_WEBUSB_URL) - 1,
    3,
    1,
    't',
    'r',
    'e',
    'z',
    'o',
    'r',
    '.',
    'i',
    'o',
    '/',
    's',
    't',
    'a',
    'r',
    't',
};

bool show_confirm_address_activity(const char* address, bool default_selection);

static void trezor_usb_hid_init_device_id(void)
{
    if (s_trezor_device_id[0] != '\0') {
        return;
    }

    uint8_t mac[6];
    if (esp_efuse_mac_get_default(mac) == ESP_OK) {
        static const char hex[] = "0123456789ABCDEF";
        for (size_t i = 0; i < sizeof(mac); ++i) {
            s_trezor_device_id[i * 2] = hex[mac[i] >> 4];
            s_trezor_device_id[(i * 2) + 1] = hex[mac[i] & 0x0f];
        }
        s_trezor_device_id[sizeof(s_trezor_device_id) - 1] = '\0';
        return;
    }

    memcpy(s_trezor_device_id, "JADEUNKNOWN", sizeof("JADEUNKNOWN"));
}

static bool trezor_usb_hid_initialize_session(void* ctx, const uint8_t* const session_id, const size_t session_id_len)
{
    (void)ctx;
    if (session_id_len != 0 && session_id_len != sizeof(s_trezor_session_id)) {
        return false;
    }
    if (session_id_len == sizeof(s_trezor_session_id)) {
        memcpy(s_trezor_session_id, session_id, sizeof(s_trezor_session_id));
    } else {
        esp_fill_random(s_trezor_session_id, sizeof(s_trezor_session_id));
    }
    s_trezor_session_id_initialized = true;
    return true;
}

uint8_t const* tud_descriptor_bos_cb(void)
{
    return TREZOR_USB_HID_BOS_DESCRIPTOR;
}

bool tud_vendor_control_xfer_cb(const uint8_t rhport, const uint8_t stage, const tusb_control_request_t* const request)
{
    if (stage != CONTROL_STAGE_SETUP) {
        return true;
    }
    if (!request || request->bmRequestType_bit.direction != TUSB_DIR_IN
        || request->bmRequestType_bit.type != TUSB_REQ_TYPE_VENDOR
        || request->bmRequestType_bit.recipient != TUSB_REQ_RCPT_DEVICE
        || request->bRequest != TREZOR_USB_WEBUSB_VENDOR_CODE || request->wIndex != TREZOR_USB_WEBUSB_GET_URL
        || request->wValue != TREZOR_USB_WEBUSB_URL_INDEX || request->wLength == 0) {
        return false;
    }
    return tud_control_xfer(rhport, request, (void*)(uintptr_t)TREZOR_USB_WEBUSB_URL_DESCRIPTOR,
        sizeof(TREZOR_USB_WEBUSB_URL_DESCRIPTOR));
}

void tud_vendor_rx_cb(const uint8_t instance, const uint8_t* const buffer, const uint16_t bufsize)
{
    trezor_trace_set_stage("usb:rx_cb");
    if (!s_hid_rx_queue || instance != 0 || !buffer || bufsize != TREZOR_WIRE_CHUNK_SIZE) {
        trezor_trace_set_stage("usb:rx_drop");
        return;
    }

    trezor_usb_hid_chunk_t chunk;
    memcpy(chunk.bytes, buffer, sizeof(chunk.bytes));
    trezor_trace_set_stage("usb:rx_queue");
    const UBaseType_t spaces_before = uxQueueSpacesAvailable(s_hid_rx_queue);
    const BaseType_t queued = xQueueSend(s_hid_rx_queue, &chunk, 0);
    tud_vendor_read_flush();
    if (queued != pdTRUE) {
        trezor_trace_set_stage("usb:rx_qfull");
        trezor_trace_set_note("rx qfull spaces=%lu", (unsigned long)spaces_before);
        return;
    }
    trezor_trace_set_note("rx queued spaces=%lu", (unsigned long)spaces_before);
    trezor_trace_set_stage("usb:rx_done");
}

void tud_vendor_stage_cb(const char* const stage)
{
    trezor_trace_set_stage(stage);
}

static bool trezor_usb_hid_expected_wire_len(const uint8_t chunk[TREZOR_WIRE_CHUNK_SIZE], size_t* const output_len)
{
    if (!chunk || !output_len || chunk[0] != TREZOR_WIRE_MARKER || chunk[1] != TREZOR_WIRE_MAGIC
        || chunk[2] != TREZOR_WIRE_MAGIC) {
        return false;
    }

    const size_t payload_len = ((size_t)chunk[5] << 24) | ((size_t)chunk[6] << 16) | ((size_t)chunk[7] << 8) | chunk[8];
    return payload_len <= TREZOR_SESSION_MAX_REQUEST_PAYLOAD_LEN && trezor_wire_encoded_len(payload_len, output_len)
        && *output_len <= TREZOR_USB_HID_RX_BUF_LEN;
}

static bool trezor_usb_hid_send_chunks(const uint8_t* const chunks, const size_t chunks_len,
    uint32_t* const last_available, uint32_t* const last_written, const bool checkpoint)
{
    if (!chunks || chunks_len == 0 || chunks_len % TREZOR_WIRE_CHUNK_SIZE != 0) {
        return false;
    }
    if (last_available) {
        *last_available = 0;
    }
    if (last_written) {
        *last_written = 0;
    }

    for (size_t offset = 0; offset < chunks_len; offset += TREZOR_WIRE_CHUNK_SIZE) {
        bool sent = false;
        for (size_t retry = 0; retry < 200; ++retry) {
            const uint32_t available = tud_vendor_mounted() ? tud_vendor_n_write_available(0) : 0;
            if (checkpoint) {
                trezor_trace_checkpoint("usb:chunk_try", "off=%lu retry=%lu av=%lu mounted=%u",
                    (unsigned long)offset, (unsigned long)retry, (unsigned long)available,
                    tud_vendor_mounted() ? 1U : 0U);
            }
            if (last_available) {
                *last_available = available;
            }
            if (!tud_vendor_mounted()) {
                vTaskDelay(pdMS_TO_TICKS(1));
                continue;
            }

            if (checkpoint) {
                trezor_trace_checkpoint("usb:write_before", "off=%lu av=%lu", (unsigned long)offset,
                    (unsigned long)available);
            }
            const uint32_t written = tud_vendor_write(chunks + offset, TREZOR_WIRE_CHUNK_SIZE);
            if (checkpoint) {
                trezor_trace_checkpoint("usb:write_after", "off=%lu wr=%lu", (unsigned long)offset,
                    (unsigned long)written);
            }
            if (last_written) {
                *last_written = written;
            }
            if (written != TREZOR_WIRE_CHUNK_SIZE) {
                vTaskDelay(pdMS_TO_TICKS(1));
                continue;
            }
#if CFG_TUD_VENDOR_TX_BUFSIZE > 0
            if (checkpoint) {
                trezor_trace_checkpoint("usb:flush_before", "off=%lu", (unsigned long)offset);
            }
            const uint32_t flushed = tud_vendor_write_flush();
            if (checkpoint) {
                trezor_trace_checkpoint("usb:flush_after", "off=%lu fl=%lu", (unsigned long)offset,
                    (unsigned long)flushed);
            }
#endif
            sent = true;
            if (checkpoint) {
                trezor_trace_checkpoint("usb:chunk_done", "off=%lu", (unsigned long)offset);
            }
            break;
        }
        if (!sent) {
            if (checkpoint) {
                trezor_trace_checkpoint("usb:chunk_fail", "off=%lu", (unsigned long)offset);
            }
            return false;
        }
    }
    if (checkpoint) {
        trezor_trace_checkpoint("usb:send_done", "len=%lu", (unsigned long)chunks_len);
    }
    return true;
}

static bool trezor_usb_hid_response_header(
    const uint8_t* const chunks, const size_t chunks_len, uint16_t* const message_type, size_t* const payload_len)
{
    if (!chunks || chunks_len < TREZOR_WIRE_CHUNK_SIZE || !message_type || !payload_len || chunks[0] != TREZOR_WIRE_MARKER
        || chunks[1] != TREZOR_WIRE_MAGIC || chunks[2] != TREZOR_WIRE_MAGIC) {
        return false;
    }

    *message_type = (uint16_t)(((uint16_t)chunks[3] << 8) | chunks[4]);
    *payload_len = ((size_t)chunks[5] << 24) | ((size_t)chunks[6] << 16) | ((size_t)chunks[7] << 8) | chunks[8];
    return true;
}

static bool trezor_usb_hid_response_is_eth_signature(const uint8_t* const chunks, const size_t chunks_len)
{
    if (!chunks || chunks_len == 0) {
        return false;
    }

    uint16_t message_type = 0;
    uint8_t payload[96];
    size_t payload_len = 0;
    bool is_signature = false;
    if (!trezor_wire_decode_message(chunks, chunks_len, &message_type, payload, sizeof(payload), &payload_len)
        || message_type != TREZOR_MSG_ETHEREUM_TX_REQUEST) {
        wally_bzero(payload, sizeof(payload));
        return false;
    }

    bool has_v = false;
    bool has_r = false;
    bool has_s = false;
    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    uint32_t field_number = 0;
    uint8_t wire_type = 0;
    const uint8_t* value = NULL;
    size_t value_len = 0;
    while (reader.pos < reader.len) {
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            wally_bzero(payload, sizeof(payload));
            return false;
        }
        if (field_number == 2 && wire_type == TREZOR_PROTOBUF_WIRE_VARINT) {
            has_v = true;
        } else if (field_number == 3 && wire_type == TREZOR_PROTOBUF_WIRE_LEN && value_len == 32) {
            has_r = true;
        } else if (field_number == 4 && wire_type == TREZOR_PROTOBUF_WIRE_LEN && value_len == 32) {
            has_s = true;
        }
    }

    is_signature = has_v && has_r && has_s;
    wally_bzero(payload, sizeof(payload));
    return is_signature;
}

static void trezor_usb_hid_show_signed_notice(void)
{
    if (s_signed_notice_active) {
        return;
    }
    s_signed_notice_active = true;
    trezor_trace_set_stage("usb:signed_notice");
    dashboard_request_redraw();
    trezor_trace_set_stage("usb:signed_done");
    s_signed_notice_active = false;
}

static bool trezor_usb_hid_ensure_wallet_ready(void)
{
    return wallet_core_is_ready();
}

static bool trezor_usb_hid_needs_local_unlock(void* ctx)
{
    (void)ctx;
    return wallet_core_is_initialized() && !wallet_core_is_ready() && !wallet_core_is_unlocked();
}

static bool trezor_usb_hid_perform_local_unlock(void* ctx)
{
    (void)ctx;
    trezor_trace_set_stage("unlock:pin_ui");
    const bool auth_ok = auth_user_unlock_wallet_with_pin(SOURCE_SERIAL);
    const bool ready = wallet_core_is_ready();
    trezor_trace_set_note("unlock auth=%u ready=%u", auth_ok ? 1U : 0U, ready ? 1U : 0U);
    trezor_trace_set_stage(auth_ok && ready ? "unlock:pin_ok" : "unlock:pin_fail");
    return auth_ok && ready;
}

static bool trezor_usb_hid_get_eth_address(
    void* ctx, const trezor_ethereum_get_address_t* const request, char* const address, const size_t address_len)
{
    (void)ctx;
    trezor_trace_set_stage("eth:req");
    if (!request || !address || address_len != ETHEREUM_CHECKSUM_ADDRESS_STRING_LEN
        || !trezor_usb_hid_ensure_wallet_ready()
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
        idletimer_set_min_timeout_secs(TREZOR_USB_HID_INTERACTIVE_TIMEOUT_SECS);
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

static bool trezor_usb_hid_get_bitcoin_address(
    void* ctx, const trezor_bitcoin_get_address_t* const request, char* const address, const size_t address_len)
{
    (void)ctx;
    if (!request || !address || !trezor_usb_hid_ensure_wallet_ready()
        || !bitcoin_path_is_trezor_connect_state_testnet_p2pkh(request->address_n, request->address_n_len)
        || (request->has_coin_name && strcmp(request->coin_name, "Testnet") != 0)
        || (request->has_script_type && request->script_type != BITCOIN_P2PKH_SPENDADDRESS
            && request->script_type != BITCOIN_P2WPKH_SPENDWITNESS
            && request->script_type != BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS)
        || (request->has_show_display && request->show_display)) {
        return false;
    }

    wallet_core_path_t path;
    memset(&path, 0, sizeof(path));
    path.len = request->address_n_len;
    memcpy(path.parts, request->address_n, request->address_n_len * sizeof(request->address_n[0]));

    const uint32_t script_type = request->has_script_type ? request->script_type : BITCOIN_P2PKH_SPENDADDRESS;
    bool ok = false;
    if (script_type == BITCOIN_P2PKH_SPENDADDRESS) {
        ok = bitcoin_wallet_p2pkh_testnet_address_from_path(&path, address, address_len);
    } else if (script_type == BITCOIN_P2WPKH_SPENDWITNESS) {
        ok = bitcoin_wallet_p2wpkh_testnet_address_from_path(&path, address, address_len);
    } else if (script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS) {
        ok = bitcoin_wallet_p2sh_p2wpkh_testnet_address_from_path(&path, address, address_len);
    }
    wally_bzero(&path, sizeof(path));
    if (!ok) {
        wally_bzero(address, address_len);
    }
    return ok;
}

static bool trezor_usb_hid_get_public_key(
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
    if (!request || !response || !trezor_usb_hid_ensure_wallet_ready()
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

static bool trezor_usb_hid_sign_eth_tx(
    void* ctx, const ethereum_tx_preflight_request_t* const request, ethereum_signature_t* const signature)
{
    (void)ctx;
    if (!request || !signature || !trezor_usb_hid_ensure_wallet_ready()) {
        trezor_trace_set_stage("ethsign:reject");
        return false;
    }
    trezor_trace_set_stage("ethsign:core");
    idletimer_set_min_timeout_secs(TREZOR_USB_HID_INTERACTIVE_TIMEOUT_SECS);
    const bool ok = ethereum_sign_tx(request, signature);
    idletimer_set_min_timeout_secs(0);
    trezor_trace_set_stage(ok ? "ethsign:core_ok" : "ethsign:core_fail");
    return ok;
}

static bool trezor_usb_hid_confirm_btc_tx(void* ctx, const bitcoin_confirm_request_t* const request)
{
    (void)ctx;
    if (!request || !trezor_usb_hid_ensure_wallet_ready()) {
        trezor_trace_set_stage("btcsign:confirm_reject");
        return false;
    }

    chain_confirm_summary_t summary;
    if (!bitcoin_confirm_summary_from_request(request, &summary)) {
        trezor_trace_set_stage("btcsign:summary_fail");
        return false;
    }

    trezor_trace_set_stage("btcsign:display");
    idletimer_set_min_timeout_secs(TREZOR_USB_HID_INTERACTIVE_TIMEOUT_SECS);
    const bool ok = show_chain_confirm_summary_activity(&summary);
    idletimer_set_min_timeout_secs(0);
    trezor_trace_set_stage(ok ? "btcsign:display_ok" : "btcsign:display_cancel");
    return ok;
}

static trezor_session_t trezor_usb_hid_session(void)
{
    const bool initialized = wallet_core_is_initialized();
    const bool ready = wallet_core_is_ready();
    trezor_session_t session = {
        .features = {
            // trezorlib accepts unknown/custom models only when the protocol vendor is one of
            // the official Trezor vendor strings. Keep the custom device identity in fw_vendor,
            // label, model, and internal_model instead of leaking it through the protocol vendor.
            .vendor = "trezor.io",
            .fw_vendor = "Jade T-Display-S3",
            .device_id = s_trezor_device_id,
            .language = "en-US",
            .label = "Jade T-Display-S3",
            .model = "Jade",
            .internal_model = "UNKNOWN",
            .session_id = s_trezor_session_id_initialized ? s_trezor_session_id : NULL,
            .session_id_len = s_trezor_session_id_initialized ? sizeof(s_trezor_session_id) : 0,
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
        .state = &s_trezor_session_state,
        .initialize_session = trezor_usb_hid_initialize_session,
        .initialize_session_ctx = NULL,
        .needs_local_unlock = trezor_usb_hid_needs_local_unlock,
        .needs_local_unlock_ctx = NULL,
        .perform_local_unlock = trezor_usb_hid_perform_local_unlock,
        .perform_local_unlock_ctx = NULL,
        .get_bitcoin_address = trezor_usb_hid_get_bitcoin_address,
        .get_bitcoin_address_ctx = NULL,
        .get_eth_address = trezor_usb_hid_get_eth_address,
        .get_eth_address_ctx = NULL,
        .get_public_key = trezor_usb_hid_get_public_key,
        .get_public_key_ctx = NULL,
        .sign_eth_tx = trezor_usb_hid_sign_eth_tx,
        .sign_eth_tx_ctx = NULL,
        .confirm_btc_tx = trezor_usb_hid_confirm_btc_tx,
        .confirm_btc_tx_ctx = NULL,
    };
    return session;
}

static void trezor_usb_hid_task(void* ignore)
{
    (void)ignore;
    sensitive_init();

    size_t rx_len = 0;
    size_t expected_len = 0;

    while (s_hid_enabled) {
        trezor_usb_hid_chunk_t chunk;
        if (xQueueReceive(s_hid_rx_queue, &chunk, 100 / portTICK_PERIOD_MS) != pdTRUE) {
            continue;
        }
        idletimer_register_activity(false);
        trezor_trace_set_stage("usb:task_rx");
        trezor_trace_set_note("task rx queued=%lu rx_len=%lu", (unsigned long)uxQueueMessagesWaiting(s_hid_rx_queue),
            (unsigned long)rx_len);

        if (rx_len == 0) {
            expected_len = 0;
            trezor_trace_set_stage("usb:expect");
            if (!trezor_usb_hid_expected_wire_len(chunk.bytes, &expected_len)) {
                trezor_trace_set_stage("usb:bad_wire");
                trezor_session_t session = trezor_usb_hid_session();
                size_t tx_len = 0;
                trezor_trace_set_stage("usb:handle_bad");
                if (trezor_session_handle_wire(
                        &session, chunk.bytes, sizeof(chunk.bytes), s_hid_tx_chunks, sizeof(s_hid_tx_chunks), &tx_len)) {
                    uint32_t available = 0;
                    uint32_t written = 0;
                    const bool sent = trezor_usb_hid_send_chunks(s_hid_tx_chunks, tx_len, &available, &written, false);
                    trezor_trace_record_transport_result(sent, tx_len, available, written);
                    trezor_trace_set_stage(sent ? "usb:txdone" : "usb:txfail");
                }
                wally_bzero(s_hid_tx_chunks, sizeof(s_hid_tx_chunks));
                trezor_trace_set_stage("usb:sens_check");
                sensitive_assert_empty();
                trezor_trace_set_stage("usb:idle");
                continue;
            }
            trezor_trace_set_stage("usb:expect_ok");
        } else if (chunk.bytes[0] != TREZOR_WIRE_MARKER) {
            trezor_trace_set_stage("usb:cont_bad");
            rx_len = 0;
            expected_len = 0;
            continue;
        }

        if (rx_len > sizeof(s_hid_rx_chunks) - sizeof(chunk.bytes)) {
            trezor_trace_set_stage("usb:rx_oversize");
            rx_len = 0;
            expected_len = 0;
            continue;
        }
        trezor_trace_set_stage("usb:copy");
        memcpy(s_hid_rx_chunks + rx_len, chunk.bytes, sizeof(chunk.bytes));
        rx_len += sizeof(chunk.bytes);

        if (expected_len != 0 && rx_len >= expected_len) {
            trezor_trace_set_stage("usb:pre_session");
            trezor_session_t session = trezor_usb_hid_session();
            size_t tx_len = 0;
            trezor_trace_set_stage("usb:handle");
            bool show_signed_notice = false;
            if (trezor_session_handle_wire(
                    &session, s_hid_rx_chunks, rx_len, s_hid_tx_chunks, sizeof(s_hid_tx_chunks), &tx_len)) {
                trezor_trace_set_stage("usb:handled");
                uint32_t available = 0;
                uint32_t written = 0;
                uint16_t response_message_type = 0;
                size_t response_payload_len = 0;
                const bool response_header_ok = trezor_usb_hid_response_header(
                    s_hid_tx_chunks, tx_len, &response_message_type, &response_payload_len);
                if (response_header_ok && response_message_type == TREZOR_MSG_ETHEREUM_TX_REQUEST) {
                    trezor_trace_checkpoint("usb:tx_start", "type=%u payload=%lu len=%lu",
                        (unsigned int)response_message_type, (unsigned long)response_payload_len,
                        (unsigned long)tx_len);
                }
                const bool sent = trezor_usb_hid_send_chunks(s_hid_tx_chunks, tx_len, &available, &written,
                    response_header_ok && response_message_type == TREZOR_MSG_ETHEREUM_TX_REQUEST);
                show_signed_notice = sent && trezor_usb_hid_response_is_eth_signature(s_hid_tx_chunks, tx_len);
                trezor_trace_record_transport_result(sent, tx_len, available, written);
                trezor_trace_set_note("usb tx sent=%u len=%lu av=%lu wr=%lu sig=%u", sent ? 1 : 0,
                    (unsigned long)tx_len, (unsigned long)available, (unsigned long)written,
                    show_signed_notice ? 1 : 0);
                trezor_trace_set_stage(sent ? "usb:txdone" : "usb:txfail");
                if (response_header_ok && response_message_type == TREZOR_MSG_ETHEREUM_TX_REQUEST) {
                    trezor_trace_checkpoint(sent ? "usb:txdone" : "usb:txfail", "type=%u payload=%lu len=%lu av=%lu wr=%lu sig=%u",
                        (unsigned int)response_message_type, (unsigned long)response_payload_len,
                        (unsigned long)tx_len, (unsigned long)available, (unsigned long)written,
                        show_signed_notice ? 1U : 0U);
                }
            }
            wally_bzero(s_hid_rx_chunks, rx_len);
            wally_bzero(s_hid_tx_chunks, sizeof(s_hid_tx_chunks));
            if (show_signed_notice) {
                trezor_trace_checkpoint("usb:sens_check", "sig=1");
            } else {
                trezor_trace_set_stage("usb:sens_check");
            }
            sensitive_assert_empty();
            if (show_signed_notice) {
                trezor_trace_checkpoint("usb:sens_ok", "sig=1");
            } else {
                trezor_trace_set_stage("usb:sens_ok");
            }
            if (show_signed_notice) {
                trezor_usb_hid_show_signed_notice();
            }
            if (show_signed_notice) {
                trezor_trace_checkpoint("usb:idle", "after_sig=1 queued=%lu",
                    (unsigned long)uxQueueMessagesWaiting(s_hid_rx_queue));
            } else {
                trezor_trace_set_stage("usb:idle");
            }
            rx_len = 0;
            expected_len = 0;
        }
    }

    vTaskDelete(NULL);
}

bool trezor_usb_hid_init(void)
{
    if (s_hid_enabled) {
        return true;
    }

    s_hid_rx_queue = xQueueCreate(TREZOR_USB_HID_QUEUE_LEN, sizeof(trezor_usb_hid_chunk_t));
    if (!s_hid_rx_queue) {
        return false;
    }
    if (!s_trezor_session_id_initialized) {
        esp_fill_random(s_trezor_session_id, sizeof(s_trezor_session_id));
        s_trezor_session_id_initialized = true;
    }
    trezor_usb_hid_init_device_id();

    const tinyusb_config_t usb_config = {
        .device_descriptor = &TREZOR_USB_HID_DEVICE_DESCRIPTOR,
        .string_descriptor = TREZOR_USB_HID_STRINGS,
        .string_descriptor_count = sizeof(TREZOR_USB_HID_STRINGS) / sizeof(TREZOR_USB_HID_STRINGS[0]),
        .configuration_descriptor = TREZOR_USB_HID_CONFIGURATION_DESCRIPTOR,
    };
    if (tinyusb_driver_install(&usb_config) != ESP_OK) {
        vQueueDelete(s_hid_rx_queue);
        s_hid_rx_queue = NULL;
        return false;
    }

    s_hid_enabled = true;
    if (xTaskCreatePinnedToCore(trezor_usb_hid_task, "trezor_hid", TREZOR_USB_HID_TASK_STACK, NULL,
            TREZOR_USB_HID_TASK_PRIORITY, &s_hid_task, JADE_CORE_SECONDARY)
        != pdPASS) {
        s_hid_enabled = false;
        (void)tinyusb_driver_uninstall();
        vQueueDelete(s_hid_rx_queue);
        s_hid_rx_queue = NULL;
        return false;
    }

    return true;
}

void trezor_usb_hid_deinit(void)
{
    if (!s_hid_enabled) {
        return;
    }
    s_hid_enabled = false;
    vTaskDelay(120 / portTICK_PERIOD_MS);
    s_hid_task = NULL;
    if (s_hid_rx_queue) {
        vQueueDelete(s_hid_rx_queue);
        s_hid_rx_queue = NULL;
    }
    (void)tinyusb_driver_uninstall();
}

bool trezor_usb_hid_enabled(void) { return s_hid_enabled; }

#else

bool trezor_usb_hid_init(void) { return false; }
void trezor_usb_hid_deinit(void) {}
bool trezor_usb_hid_enabled(void) { return false; }

#endif /* CONFIG_TREZOR_USB_HID */
#endif /* AMALGAMATED_BUILD */
