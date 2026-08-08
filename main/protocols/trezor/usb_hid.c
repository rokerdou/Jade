#ifndef AMALGAMATED_BUILD
#include "usb_hid.h"

#ifdef CONFIG_TREZOR_USB_HID

#include "messages.h"
#include "public_key.h"
#include "session.h"
#include "wire.h"

#include "../../chains/bitcoin/path.h"
#include "../../chains/bitcoin/wallet.h"
#include "../../chains/ethereum/address.h"
#include "../../chains/ethereum/path.h"
#include "../../chains/ethereum/wallet.h"
#include "../../jade_assert.h"
#include "../../jade_tasks.h"
#include "../../process/auth_user.h"
#include "../../process.h"
#include "../../wallet_core/wallet_core.h"

#include <esp_err.h>
#include <esp_random.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>
#include <stdint.h>
#include <string.h>
#include <tinyusb.h>
#include <tusb.h>
#include <wally_crypto.h>

#define TREZOR_USB_HID_VID 0x1209
#define TREZOR_USB_HID_PID 0x53C1
#define TREZOR_USB_HID_RELEASE 0x0200
#define TREZOR_USB_HID_ENDPOINT 0x01
#define TREZOR_USB_HID_QUEUE_LEN 4
#define TREZOR_USB_HID_TASK_STACK 8192
#define TREZOR_USB_HID_TASK_PRIORITY 5
#define TREZOR_USB_HID_RX_BUF_LEN 1152
#define TREZOR_USB_HID_TX_BUF_LEN 1152
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
static uint8_t s_trezor_session_id[TREZOR_FEATURES_SESSION_ID_LEN];
static bool s_trezor_session_id_initialized = false;

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
    "000000000000000000000000",
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
    if (!s_hid_rx_queue || instance != 0 || !buffer || bufsize != TREZOR_WIRE_CHUNK_SIZE) {
        return;
    }

    trezor_usb_hid_chunk_t chunk;
    memcpy(chunk.bytes, buffer, sizeof(chunk.bytes));
    (void)xQueueSend(s_hid_rx_queue, &chunk, 0);
    tud_vendor_read_flush();
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

static bool trezor_usb_hid_send_chunks(const uint8_t* const chunks, const size_t chunks_len)
{
    if (!chunks || chunks_len == 0 || chunks_len % TREZOR_WIRE_CHUNK_SIZE != 0) {
        return false;
    }

    for (size_t offset = 0; offset < chunks_len; offset += TREZOR_WIRE_CHUNK_SIZE) {
        bool sent = false;
        for (size_t retry = 0; retry < 200; ++retry) {
            if (tud_vendor_mounted() && tud_vendor_n_write_available(0) >= TREZOR_WIRE_CHUNK_SIZE
                && tud_vendor_write(chunks + offset, TREZOR_WIRE_CHUNK_SIZE) == TREZOR_WIRE_CHUNK_SIZE) {
#if CFG_TUD_VENDOR_TX_BUFSIZE > 0
                (void)tud_vendor_write_flush();
#endif
                sent = true;
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(1));
        }
        if (!sent) {
            return false;
        }
    }
    return true;
}

static bool trezor_usb_hid_ensure_wallet_ready(void)
{
    if (wallet_core_is_ready()) {
        return true;
    }
    if (!wallet_core_is_initialized() || wallet_core_is_unlocked()) {
        return false;
    }

    return auth_user_unlock_wallet_with_pin(SOURCE_SERIAL) && wallet_core_is_ready();
}

static bool trezor_usb_hid_get_eth_address(
    void* ctx, const trezor_ethereum_get_address_t* const request, char* const address, const size_t address_len)
{
    (void)ctx;
    if (!request || !address || address_len != ETHEREUM_CHECKSUM_ADDRESS_STRING_LEN
        || !trezor_usb_hid_ensure_wallet_ready()
        || !ethereum_path_is_supported(request->address_n, request->address_n_len)) {
        return false;
    }

    wallet_core_path_t path;
    memset(&path, 0, sizeof(path));
    path.len = request->address_n_len;
    memcpy(path.parts, request->address_n, request->address_n_len * sizeof(request->address_n[0]));

    uint8_t raw_address[ETHEREUM_ADDRESS_LEN];
    bool ok = ethereum_wallet_address_from_path(&path, raw_address, sizeof(raw_address))
        && ethereum_address_to_checksum_string(raw_address, sizeof(raw_address), address, address_len);
    wally_bzero(&path, sizeof(path));
    wally_bzero(raw_address, sizeof(raw_address));
    if (!ok) {
        return false;
    }

    if (request->has_show_display && request->show_display && !show_confirm_address_activity(address, false)) {
        wally_bzero(address, address_len);
        return false;
    }

    return true;
}

static bool trezor_usb_hid_get_bitcoin_address(
    void* ctx, const trezor_bitcoin_get_address_t* const request, char* const address, const size_t address_len)
{
    (void)ctx;
    if (!request || !address || !trezor_usb_hid_ensure_wallet_ready()
        || !bitcoin_path_is_trezor_connect_state_testnet_p2pkh(request->address_n, request->address_n_len)
        || (request->has_coin_name && strcmp(request->coin_name, "Testnet") != 0)
        || (request->has_script_type && request->script_type != BITCOIN_P2PKH_SPENDADDRESS)
        || (request->has_show_display && request->show_display)) {
        return false;
    }

    wallet_core_path_t path;
    memset(&path, 0, sizeof(path));
    path.len = request->address_n_len;
    memcpy(path.parts, request->address_n, request->address_n_len * sizeof(request->address_n[0]));

    const bool ok = bitcoin_wallet_p2pkh_testnet_address_from_path(&path, address, address_len);
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
    if (!request || !response || !trezor_usb_hid_ensure_wallet_ready()
        || !ethereum_path_is_public_key_export_supported(request->address_n, request->address_n_len)
        || (request->has_show_display && request->show_display)) {
        return false;
    }

    wallet_core_path_t path;
    memset(&path, 0, sizeof(path));
    path.len = request->address_n_len;
    memcpy(path.parts, request->address_n, request->address_n_len * sizeof(request->address_n[0]));

    wallet_core_public_node_t node;
    bool ok = wallet_core_get_public_node(&path, &node);
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

static trezor_session_t trezor_usb_hid_session(void)
{
    const bool initialized = wallet_core_is_initialized();
    trezor_session_t session = {
        .features = {
            .vendor = "jade.tdisplay-s3",
            .fw_vendor = "Jade T-Display-S3",
            .device_id = "000000000000000000000000",
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
            .unlocked = wallet_core_is_ready(),
            .pin_protection = initialized,
            .passphrase_protection = false,
            .capabilities = { TREZOR_CAPABILITY_BITCOIN, TREZOR_CAPABILITY_BITCOIN_LIKE, TREZOR_CAPABILITY_ETHEREUM },
            .capabilities_len = 3,
        },
        .get_bitcoin_address = trezor_usb_hid_get_bitcoin_address,
        .get_bitcoin_address_ctx = NULL,
        .get_eth_address = trezor_usb_hid_get_eth_address,
        .get_eth_address_ctx = NULL,
        .get_public_key = trezor_usb_hid_get_public_key,
        .get_public_key_ctx = NULL,
    };
    return session;
}

static void trezor_usb_hid_task(void* ignore)
{
    (void)ignore;
    uint8_t rx_chunks[TREZOR_USB_HID_RX_BUF_LEN];
    uint8_t tx_chunks[TREZOR_USB_HID_TX_BUF_LEN];
    size_t rx_len = 0;
    size_t expected_len = 0;

    while (s_hid_enabled) {
        trezor_usb_hid_chunk_t chunk;
        if (xQueueReceive(s_hid_rx_queue, &chunk, 100 / portTICK_PERIOD_MS) != pdTRUE) {
            continue;
        }

        if (rx_len == 0) {
            expected_len = 0;
            if (!trezor_usb_hid_expected_wire_len(chunk.bytes, &expected_len)) {
                trezor_session_t session = trezor_usb_hid_session();
                size_t tx_len = 0;
                if (trezor_session_handle_wire(
                        &session, chunk.bytes, sizeof(chunk.bytes), tx_chunks, sizeof(tx_chunks), &tx_len)) {
                    (void)trezor_usb_hid_send_chunks(tx_chunks, tx_len);
                }
                continue;
            }
        } else if (chunk.bytes[0] != TREZOR_WIRE_MARKER) {
            rx_len = 0;
            expected_len = 0;
            continue;
        }

        if (rx_len > sizeof(rx_chunks) - sizeof(chunk.bytes)) {
            rx_len = 0;
            expected_len = 0;
            continue;
        }
        memcpy(rx_chunks + rx_len, chunk.bytes, sizeof(chunk.bytes));
        rx_len += sizeof(chunk.bytes);

        if (expected_len != 0 && rx_len >= expected_len) {
            trezor_session_t session = trezor_usb_hid_session();
            size_t tx_len = 0;
            if (trezor_session_handle_wire(&session, rx_chunks, rx_len, tx_chunks, sizeof(tx_chunks), &tx_len)) {
                (void)trezor_usb_hid_send_chunks(tx_chunks, tx_len);
            }
            wally_bzero(rx_chunks, rx_len);
            wally_bzero(tx_chunks, sizeof(tx_chunks));
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
