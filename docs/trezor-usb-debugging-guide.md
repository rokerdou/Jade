# Trezor USB Debugging Guide

This guide records the verified failure modes seen while bringing up the
T-Display-S3 Trezor/WebUSB transport. Keep USB traces non-sensitive: do not log
mnemonics, private keys, PINs, signatures, encrypted key material, or raw
transaction payloads unless they are known public test vectors.

## Baseline Commands

Build:

```sh
. ~/esp/esp-idf/export.sh >/dev/null && idf.py \
  -B build-tdisplays3-hardened-ok \
  -D SDKCONFIG=build-tdisplays3-hardened-ok/sdkconfig \
  -D SDKCONFIG_DEFAULTS=configs/sdkconfig_display_ttgo_tdisplays3_hardened.defaults \
  build
```

Flash:

```sh
. ~/esp/esp-idf/export.sh >/dev/null && idf.py \
  -B build-tdisplays3-hardened-ok \
  -D SDKCONFIG=build-tdisplays3-hardened-ok/sdkconfig \
  -D SDKCONFIG_DEFAULTS=configs/sdkconfig_display_ttgo_tdisplays3_hardened.defaults \
  -p /dev/cu.usbmodem101 flash
```

Protocol tests:

```sh
/tmp/trezorctl-venv/bin/trezorctl get-features
/tmp/trezorctl-venv/bin/trezorctl -v ethereum get-address -n "m/44h/60h/0h/0/0"
```

Security config check:

```sh
rg "CONFIG_SECURE_BOOT=|CONFIG_SECURE_FLASH_ENC_ENABLED=|CONFIG_FLASH_ENCRYPTION_ENABLED=" \
  build-tdisplays3-hardened-ok/sdkconfig configs/sdkconfig_display_ttgo_tdisplays3_hardened.defaults
```

For debug builds, the expected result is no enabled Secure Boot or Flash
Encryption setting. `CONFIG_SECURE_BOOT_V2_RSA_SUPPORTED=y` is only an IDF/chip
capability flag.

## Verified Symptoms And Causes

### Host Cannot Open Device

Symptom:

```text
Unable to open device
Inactive device
This device is used by another application
```

Likely cause: browser, wallet extension, Trezor Suite, or another process owns
the WebUSB device.

Checks:

```sh
lsof /dev/cu.usbmodem101
ioreg -p IOUSB -l -w0 | grep -A35 -B5 TREZOR
```

If `UsbExclusiveOwner` shows a browser or wallet process, close that app before
running `trezorctl`.

### Flash Port Changes In Bootloader Mode

Symptom: normal firmware appears as one `/dev/cu.usbmodem*` port, bootloader as
another, or the port appears only while holding the correct boot button.

Check:

```sh
while true; do
  clear
  date
  ls /dev/cu.* | grep -E 'usb|modem|serial' || true
  sleep 0.5
done
```

Use the port visible in ESP32-S3 download mode, not the normal app port.

### Initialize/Features Read Timeout

Symptom: host sends `Initialize`, device trace shows `init>feat`, but host times
out reading 64-byte IN packets. Device trace may show `txbad ... w0`.

Cause found: TinyUSB vendor IN path was configured with no effective TX buffer
and sent an unwanted zero-length packet behavior for this transport.

Fix area:

- `managed_components/espressif__esp_tinyusb/include/tusb_config.h`
- `managed_components/espressif__tinyusb/src/class/vendor/vendor_device.c`

The Trezor/WebUSB path uses buffered vendor TX and disables ZLP for this class.

### Connect Receives Features But Stops

Symptom: trace repeats `GetFeatures > Features`, but wallet UI does not progress.

Known compatibility requirements:

- `Features.vendor` must be `trezor.io` for trezorlib/connect compatibility.
- Custom identity belongs in fields such as `fw_vendor`, `label`, `model`, and
  `internal_model`.
- `internal_model=UNKNOWN` should use a conservative firmware version range.
- `capabilities` must include the chains advertised by the firmware.

Do not use misleading official model/version values unless the implemented
protocol behavior actually matches that model.

### EthereumGetAddress Causes Locked Screen Then Reboot

Symptom:

```text
EthereumGetAddress(show_display=False)
device appears locked/unlocked transition
after about 5 seconds device reboots
reset reason rr=4
```

Root cause found: `trezor_hid` is a new FreeRTOS task. ETH address derivation
enters `wallet_core_get_public_key(... UNCOMPRESSED ...)`, which calls
`SENSITIVE_PUSH(compressed_pubkey)`. The task did not call `sensitive_init()`,
so Jade's sensitive-memory framework asserted:

```text
sensitive_init() has not been called for task 'trezor_hid'
```

`jade_abort()` then clears keychain, displays an error/locked state, waits about
5 seconds, and aborts/reboots.

Fix:

- Call `sensitive_init()` once when `trezor_hid` starts.
- Call `sensitive_assert_empty()` after each complete USB request.

Validation:

```text
EthereumGetAddress -> EthereumAddress
EndSession -> Success
subsequent get-features remains unlocked=True
```

### EndSession Returns Unsupported Message

Symptom: ETH address succeeds, but trezorlib closes with:

```text
Failed to end session: UnexpectedMessage: Unsupported message
```

Cause found: `EndSession` was missing from the supported lifecycle messages.

Trezor reference behavior: `EndSession` is allowed while locked and returns
`Success()`.

Fix:

- Add message type `EndSession = 83`.
- Accept empty payload only.
- Clear pending local-unlock state.
- Return empty `Success`.

### PublicKey xpub/Node Mismatch

Symptom:

```text
pubKey2bjsNode: Invalid public key transmission detected
```

Root cause found: the `HDNodeType.fingerprint` field must be the immediate
parent fingerprint of the exported node. It must match the parent fingerprint
embedded inside the exported xpub. The broken code used the current node's
HASH160, so both fields looked individually valid but described different
BIP32 nodes.

Trezor reference behavior:

- Ethereum `GetPublicKey` reuses Bitcoin public-node generation.
- The response returns `EthereumPublicKey(node=resp.node, xpub=resp.xpub)`.
- `node.fingerprint()` and `node.serialize_public(...)` therefore come from
  the same derived node object.

Fix:

- Build `wallet_core_public_node_t.fingerprint` from `derived.parent160`.
- Keep `xpub`, `depth`, `child_num`, `chain_code`, and compressed `public_key`
  copied from the same derived public node.

Gate:

```sh
./build-tdisplays3-hardened-ok/wallet_core_public_node_gate
```

This gate compiles the real `wallet_core/wallet_core.c` with controlled host
stubs and fails if the exported public-node fields disagree. It exists because
the broader ETH/TRON protocol gate intentionally mocks `wallet_core`, so it
cannot catch this class of real-derivation bugs.

## Hardware-Specific Pitfall

T-Display-S3 has no Jade-style PMIC/VBUS status path. Do not treat USB suspend
as physical disconnect. WebUSB can be mounted but idle/suspended. For this board,
`usb_is_powered()` should use `tud_mounted()` as the primary connected signal.

## Remaining Security Work

The original Jade keychain state is global and not designed around a new
parallel Trezor USB worker. Calls such as `keychain_get()`, `keychain_clear()`,
and `wallet_get_hdkey()` can be reached from different tasks.

Before adding signing flows, design a single wallet-core access boundary:

- serialize all keychain reads/writes, or
- protect keychain access with a carefully scoped mutex, and
- test disconnect, idle timeout, local PIN unlock, address export, and signing
  under concurrent USB traffic.

This is a safety and availability issue first: a malicious host must not be able
to trigger assert/reboot loops, and no sensitive key material may be exposed or
left uncleared.
