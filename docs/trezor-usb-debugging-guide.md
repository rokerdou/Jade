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

### EthereumSignTx Reboots During Local Confirmation

Symptom:

```text
trezorctl ethereum sign-tx sends EthereumSignTx
host receives LIBUSB_ERROR_NOT_FOUND / NO_DEVICE
device re-enumerates and wallet appears locked
```

Important distinction: the locked state after reboot does not by itself prove a
sensitive-memory leak. `jade_abort()` clears the keychain for any internal abort,
including sensitive-stack assertions, ordinary asserts, and task failures.

Investigation checklist:

- Check the retained trace `reset_last=...` on the USB Trace screen after
  reboot. `last=...` is the latest stage in the current boot and can be
  overwritten by post-reboot `GetFeatures` probes.
- If the last stage is before `ethsign:encoded`, the device aborted before
  returning `EthereumTxRequest(signature)`.
- If the last stage is `usb:sens_check`, inspect `sensitive_assert_empty()` and
  private-key/public-key sensitive stack pairing.
- If the last stage is `idle:reboot`, inspect idle timeout handling around
  local hardware confirmation.
- `usb:idle` is only trustworthy after the USB task has passed
  `sensitive_assert_empty()`. Older firmware set `usb:idle` before the sensitive
  check, so it could mask a sensitive-stack abort.
- Keep traces non-sensitive: do not log private keys, mnemonics, xprivs,
  signatures, raw transaction payloads, addresses, or token amounts.

Verified UI line-limit failure:

```text
reset_last=abort:dialogs.c:306 reset_hwm=5440
boot=2 rr=4 last=abort:dialogs.c:306
```

Root cause: `main/ui/dialogs.c` rejects message dialogs with 5 or more lines:

```c
JADE_ASSERT(message_size < 5);
```

The observed user flow was stable: the device rebooted after the `Nonce` page,
before the next ETH confirmation field became visible. In the ETH native
transfer summary the field order is:

```text
Path -> Chain ID -> Nonce -> From -> Max Fee -> To -> Amount -> Final Confirm
```

The fixed root cause is not a private-key/signing failure and not a
sensitive-memory leak:

- `reset_hwm=5440` showed there was still stack headroom.
- A sensitive-stack leak would leave a `sens:<file>:<line>` crash marker after
  the crash-safe trace hook was added.
- The abort location was the generic UI dialog line-count assert.

Fix:

- Chain confirmation hex display now paginates fields before calling
  `await_continueback_activity()`.
- Each page passes at most `CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES` lines to the
  Jade generic dialog.
- `dialogs.c` records a non-sensitive crash marker such as `dlg:From:5` before
  asserting if any future caller still violates the line limit. The marker
  contains only the UI title and line count, not address/value payloads.

Validation:

```text
EthereumGetAddress -> EthereumAddress
EthereumSignTx -> hardware UI confirmation -> EthereumTxRequest(signature)
EndSession -> Success
```

Expected ETH native-transfer confirmation fields for the test command:

```text
Path: m/44'/60'/0'/0/0
Chain ID: 1
Nonce: 0
From: 0xf2a82bf45c0ea76b3e0e187102858a869d121366
Max Fee: 21000000000000
To: 0x52908400098527886e0f7030069857d2e4169ee7
Amount: 0x01
```

Follow-up gate expectation:

- ETH/ERC20 and TRON confirmation fields that carry 20, 21, or 32 byte values
  must be displayable without tripping the generic dialog line limit.
- Host gates should cover UI pagination/line-count invariants because the
  existing summary tests can verify the fields are present while still missing
  a real UI layout assertion.

Other fixes in the same investigation:

- Do not allocate `trezor_ethereum_signing_state_t` on the `trezor_hid` task
  stack. It contains a large transaction data buffer and belongs in the session
  pending state.
- Register Trezor/WebUSB traffic with the idle timer and temporarily raise the
  minimum idle timeout while local address/transaction confirmation is active.
  Otherwise Jade can treat a pending hardware-wallet confirmation as idle,
  clear the keychain, and reboot while the host is still waiting.
- Keep `sensitive_init()` at task start and `sensitive_assert_empty()` after
  each complete USB request.

### Confirmation Screen Rendering Artifacts

Symptom: `trezorctl ethereum sign-tx` completes, but the device screen shows
stale characters in confirmation fields:

```text
From: ...1366R
To: ...9ee7R
Amount: 0x01 7030069857d2e4169ee7R
```

Root cause: this is a display/UI rendering issue, not a transaction parsing or
signing issue. The affected firmware split long hex fields into multiple dialog
line nodes. On the T-Display-S3 path, switching from a longer multi-line value
to a shorter value could leave stale glyphs visible. The host-side signature was
already valid, so the fix must stay in the UI layer and must not change digest
or signing code.

Fix:

- Format each paginated hex field as one newline-delimited text node before
  calling `await_continueback_activity()`.
- Wrap the dialog message area in an explicit black fill container. This forces
  the value area to be cleared before rendering the next field, which matters on
  the T-Display-S3 display path when moving from a long address to a short
  amount.
- Keep the manual integer and hex formatting helpers; avoid relying on
  printf-length modifiers for money-critical on-device display text.
- Do not call `display_processing_message_activity()` after a successful
  Trezor ETH address or transaction response. That screen is persistent and is
  only appropriate while a later Jade-controlled step will replace it.
- After the final ETH signature response is successfully written to USB, show a
  short `Signed / Sent to host` notice and then request the dashboard to redraw.
  This notice only means the device signed and sent the response; it does not
  mean the host broadcast the transaction or that the chain accepted it.
- While local Trezor confirmation is active, the minimum idle timeout also
  extends the UI dim timeout. Otherwise a long review can dim the screen after
  90 seconds and the first subsequent button press only wakes the screen instead
  of activating the selected button.

T-Display-S3 input note: this board has no touchscreen in the current config.
The top-left back glyph is a selectable UI item, not a touch target. The current
T-Display-S3 config uses `navbtns.inc` plus `selectbtn.inc`, not one-button
mode: a single A/B press moves selection, and pressing both hardware buttons
together triggers `gui_front_click()` to activate the currently selected button.

Gate:

- Native ETH transfer summaries now assert that the `Amount` field copied into
  the confirmation summary is exactly one byte for the `1 wei` test vector. This
  catches accidental reuse of adjacent address bytes before flashing hardware.

Expected screen fields for the ETH native-transfer test:

```text
From:
0xf2a82bf45c0ea76b3e
0e187102858a869d121366

To:
0x52908400098527886e0f
7030069857d2e4169ee7

Amount:
0x01
```

Follow-up root-cause boundary for the Amount artifact:

- The ETH native-transfer gate proves the confirmation summary `Amount` field is
  one byte (`0x01`) for this test vector. If the device screen also shows
  `703006985...9ee7`, that substring matches the previous `To` address field
  and should be treated as a UI rendering/state-clearing bug unless a summary
  gate fails.
- The UI now renders paginated hex fields with exactly four fixed line nodes.
  Short fields such as `Amount: 0x01` still occupy and clear the remaining
  lines, so switching from a two-line address field cannot leave old address
  glyphs in the value area.

### Final Confirm Does Not Return Signature

Symptom: the `Final Confirm` page is visible, pressing both T-Display-S3
hardware buttons appears to do nothing, and the host keeps waiting for
`EthereumTxRequest(signature)`.

Important flow boundary:

```text
Final Confirm BTN_YES
  -> ethereum_authorize_tx() returns true
  -> ethereum_digest_authorized_tx()
  -> wallet_core_sign_digest()
  -> EthereumTxRequest(signature)
  -> USB IN write
```

Therefore, if the button event does not become `BTN_YES`, no digest, signature,
or USB response is produced. This is a UI event/selection issue, not a USB send
issue.

Fix:

- Do not use the custom single-footer-button `Sign` dialog for final signing.
  The final page now reuses Jade's existing Yes/No footer layout with button
  text `Cancel | Sign`, defaulting to `Sign`.
- Intermediate transaction detail pages treat the top-left `Back` action as
  "previous detail page", not "cancel signing". Only backing out before the
  first detail page, or pressing `Cancel` on the final page, rejects the USB
  signing request.
- Add non-sensitive retained trace stages in the GUI path:
  `gui:front`, `gui:front_dim`, `gui:btn_yes`, `gui:btn_no`, and
  `gui:no_select`.
- Existing dialog trace stages then show whether the event reached the dialog:
  `dlg:btn_yes`, `dlg:btn_no`, `ui:final_ok`, or `ui:final_cancel`.

Crash/hang debugging:

- After a reboot, use USB Trace `reset_last=...` and `last=...`; these stages
  are retained in RTC memory across software resets.
- If the latest stage is `gui:no_select`, the activity had no valid selected
  button at the moment both hardware buttons were pressed.
- If it reaches `dlg:btn_yes` but not `ui:final_ok`, inspect
  `await_yesno_activity_loop()`.
- If it reaches `ui:final_ok` but not `ethsign:encoded`, inspect digest/signing
  and sensitive-stack cleanup.
- If it reaches `ethsign:encoded` but not `usb:txdone`, inspect the USB IN
  transport path.

Verified post-send infinite loop:

```text
@50 usb:tx_start type=59 payload=70 len=128
@88 usb:chunk_done off=64
@89 usb:send_done len=128
```

Root cause found: the device had already written both 64-byte USB chunks, and
the host had received `EthereumTxRequest(signature)`. The firmware then tried
to inspect the just-encoded response so it could briefly show `Signed / Sent to
host`. That helper used this unsafe pattern:

```c
while (trezor_protobuf_reader_next(&reader, ...)) {
    ...
}
```

At that time `trezor_protobuf_reader_next()` returned true at EOF without
advancing `reader.pos`, so the loop never exited after parsing the signature
fields. This exactly matches the observed failure: signature reached the host,
but the device never advanced to `usb:txdone`, `usb:sens_check`, or `usb:idle`,
so `EndSession` later failed.

Fix:

- Signature-response inspection now loops with `while (reader.pos < reader.len)`.
- `trezor_protobuf_reader_next()` now returns false at EOF, not true with an
  empty field. This makes the parser fail-fast if a future caller accidentally
  uses `reader_next()` as the loop condition.
- `eth_tron_address_gate` asserts this EOF behavior as a compile/test gate.
- Keep the diagnostic checkpoints until the next hardware run confirms
  `usb:txdone -> usb:sens_ok -> usb:idle` after ETH signing.

### Infinite Loop Audit Checklist

Host-originated USB/protobuf data is untrusted. Any loop reachable from the USB
task must satisfy at least one of these conditions:

- The loop condition is bounded by an input length or fixed array length.
- The loop body always advances the cursor/index on every successful iteration.
- The loop has a fixed retry/timeout limit for external state such as USB TX
  availability or a queue.
- The loop is an intentional UI event loop and has visible cancellation/back
  behavior.

Audit findings for this incident:

- Protobuf readers in `main/protocols/trezor/*.c`, `ethereum_definitions.c`,
  `public_key.c`, `session.c`, `trace.c`, and `bitcoin.c` use
  `while (reader.pos < reader.len)`, which is the correct bounded form.
- USB IN sending uses a fixed 200-retry cap per 64-byte chunk.
- The Trezor USB task waits on `xQueueReceive(..., 100ms)` inside
  `while (s_hid_enabled)`, so the task can keep servicing state without a
  permanent blocking receive.
- `trezor_wire_encode_message()` and `trezor_wire_decode_message()` loop on
  copied payload length and advance `copied` on every successful iteration.
- ETH amount/digest formatting loops are bounded by fixed integer widths
  (`uint64_t` or 32-byte EVM words) and explicit maximum decimal lengths.
- Chain confirmation pagination advances field/page offsets and is bounded by
  `summary->num_fields`, fixed hex-line widths, and per-field byte limits.
- UI `while (true)` loops are expected modal loops, but they must be paired with
  non-sensitive retained stages before and after the user event so a hang can be
  separated from a crash or USB stall.
- Existing Jade process/GUI helpers such as `jade_process_push_in_message()`,
  `jade_process_push_out_message()`, `gui_repaint()`, and
  `gui_set_current_activity_ex()` retry ringbuffer sends indefinitely. This is
  not the root cause of the observed ETH signing hang, and
  `dashboard_request_redraw()` is non-blocking, but it is a residual robustness
  risk: if a consumer task is dead or permanently wedged, a wallet operation can
  wait forever. New USB wallet flows should prefer bounded sends or return a
  non-sensitive failure to the host.
- No loop may log private keys, mnemonics, PINs, xprivs, encrypted key material,
  signatures, full raw transaction payloads, or signing digests while being
  diagnosed.

### Locked Wallet Local PIN Unlock

Expected Trezor USB flow when the wallet is initialized but locked:

```text
Host request, e.g. EthereumSignTx
  -> device returns ButtonRequest(pin-entry)
  -> host sends ButtonAck
  -> device shows local PIN UI
  -> local PIN KDF derives AES key
  -> keychain_load()
  -> original request is replayed
```

The PIN is never requested over USB and must not appear in traces. The
diagnostic stages for this flow are intentionally non-sensitive:

```text
unlock:defer
unlock:ack
unlock:perform
unlock:pin_ui
auth:pin_start
auth:aes_ready
auth:load_ok / auth:load_fail
auth:done
unlock:pin_ok / unlock:pin_fail
unlock:replay
unlock:replay_ok / unlock:replay_fail
```

How to interpret failures:

- Stuck at `unlock:defer`: host did not send `ButtonAck` after `ButtonRequest`.
- Stuck at `auth:pin_start`: user is still in local PIN entry, or the UI did not
  deliver the final PIN confirmation event.
- Stuck at `auth:aes_ready`: local KDF completed, next step is encrypted
  keychain load.
- `auth:load_fail`: wrong PIN, changed local PIN salt/domain, corrupted
  encrypted wallet blob, or an old wallet saved with a different local-PIN
  derivation policy.
- `unlock:pin_ok` but not `unlock:replay_ok`: local unlock succeeded, but replay
  of the original host request failed.

### Trace Storage Policy

USB trace must be useful for diagnosis without wearing flash or leaking secrets.

- `trezor_trace_set_stage()` and `trezor_trace_set_note()` keep the latest
  non-sensitive state in RTC/no-init memory so it can survive a software reset.
- `trezor_trace_checkpoint()` no longer writes checkpoint history to NVS by
  default. It only persists checkpoints if a debug build explicitly enables
  `CONFIG_TREZOR_TRACE_PERSIST_CHECKPOINTS`.
- The Options/Info menu has `Clear USB Logs`, which erases the old
  `TZTRACE/hist` NVS checkpoint blob and clears the current in-memory USB trace.
- This clear action does not erase wallet data, PIN data, seed material,
  encrypted key material, or the NVS key partition.

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
