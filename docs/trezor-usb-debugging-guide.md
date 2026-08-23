# Trezor USB Debugging Guide

This guide records the verified failure modes seen while bringing up the
T-Display-S3 Trezor/WebUSB transport. Keep USB traces non-sensitive: do not log
mnemonics, private keys, PINs, signatures, encrypted key material, or raw
transaction payloads unless they are known public test vectors.

## Baseline Commands

Fast host gates before flashing:

```sh
tools/run_host_gates.sh
tools/run_host_gates.sh build-tdisplays3-hardened-ok --no-build
```

Run these before any firmware flash. They execute on the development host and
cover non-sensitive protocol/session checks, ETH/TRON/BTC address-path rules,
Trezor wire/protobuf edge cases, signing-summary binding, and T-Display-S3
confirmation UI constraints. They do not exercise TinyUSB, FreeRTOS scheduling,
physical buttons, or the real LCD renderer, so a final hardware smoke test is
still required for transport and display acceptance.

The host gates must not only prove that local code is internally consistent.
They also include external-oracle checks against mainstream community libraries:

- `eth-keys` derives the public key/address from the fixed public test private
  key.
- `eth-utils` computes Keccak/EIP-55 checksum addresses and ETH transaction
  hashes.
- `rlp` builds legacy/EIP-155 and EIP-1559 signing payloads.
- `base58` and Python `hashlib` check BTC testnet P2PKH and TRON Base58Check
  address strings.
- `trezorlib` builds official Trezor protobuf messages for
  `Initialize`, `GetFeatures`, `EthereumGetAddress`, `GetAddress`,
  `GetPublicKey`, `EthereumSignTx`, `EthereumSignTxEIP1559`, ERC20 transfer
  with `EthereumDefinitions`, and BTC `SignTx`; the test wraps those payloads in
  local Trezor Protocol v1 wire frames, feeds them into the local session
  handler, and decodes the response with `trezorlib`.
- BTC `SignTx` is also covered by a trezorlib host-flow oracle that calls
  `trezorlib.btc.sign_tx()` directly. The scripted device side requires the
  official interactive sequence:
  `SignTx -> TxRequest(TXINPUT) -> TxAck(input) ->
  TxRequest(TXOUTPUT) -> TxAck(output) ->
  TxRequest(TXFINISHED)`.
  Current transaction metadata is already carried in `SignTx`; the firmware
  must not require a no-`tx_hash` current `TXMETA`, because Sparrow/Lark treats
  that as an unexpected request. Prev-tx verification still uses
  `TxRequest(TXMETA)` with `details.tx_hash`.
- BTC protobuf parsing now has host gates for the safe subset needed by that
  flow: `SignTx`, `TxAck(TransactionType.inputs)`,
  `TxAck(TransactionType.outputs)`, `TxAck(TransactionType meta)`, and
  `TxRequest` encoding. These gates validate counts, path length, hash length,
  supported script types, address/string bounds, and unsupported field
  rejection before any wallet signing code is reachable.
- BTC session preflight now accepts `SignTx` and stateful `TxAck` only for the
  bounded Testnet subset. It collects meta, one input at a time, one output at a
  time, validates input/output totals, computes fee, then returns
  `Failure(ActionCancelled, "Bitcoin signing disabled")` before any private key
  or signature code is reachable. Before that terminal failure it builds a
  Bitcoin confirmation summary containing path, recipient address, amount, and
  fee, and asks the hardware UI to confirm it. Orphan or out-of-order `TxAck`
  returns `Failure(DataError)` and clears the pending state.

These Python packages are development-test dependencies only. They are installed
into `.host-oracle-venv/` and are not linked into firmware or ESP-IDF builds.

Current host-gate coverage:

- ETH/TRON/BTC path and public-address mapping checks. BTC currently covers
  testnet P2PKH, native P2WPKH, and P2SH-P2WPKH address derivation from the
  same compressed public key.
- BTC public node/xpub safety checks, including rejecting private-key fields in
  public-node responses.
- ETH legacy/EIP-155 and EIP-1559 signing payload/digest vectors.
- Trezorlib-generated `EthereumSignTxEIP1559` requests must return a valid
  `EthereumTxRequest(signature)` response.
- ERC20/TRC20 `transfer(address,uint256)` and `approve(address,uint256)` ABI
  parsing and summary binding.
- Trezorlib-generated ERC20 transfer requests with official
  `EthereumDefinitions(encoded_token=...)` wrapping must reach the signing
  response path; this prevents confusing local raw field-12 bytes with the
  official nested protobuf message.
- Trezor Protocol v1 wire chunking, malformed marker/header/length rejection,
  and oversized payload rejection.
- Protobuf EOF and malformed field rejection, including field zero, unsupported
  wire type, truncated varint, overlong varint, truncated length-delimited
  fields, oversized field lengths, and too-large field numbers.
- Fake hardware confirmation UI rejects summaries that cannot be rendered within
  the T-Display-S3/Jade message line limits. Text fields, including BTC bech32
  addresses, are paginated into at most four display lines per page; long text
  must never be silently truncated.
- Sensitive or unsupported Trezor messages such as `GetEntropy`, `LoadDevice`,
  `ResetDevice`, `TxAckPaymentRequest`, `CipherKeyValue`, `BackupDevice`,
  `RecoveryDevice`, and `UnlockPath` are rejected before reaching key material.
- The same sensitive/unsupported messages are also checked through the full
  Trezor wire/session path. BTC `SignTx`/`TxAck` may enter only the preflight
  state machine described above; until BTC signing is fully implemented, that
  state machine must terminate before wallet signing code and must not return a
  signature or serialized transaction. A parser passing its host gate is not
  sufficient reason to call wallet signing code.
- Malformed wire packets are checked to return `Failure(InvalidProtocol)` rather
  than crashing, hanging, or leaking parser state.

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
- Sparrow/Lark rejects unknown Trezor-compatible models before it reaches BTC
  protocol calls. For Sparrow compatibility this firmware reports
  `model=Safe 5`, `internal_model=T3T1`, and version `2.1.0`; keep the actual
  custom identity in `fw_vendor` and `label`.
- `capabilities` must include the chains advertised by the firmware.

Do not use misleading official model/version values unless the implemented
protocol behavior actually matches that model.

### Local PIN Unlock Works On macOS But Appears To Fail On Windows

Symptom: the same wallet can be unlocked with the local PIN while connected to
macOS, but when connected to Windows the PIN entry returns to locked/unlocked UI
or never stays usable for host signing.

Cause found on T-Display-S3: local PIN unlock marks the keychain as
`SOURCE_SERIAL`. The Jade dashboard then clears a persisted serial keychain when
`usb_is_powered()` reports false. On T-Display-S3 there is no reliable VBUS sense
path, so `usb_is_powered()` used TinyUSB `tud_mounted()` plus a battery-voltage
fallback. Windows driver/mount/suspend behavior can make `tud_mounted()` false
while the board is still physically connected, immediately clearing the
successfully decrypted keychain.

Security rule: USB host mount state is untrusted and must not control the
lifetime of locally PIN-unlocked key material on T-Display-S3 Trezor HID builds.
Use explicit lock, idle timeout, reboot, or real hardware power state instead.
BLE disconnect clearing remains valid because BLE connection state is the chosen
authenticated channel state.

### Hidden Wallet Unlock Re-enters PIN

Symptom: after a correct PIN, the hidden-wallet/passphrase keyboard flashes and
the device immediately asks for PIN again. Entering the same correct PIN then
shows `Incorrect PIN`.

Root cause: a BIP39-passphrase wallet stores encrypted mnemonic entropy. A
correct PIN can decrypt that entropy and set `mnemonic_entropy_len`, but the
wallet is not fully unlocked until the passphrase derives the final keychain.
If USB `ButtonAck` or another local unlock path re-enters unlock during this
middle state, `keychain_load()` rejects because mnemonic entropy is already
cached. That rejection was reported as a PIN failure even though the PIN had
already succeeded.

Rules:

- Dashboard/local unlock must use `SOURCE_INTERNAL`, not `SOURCE_SERIAL`.
- Only one local PIN/passphrase unlock flow may run at a time.
- If `keychain_requires_passphrase()` is already true, resume passphrase entry
  instead of asking for PIN again.
- `auth:busy` means another local unlock is already in progress; it is not a
  bad PIN and must not decrement PIN attempts.
- `auth:resume_pass` means the PIN stage has already succeeded and the device
  is continuing the hidden-wallet passphrase stage.

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

Root cause: this is a display/UI pagination issue, not a transaction parsing or
signing issue. `show_text_value()` and `show_hex_value()` advanced the source
offset by a fixed line width even when the copied line stopped at the string's
NUL terminator. Short values such as `1 wei` or `0x01` could therefore skip past
the terminator and read uninitialized tail bytes as a second line. The
host-side signature was already valid, so the fix belongs in the UI formatter
and must not change digest or signing code.

Fix:

- Advance paginated text and hex fields by the number of characters actually
  copied, not by the maximum line width.
- Stop the outer page loop exactly at the source NUL terminator; never inspect
  bytes after it.
- Keep four fixed line nodes per page so the T-Display-S3 value area is fully
  repainted before rendering the next field.
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

- Native ETH transfer summaries assert that the `Amount` field copied into the
  confirmation summary is exactly one byte for the `1 wei` test vector.
- The host gate now also exercises the real UI line-copy formatter with buffers
  whose unused tail is filled with `R`, proving that short text/hex values stop
  at NUL and do not render a garbage follow-up line.

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
- The UI now renders paginated values with exactly four fixed line nodes per
  page, and each copied line reports its actual consumed length. Short fields
  such as `Amount: 0x01` stop at their real terminator, so switching from a
  two-line address field cannot append old address bytes or other stack tail
  data to the value area.

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

### Host-Triggered UI Activity Lifetime Audit

Symptom:

```text
The visible dialog can still move selection between buttons, but pressing the
confirm gesture does nothing. Repeating the same host request makes the failure
appear more often.
```

Root cause class: external USB/protocol requests can create many managed
activities, wait semaphores, and event-handler links without returning through
the dashboard cleanup point. Once enough stale activities accumulate, event
handler registration or the activity event chain can fail in a way that leaves a
visible page selectable but without a working `GUI_BUTTON_EVENT` handler for
the waiting caller.

Audit result:

- High risk: Trezor-compatible USB flows that a host can trigger repeatedly:
  `GetEntropy`, address display confirmations, ETH/BTC/Safe transaction review
  pages, and future TRON confirmations.
- Medium risk: Jade native RPC confirmation screens such as xpub/address/key
  export confirmations. They are normally serialized by the Jade process loop,
  but they are still host-triggered and should use an explicit cleanup variant
  when touched.
- Lower risk: dashboard menus, setup, PIN, mnemonic, and local settings flows.
  These are human-paced local navigation paths and already converge back to the
  dashboard cleanup point. Do not churn them unless a real lifecycle bug is
  observed.

Fix pattern:

- For host-triggered confirmation flows, call an `_ex(..., true)` UI helper that
  uses `gui_set_current_activity_ex(activity, true)` before waiting for input.
- For multi-page address flows, first switch to a temporary blank activity with
  `free_managed_activities=true`, then create and show the address pages. This
  avoids freeing the second address page before it is displayed.
- Check `esp_event_handler_instance_register()` return values. A failed event
  registration must assert or return a controlled error; it must not leave an
  apparent confirmation screen with no handler.
- Do not log payloads, private keys, mnemonics, PINs, xprivs, signatures, full
  addresses, or raw transactions while diagnosing this class.

### HID Task Stack Exhaustion Audit

Bug class: Trezor/WebUSB requests run inside the `trezor_hid` FreeRTOS task.
Protocol objects that are safe in a desktop process can exhaust this task stack
on ESP32-S3 if they are allocated as local variables.

Observed signature:

```text
reset_last=usb:write_after reset_hwm=4 reset_note=off=192 wr=0
```

Interpretation:

- `reset_hwm` close to zero means stack high-water mark was exhausted or nearly
  exhausted. Treat this as a stack/memory-layout bug before blaming UI or USB
  cable quality.
- `usb:write_after` means the signing result had already reached USB response
  sending. The failure happened after confirmation/signing, while writing the
  response or immediately after a deep call chain returned.
- `wr=0` can be an ordinary TinyUSB backpressure value, but combined with
  `reset_hwm=4` it is strong evidence of stack pressure.

Root cause found:

- BTC signing had `trezor_bitcoin_signed_tx_t` on the HID task stack. The struct
  reserves room for up to 8 signatures plus an 1800-byte serialized raw
  transaction buffer.
- `TxRequest.serialized` encoding also used an approximately 1.9KB nested
  protobuf scratch buffer on the stack.
- Additional similar risks were found in `TxAck` decoding, multisig payload
  normalization, and SafeTx ACK decoding. Trezor multisig payloads can carry up
  to 15 signers, so their normalized C structs are much larger than a single
  transaction would suggest.

Fix pattern:

- Keep large request/response state in static session state or heap objects, not
  on the HID task stack.
- For host-triggered protocol paths, allocation failure must return a protocol
  failure; do not assert and reboot.
- Zero temporary protocol objects before freeing them with `wally_bzero()`.
- Do not move private keys, seeds, mnemonics, xprivs, PINs, signatures, full raw
  tx payloads, or signing digests into logs while diagnosing stack pressure.

Current remediations:

- BTC signed transaction response state reuses `pending_btc_signed_tx` instead
  of a local `trezor_bitcoin_signed_tx_t`.
- BTC signed-response protobuf scratch is heap allocated and cleared before
  free.
- `trezor_bitcoin_transaction_t` temporary `TxAck` objects are heap allocated.
- Large multisig decode temporaries are heap allocated.
- SafeTx ACK, which contains `data[6144]`, is heap allocated.
- `btcsign:` stages are persisted so post-reboot diagnostics retain the BTC
  signing phase.

Periodic review checklist:

- Search for local variables of these high-risk types before every BTC/ETH/Safe
  protocol change:
  `trezor_bitcoin_signed_tx_t`, `trezor_bitcoin_transaction_t`,
  `trezor_bitcoin_multisig_t`, `trezor_bitcoin_multisig_policy_t`,
  `trezor_ethereum_safe_tx_ack_t`, arrays sized by
  `TREZOR_BITCOIN_SIGNED_TX_MAX_LEN`, `ETHEREUM_TX_MAX_PREFLIGHT_DATA_LEN`, or
  `ETHEREUM_SAFE_TX_MAX_DATA_LEN`.
- New USB/protobuf handlers must document whether large buffers live in static
  session state, heap, or a bounded small stack object.
- Hardware regressions should record `reset_last`, `reset_hwm`, and the latest
  non-sensitive `btcsign:`/`ethsign:`/`safe:` stage before changing code.
- A successful fix should be validated by host gates, ESP-IDF build, and a real
  hardware signing run where `reset_hwm` has meaningful headroom after the USB
  signed response is sent.
- BTC UI review is tiered: destination, amount, change, fee, fee rate, path, and
  multisig policy are critical review fields. Non-default transaction behavior
  such as Sparrow-style RBF/locktime is displayed as one compact `Tx Flags`
  field and must be bound to the serialized signed transaction by an external
  oracle. Pure protocol bookkeeping should not be promoted to UI noise.

### C String And Buffer Bounds Audit

Bug class: host-controlled or user-registered text reaches C string helpers
that copy into a smaller response/UI/export buffer. These bugs often hide behind
an earlier validator, or behind a `written > output_len` check that misses the
exact-fill case.

Observed root cause:

- `multisig_create_export_file()` used `write_text()` to append Coldcard-style
  multisig export lines.
- The old guard checked only `strlen(text) >= output_len`.
- With `add_eol=true`, the function wrote `text`, then `'\n'`, then `'\0'`.
  If `strlen(text) == output_len - 1`, the newline landed inside the buffer but
  the trailing NUL wrote one byte past the end.
- The caller checked `written > export_file_len`, so an exact-fill result was not
  rejected.

Fix pattern:

- Before any `memcpy()`, `strcpy()`, `strncpy()`, `snprintf()`, or manual
  terminator write, calculate the exact bytes required, including separators,
  newline, and trailing NUL.
- Reject when `required_len > output_len`; reject exact-fill when the downstream
  consumer requires a NUL-terminated string inside the allocated buffer.
- Do not rely on another parser, address decoder, or UI formatter to have already
  constrained the input. Each copy site must have a local bound check against the
  destination object.
- Prefer structured builders or library helpers when available. If a manual copy
  remains, the destination size and required size must be visible in the same
  function.

Review checklist:

- Search every changed file for `memcpy`, `strcpy`, `strncpy`, `strcat`,
  `sprintf`, `snprintf`, `strlen`, and direct writes such as `buf[len + 1]`.
- For every copy, identify: source maximum length, destination `sizeof`, whether
  the source is NUL-terminated, and whether the copy includes the terminator.
- For every `written` check, verify whether equality is valid. If the output is
  a C string, `written >= output_len` is usually a failure.
- Add or update a host gate for malformed, exact-fill, and one-byte-too-long
  inputs when the path is reachable from USB/protobuf/CBOR, registered wallet
  data, QR import, or file import.
- Normal business output for valid inputs must remain byte-for-byte unchanged;
  the fix should only turn boundary cases into explicit rejection.

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
auth:resume_pass
auth:load_ok / auth:load_fail
auth:busy
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

## Architecture Guardrails

Treat code layout as part of the security boundary. Large files such as
`gui.c`, `dashboard.c`, or protocol/session files are not automatically unsafe,
but they make it harder to prove that PIN handling, USB parsing, UI confirmation,
and signing cannot interfere with each other.

Current guardrails:

- USB transport owns TinyUSB/WebUSB packet I/O only.
- Trezor session owns message state, pending requests, and protobuf response
  selection only.
- Chain modules own path policy, address derivation, transaction parsing, UI
  summary construction, and digest construction.
- The signer boundary signs a 32-byte digest for an approved path. Chain and USB
  code must not request or receive private keys, seed, mnemonic, xpriv, or PIN.
- Local unlock is isolated behind `protocols/trezor/auth_bridge.*`; USB code
  asks whether unlock is needed and asks the bridge to perform local PIN entry.
- UI confirmation must fit the T-Display-S3 dialog constraints before hardware
  testing. Every chain confirmation page must respect the line-count limit.

User-visible errors must be product errors, not developer locations. PIN errors,
unsupported protocol payloads, UI-size violations, and wallet-not-ready states
should become controlled error codes/messages. Source file and line details
belong in retained diagnostics only, and diagnostics must never contain secrets.

## BTC Signing Gate

The BTC SignTx gate must cover the full protocol chain:

```text
SignTx -> TxRequest(TXINPUT) -> TxAck(input)
       -> TxRequest(TXOUTPUT) -> TxAck(output)
       -> optional prev_tx TxRequest(TXMETA with tx_hash)
       -> local UI confirm
       -> build sighash with libwally
       -> sign_digest(path, digest)
       -> TxRequest(TXFINISHED, serialized.signature, serialized.serialized_tx)
```

Do not treat "UI confirmation was shown" as a signing test. A gate must verify
the final `TxRequest(TXFINISHED)` shape and must keep P2PKH state-probe paths
separate from P2WPKH signing paths.

### BTC Policy Reject Trace

Symptom:

```text
Bitcoin signing unsupported
```

The BTC policy layer records a safe diagnostic stage before rejecting a signing
request. These diagnostics intentionally do not include seed, private keys, PIN,
xpriv, xpub, full addresses, raw scripts, or full transaction bytes.

Useful stages:

- `btcpol:not_ready`: the host has not provided all requested inputs/outputs yet.
- `btcpol:input_bad`: an input does not match the supported script policy, or
  required prevout verification is missing for legacy/nested-segwit inputs.
- `btcpol:input_path`: input derivation path is too short to bind to an account.
- `btcpol:input_acct`: inputs are from different accounts.
- `btcpol:out_shape`: output is missing amount, uses an unsupported script type,
  or contains multisig data on the basic single-sig path.
- `btcpol:out_addr_path`: output contains both a host address and change path.
- `btcpol:change_bad`: host supplied an internal output path, but it does not
  match the input account and script policy.
- `btcpol:change_len`: change path is not a 5-element BIP44/BIP49/BIP84 path.
- `btcpol:change_purpose`: change path purpose does not match the input script
  policy, for example BIP84 input with BIP49 change.
- `btcpol:change_coin`: change path coin type does not match `coin_name`, for
  example testnet path `m/.../1'/...` under a mainnet `Bitcoin` signing request.
- `btcpol:change_acct`: change output account does not match the signed input
  account.
- `btcpol:change_branch`: internal output is not on branch `0` or `1`.
  Branch `0` is allowed only after account/script binding and is shown as
  `Self`; branch `1` is shown as `Change`.
- `btcpol:change_index`: internal output address index exceeds the wallet policy
  limit.
- `btcpol:change_script`: host supplied an internal output path with an output script
  type that does not match the input script policy. For example, BIP84 native
  SegWit inputs require a `PAYTOWITNESS` internal output, while BIP49 nested
  SegWit inputs require `PAYTOP2SHWITNESS`.
- `btcpol:out_ext_many`: more than one output was supplied as a plain host
  address. This is the expected diagnosis if a coordinator sends both recipient
  and change/self outputs as plain addresses instead of marking wallet-owned
  outputs with `address_n`.
- `btcpol:out_ext_none`: no plain host address output was supplied, and the
  internal output total is zero. A self-transfer/consolidation is allowed only
  when every output is a non-zero wallet-owned `address_n` output.
- `btcpol:insufficient`: total outputs exceed total inputs.
- `btcpol:req_*`: policy passed, but the internal confirmation request could
  not be built. These cover path length, scriptPubKey validation, address-copy
  bounds, amount overflow, or sequence extraction failures.

The note attached to `btcpol:change_bad`/`btcpol:out_shape` records only
structure: output index, whether `address` was present, `address_n` length,
script type, amount-present flag, sats amount, and change branch. This is enough
to distinguish coordinator-shape errors from firmware policy errors without
logging the user's full address.
