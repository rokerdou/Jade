# BTC Client Compatibility Matrix

This matrix separates protocol-level hardware tests from GUI wallet tests.
Protocol tests are repeatable and use `trezorlib` over the real USB device.
GUI tests verify that Sparrow/OneKey can consume the same xpubs and partial
signatures through their own coordinator flows.

## Protocol Gate

Run after flashing and unlocking the device:

```sh
cd /Users/doujia/work/Jade
. .host-oracle-venv/bin/activate
python tools/run_btc_hardware_protocol_tests.py --include-legacy --include-multisig
```

Expected multisig coverage:

| Case | Path | Script | Expected result |
| --- | --- | --- | --- |
| BIP45 legacy multisig | `m/45'/0/0/0` | P2SH | Device returns one DER partial signature; no full raw tx |
| BIP48 nested multisig | `m/48'/1'/0'/1'/0/0` | P2SH-P2WSH | Device returns one DER partial signature; no full raw tx |
| BIP48 native multisig | `m/48'/1'/0'/2'/0/0` | P2WSH | Device returns one DER partial signature; no full raw tx |

The script verifies returned signatures with `embit`, using public xpubs,
redeem/witness scripts, tx amount, output, and independent sighash calculation.
It does not read or derive device private keys.

## Sparrow Manual Matrix

Close browser wallets and other Trezor clients before testing so WebUSB/HID is
not owned by another process.

| Flow | Wallet policy | Expected result |
| --- | --- | --- |
| Import single-sig BIP44 | P2PKH | Account xpub is retrieved |
| Import single-sig BIP49 | P2SH-P2WPKH | Account xpub is retrieved |
| Import single-sig BIP84 | P2WPKH | Account xpub is retrieved |
| Import multisig BIP45 | P2SH | Cosigner xpub is retrieved |
| Import multisig BIP48 | P2SH-P2WSH | Cosigner xpub is retrieved |
| Import multisig BIP48 | P2WSH | Cosigner xpub is retrieved |
| Sign multisig PSBT | P2SH | Sparrow accepts device partial signature |
| Sign multisig PSBT | P2SH-P2WSH | Sparrow accepts device partial signature |
| Sign multisig PSBT | P2WSH | Sparrow accepts device partial signature |

Record failures with:

- Device screen last page and whether confirmation was shown.
- USB Trace last request/response.
- Sparrow error text.
- Whether the same case passes through `tools/run_btc_hardware_protocol_tests.py --include-multisig`.

## OneKey Manual Matrix

Use the Trezor-compatible hardware flow, not OneKey-only raw `SignPsbt`.
The current firmware deliberately rejects OneKey raw `SignPsbt` message 10052
until a bounded PSBT adapter and policy gate are implemented.

| Flow | Expected result |
| --- | --- |
| Detect device | Device appears as Trezor-compatible hardware |
| Import BIP45 P2SH multisig xpub | xpub retrieved |
| Import BIP48 P2SH-P2WSH multisig xpub | xpub retrieved |
| Import BIP48 P2WSH multisig xpub | xpub retrieved |
| Sign standard Trezor `SignTx/TxAck` multisig flow | Partial signature accepted |
| Send raw OneKey `SignPsbt` | Rejected with `Failure/DataError` |

## Security Invariants

- USB/protocol code must never return private key, seed, mnemonic, or xpriv.
- Multisig signing returns only the local cosigner partial signature.
- The device must not assemble or broadcast a complete multisig transaction.
- Unknown witness script, mismatched prevout script, wrong policy, wrong network,
  or path mismatch must fail before UI confirmation or signing.
- Secure Boot and Flash Encryption remain disabled during debugging.
