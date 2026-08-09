#!/usr/bin/env python3
"""Run BTC protocol tests against a flashed hardware device.

This is intentionally host-only. It uses trezorlib to exercise the USB/Trezor
protocol and embit as an independent oracle for transaction parsing, BIP143
sighash calculation, and ECDSA signature verification.
"""

from __future__ import annotations

import argparse
import inspect
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from trezorlib import btc, client, exceptions, messages

HOST_ORACLE_SITE_PACKAGES = (
    Path(__file__).resolve().parents[1]
    / ".host-oracle-venv"
    / "lib"
    / f"python{sys.version_info.major}.{sys.version_info.minor}"
    / "site-packages"
)
if HOST_ORACLE_SITE_PACKAGES.exists():
    sys.path.append(str(HOST_ORACLE_SITE_PACKAGES))

from embit import ec, script
from embit.transaction import Transaction


HARDENED = 0x80000000
P2WPKH_SCRIPT_TYPE = messages.InputScriptType.SPENDWITNESS
PAYTOADDRESS = messages.OutputScriptType.PAYTOADDRESS


def h(index: int) -> int:
    return HARDENED + index


def p2wpkh_path(*, testnet: bool, index: int = 0, account: int = 0, change: int = 0) -> list[int]:
    coin_type = 1 if testnet else 0
    return [h(84), h(coin_type), h(account), change, index]


@dataclass(frozen=True)
class ExpectedInput:
    prev_hash: bytes
    prev_index: int
    amount: int


@dataclass(frozen=True)
class ExpectedOutput:
    address: str | None
    amount: int


def get_session(app_name: str) -> Any:
    signature = inspect.signature(client.get_default_client)
    if "app_name" in signature.parameters:
        trezor_client = client.get_default_client(app_name=app_name)
    else:
        trezor_client = client.get_default_client()
    if hasattr(client, "get_default_session"):
        return client.get_default_session(trezor_client)
    return trezor_client


def close_session(session: Any) -> None:
    close = getattr(session, "close", None)
    if callable(close):
        close()


def assert_address(session: Any, *, coin_name: str, path: list[int], expected_prefix: str) -> str:
    response = btc.get_address(session, coin_name, path, show_display=False, script_type=P2WPKH_SCRIPT_TYPE)
    if not response.startswith(expected_prefix):
        raise AssertionError(f"{coin_name} P2WPKH address prefix mismatch: {response}")
    return response


def assert_signed_tx(
    raw_tx: bytes,
    *,
    expected_inputs: list[ExpectedInput],
    expected_outputs: list[ExpectedOutput],
) -> None:
    tx = Transaction.parse(raw_tx)
    if tx.serialize() != raw_tx:
        raise AssertionError("raw transaction does not round-trip through embit")
    if tx.version != 2 or tx.locktime != 0:
        raise AssertionError(f"unexpected version/locktime: {tx.version}/{tx.locktime}")
    if len(tx.vin) != len(expected_inputs) or len(tx.vout) != len(expected_outputs):
        raise AssertionError(f"input/output count mismatch: {len(tx.vin)}/{len(tx.vout)}")

    for index, expected in enumerate(expected_inputs):
        txin = tx.vin[index]
        if txin.txid != expected.prev_hash or txin.vout != expected.prev_index:
            raise AssertionError(f"input {index} outpoint mismatch")
        if txin.script_sig.data != b"":
            raise AssertionError(f"input {index} scriptSig must be empty for native P2WPKH")
        if txin.sequence != 0xFFFFFFFF:
            raise AssertionError(f"input {index} sequence mismatch: {txin.sequence}")
        if len(txin.witness.items) != 2:
            raise AssertionError(f"input {index} witness item count mismatch: {len(txin.witness.items)}")

        signature_with_sighash, pubkey_bytes = txin.witness.items
        if len(signature_with_sighash) < 9:
            raise AssertionError(f"input {index} witness signature too short")
        sighash = signature_with_sighash[-1]
        if sighash != 1:
            raise AssertionError(f"input {index} sighash must be SIGHASH_ALL, got {sighash}")

        pubkey = ec.PublicKey.parse(pubkey_bytes)
        signature = ec.Signature.parse(signature_with_sighash[:-1])
        digest = tx.sighash_segwit(index, script.p2wpkh(pubkey), expected.amount, sighash)
        if not pubkey.verify(signature, digest):
            raise AssertionError(f"input {index} witness signature verification failed")

    for index, expected in enumerate(expected_outputs):
        txout = tx.vout[index]
        if txout.value != expected.amount:
            raise AssertionError(f"output {index} amount mismatch: {txout.value}")
        if expected.address is not None:
            expected_script = script.address_to_scriptpubkey(expected.address).data
            if txout.script_pubkey.data != expected_script:
                raise AssertionError(f"output {index} scriptPubKey mismatch: {txout.script_pubkey.data.hex()}")


def enum_name(value: Any) -> str:
    return getattr(value, "name", str(value))


def sign_tx_protocol_driver(
    session: Any,
    *,
    coin_name: str,
    inputs: list[messages.TxInputType],
    outputs: list[messages.TxOutputType],
) -> tuple[list[bytes | None], bytes]:
    response = session.call(
        messages.SignTx(
            coin_name=coin_name,
            inputs_count=len(inputs),
            outputs_count=len(outputs),
            version=2,
            lock_time=0,
        ),
        expect=messages.TxRequest,
    )
    signatures: list[bytes | None] = [None] * len(inputs)
    serialized_tx = b""

    while True:
        if response.serialized:
            if response.serialized.serialized_tx:
                serialized_tx += response.serialized.serialized_tx
            if response.serialized.signature_index is not None:
                index = response.serialized.signature_index
                if index >= len(signatures):
                    raise AssertionError(f"signature index out of range: {index}")
                if signatures[index] is not None:
                    raise AssertionError(f"duplicate signature index: {index}")
                signatures[index] = response.serialized.signature
                print(f"  got signature index={index} len={len(signatures[index] or b'')}", flush=True)

        print(f"  device request={enum_name(response.request_type)}", flush=True)
        if response.request_type == messages.RequestType.TXFINISHED:
            break
        if response.details is None:
            raise AssertionError("TxRequest missing details")

        tx = messages.TransactionType()
        if response.request_type == messages.RequestType.TXMETA:
            tx.version = 2
            tx.lock_time = 0
            tx.inputs_cnt = len(inputs)
            tx.outputs_cnt = len(outputs)
            ack_name = "meta"
        elif response.request_type == messages.RequestType.TXINPUT:
            if response.details.request_index is None or response.details.request_index >= len(inputs):
                raise AssertionError(f"bad input request index: {response.details.request_index}")
            tx.inputs = [inputs[response.details.request_index]]
            ack_name = f"input[{response.details.request_index}]"
        elif response.request_type == messages.RequestType.TXOUTPUT:
            if response.details.request_index is None or response.details.request_index >= len(outputs):
                raise AssertionError(f"bad output request index: {response.details.request_index}")
            tx.outputs = [outputs[response.details.request_index]]
            ack_name = f"output[{response.details.request_index}]"
        else:
            raise AssertionError(f"unsupported device request type: {response.request_type}")

        print(f"  send TxAck {ack_name}", flush=True)
        response = session.call(messages.TxAck(tx=tx), expect=messages.TxRequest)

    return signatures, serialized_tx


def sign_p2wpkh(
    session: Any,
    *,
    coin_name: str,
    inputs: list[messages.TxInputType],
    outputs: list[messages.TxOutputType],
) -> tuple[list[bytes | None], bytes]:
    signatures, raw_tx = sign_tx_protocol_driver(session, coin_name=coin_name, inputs=inputs, outputs=outputs)
    if any(signature is None for signature in signatures):
        raise AssertionError("device did not return all required BTC signatures")
    return list(signatures), raw_tx


def expect_failure(name: str, call) -> None:
    try:
        call()
    except exceptions.TrezorFailure as exc:
        print(f"PASS {name}: rejected with {exc.failure.code.name}", flush=True)
        return
    except Exception as exc:
        print(f"PASS {name}: rejected with {type(exc).__name__}", flush=True)
        return
    raise AssertionError(f"{name} unexpectedly succeeded")


def test_testnet_single(session: Any) -> None:
    print("RUN testnet single-input P2WPKH", flush=True)
    prev_hash = bytes.fromhex("11" * 32)
    output_address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
    inputs = [
        messages.TxInputType(
            address_n=p2wpkh_path(testnet=True),
            prev_hash=prev_hash,
            prev_index=0,
            script_type=P2WPKH_SCRIPT_TYPE,
            amount=100_000,
            sequence=0xFFFFFFFF,
        )
    ]
    outputs = [
        messages.TxOutputType(address=output_address, amount=90_000, script_type=PAYTOADDRESS),
    ]
    signatures, raw_tx = sign_p2wpkh(session, coin_name="Testnet", inputs=inputs, outputs=outputs)
    assert_signed_tx(
        raw_tx,
        expected_inputs=[ExpectedInput(prev_hash, 0, 100_000)],
        expected_outputs=[ExpectedOutput(output_address, 90_000)],
    )
    print(f"PASS testnet single-input P2WPKH: sigs={list(map(len, signatures))} raw_len={len(raw_tx)}", flush=True)


def test_testnet_multi_change(session: Any) -> None:
    print("RUN testnet multi-input change P2WPKH", flush=True)
    prev_hash0 = bytes.fromhex("11" * 32)
    prev_hash1 = bytes.fromhex("22" * 32)
    output_address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
    inputs = [
        messages.TxInputType(
            address_n=p2wpkh_path(testnet=True, index=0),
            prev_hash=prev_hash0,
            prev_index=0,
            script_type=P2WPKH_SCRIPT_TYPE,
            amount=100_000,
            sequence=0xFFFFFFFF,
        ),
        messages.TxInputType(
            address_n=p2wpkh_path(testnet=True, index=1),
            prev_hash=prev_hash1,
            prev_index=1,
            script_type=P2WPKH_SCRIPT_TYPE,
            amount=40_000,
            sequence=0xFFFFFFFF,
        ),
    ]
    outputs = [
        messages.TxOutputType(address=output_address, amount=90_000, script_type=PAYTOADDRESS),
        messages.TxOutputType(
            address_n=p2wpkh_path(testnet=True, change=1),
            amount=45_000,
            script_type=PAYTOADDRESS,
        ),
    ]
    signatures, raw_tx = sign_p2wpkh(session, coin_name="Testnet", inputs=inputs, outputs=outputs)
    assert_signed_tx(
        raw_tx,
        expected_inputs=[ExpectedInput(prev_hash0, 0, 100_000), ExpectedInput(prev_hash1, 1, 40_000)],
        expected_outputs=[ExpectedOutput(output_address, 90_000), ExpectedOutput(None, 45_000)],
    )
    print(f"PASS testnet multi-input change P2WPKH: sigs={list(map(len, signatures))} raw_len={len(raw_tx)}", flush=True)


def test_mainnet_single(session: Any) -> None:
    print("RUN mainnet single-input P2WPKH", flush=True)
    prev_hash = bytes.fromhex("33" * 32)
    output_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    inputs = [
        messages.TxInputType(
            address_n=p2wpkh_path(testnet=False),
            prev_hash=prev_hash,
            prev_index=0,
            script_type=P2WPKH_SCRIPT_TYPE,
            amount=100_000,
            sequence=0xFFFFFFFF,
        )
    ]
    outputs = [
        messages.TxOutputType(address=output_address, amount=90_000, script_type=PAYTOADDRESS),
    ]
    signatures, raw_tx = sign_p2wpkh(session, coin_name="Bitcoin", inputs=inputs, outputs=outputs)
    assert_signed_tx(
        raw_tx,
        expected_inputs=[ExpectedInput(prev_hash, 0, 100_000)],
        expected_outputs=[ExpectedOutput(output_address, 90_000)],
    )
    print(f"PASS mainnet single-input P2WPKH: sigs={list(map(len, signatures))} raw_len={len(raw_tx)}", flush=True)


def test_rejections() -> None:
    output_address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"

    def high_fee() -> None:
        session = get_session("codex-btc-high-fee")
        try:
            btc.sign_tx(
                session,
                "Testnet",
                [
                    messages.TxInputType(
                        address_n=p2wpkh_path(testnet=True),
                        prev_hash=bytes.fromhex("44" * 32),
                        prev_index=0,
                        script_type=P2WPKH_SCRIPT_TYPE,
                        amount=200_000,
                        sequence=0xFFFFFFFF,
                    )
                ],
                [messages.TxOutputType(address=output_address, amount=80_000, script_type=PAYTOADDRESS)],
                version=2,
                lock_time=0,
            )
        finally:
            close_session(session)

    def lock_time() -> None:
        session = get_session("codex-btc-locktime")
        try:
            btc.sign_tx(
                session,
                "Testnet",
                [
                    messages.TxInputType(
                        address_n=p2wpkh_path(testnet=True),
                        prev_hash=bytes.fromhex("55" * 32),
                        prev_index=0,
                        script_type=P2WPKH_SCRIPT_TYPE,
                        amount=100_000,
                        sequence=0xFFFFFFFF,
                    )
                ],
                [messages.TxOutputType(address=output_address, amount=90_000, script_type=PAYTOADDRESS)],
                version=2,
                lock_time=1,
            )
        finally:
            close_session(session)

    expect_failure("high fee-rate", high_fee)
    expect_failure("hidden lock_time", lock_time)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--include-mainnet-sign",
        action="store_true",
        help="Also ask the device to sign a fake mainnet P2WPKH transaction.",
    )
    parser.add_argument("--skip-rejections", action="store_true", help="Skip negative protocol tests.")
    args = parser.parse_args()

    session = get_session("codex-btc-hardware")
    try:
        testnet_address = assert_address(
            session, coin_name="Testnet", path=p2wpkh_path(testnet=True), expected_prefix="tb1"
        )
        mainnet_address = assert_address(
            session, coin_name="Bitcoin", path=p2wpkh_path(testnet=False), expected_prefix="bc1"
        )
    finally:
        close_session(session)
    print(f"PASS address testnet={testnet_address}", flush=True)
    print(f"PASS address mainnet={mainnet_address}", flush=True)

    session = get_session("codex-btc-single")
    try:
        test_testnet_single(session)
    finally:
        close_session(session)

    session = get_session("codex-btc-multi")
    try:
        test_testnet_multi_change(session)
    finally:
        close_session(session)

    if args.include_mainnet_sign:
        session = get_session("codex-btc-mainnet")
        try:
            test_mainnet_single(session)
        finally:
            close_session(session)
    else:
        print("SKIP mainnet signing; pass --include-mainnet-sign to enable", flush=True)
    if not args.skip_rejections:
        test_rejections()
    print("PASS btc_hardware_protocol_tests", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
