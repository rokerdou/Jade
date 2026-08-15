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

from embit import bip32, ec, networks, script
from embit.transaction import Transaction, TransactionInput, TransactionOutput


HARDENED = 0x80000000
P2WPKH_SCRIPT_TYPE = messages.InputScriptType.SPENDWITNESS
P2PKH_SCRIPT_TYPE = messages.InputScriptType.SPENDADDRESS
P2SH_P2WPKH_SCRIPT_TYPE = messages.InputScriptType.SPENDP2SHWITNESS
PAYTOADDRESS = messages.OutputScriptType.PAYTOADDRESS


def h(index: int) -> int:
    return HARDENED + index


def p2wpkh_path(*, testnet: bool, index: int = 0, account: int = 0, change: int = 0) -> list[int]:
    coin_type = 1 if testnet else 0
    return [h(84), h(coin_type), h(account), change, index]


def p2pkh_path(*, testnet: bool, index: int = 0, account: int = 0, change: int = 0) -> list[int]:
    coin_type = 1 if testnet else 0
    return [h(44), h(coin_type), h(account), change, index]


def p2sh_p2wpkh_path(*, testnet: bool, index: int = 0, account: int = 0, change: int = 0) -> list[int]:
    coin_type = 1 if testnet else 0
    return [h(49), h(coin_type), h(account), change, index]


def p2wpkh_account_path(*, testnet: bool, account: int = 0) -> list[int]:
    coin_type = 1 if testnet else 0
    return [h(84), h(coin_type), h(account)]


def account_path_for_script(script_type: messages.InputScriptType, *, testnet: bool, account: int = 0) -> list[int]:
    coin_type = 1 if testnet else 0
    if script_type == P2PKH_SCRIPT_TYPE:
        return [h(44), h(coin_type), h(account)]
    if script_type == P2SH_P2WPKH_SCRIPT_TYPE:
        return [h(49), h(coin_type), h(account)]
    if script_type == P2WPKH_SCRIPT_TYPE:
        return [h(84), h(coin_type), h(account)]
    raise ValueError(f"unsupported account script type: {script_type}")


@dataclass(frozen=True)
class ExpectedInput:
    prev_hash: bytes
    prev_index: int
    amount: int
    address: str | None = None


@dataclass(frozen=True)
class ExpectedOutput:
    address: str | None
    amount: int


@dataclass(frozen=True)
class PrevInput:
    prev_hash: bytes
    prev_index: int
    script_sig: bytes
    sequence: int = 0xFFFFFFFE


@dataclass(frozen=True)
class PrevOutput:
    amount: int
    script_pubkey: bytes


@dataclass(frozen=True)
class PrevTx:
    version: int
    lock_time: int
    inputs: list[PrevInput]
    outputs: list[PrevOutput]
    txid: bytes


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


def account_xpub(
    session: Any, *, coin_name: str, testnet: bool, script_type: messages.InputScriptType = P2WPKH_SCRIPT_TYPE,
    account: int = 0, expected_prefix: str | None = None, omit_script_type: bool = False,
    request_script_type: messages.InputScriptType | None = None
) -> str:
    request_kwargs: dict[str, Any] = {
        "show_display": False,
        "coin_name": coin_name,
    }
    if not omit_script_type:
        request_kwargs["script_type"] = request_script_type if request_script_type is not None else script_type
    response = btc.get_public_node(
        session,
        account_path_for_script(script_type, testnet=testnet, account=account),
        **request_kwargs,
    )
    xpub = getattr(response, "xpub", None)
    if not xpub:
        raise AssertionError("GetPublicKey did not return xpub")
    if expected_prefix is not None and not xpub.startswith(expected_prefix):
        raise AssertionError(
            f"{coin_name}/{script_type} xpub prefix mismatch: expected {expected_prefix}, got {xpub[:4]}"
        )
    bip32.HDKey.from_base58(xpub)
    return xpub


def p2wpkh_address_from_xpub(xpub: str, *, testnet: bool, change: int, index: int) -> str:
    key = bip32.HDKey.from_base58(xpub).child(change).child(index)
    network = networks.NETWORKS["test" if testnet else "main"]
    return script.p2wpkh(key.get_public_key()).address(network)


def p2pkh_address_from_xpub(xpub: str, *, testnet: bool, change: int, index: int) -> str:
    key = bip32.HDKey.from_base58(xpub).child(change).child(index)
    network = networks.NETWORKS["test" if testnet else "main"]
    return script.p2pkh(key.get_public_key()).address(network)


def p2sh_p2wpkh_address_from_xpub(xpub: str, *, testnet: bool, change: int, index: int) -> str:
    key = bip32.HDKey.from_base58(xpub).child(change).child(index)
    network = networks.NETWORKS["test" if testnet else "main"]
    return script.p2sh(script.p2wpkh(key.get_public_key())).address(network)


def optional_account_xpub(
    session: Any, *, coin_name: str, testnet: bool, script_type: messages.InputScriptType = P2WPKH_SCRIPT_TYPE,
    account: int = 0
) -> str | None:
    try:
        return account_xpub(session, coin_name=coin_name, testnet=testnet, script_type=script_type, account=account)
    except (exceptions.TrezorFailure, exceptions.Cancelled) as exc:
        print(f"  WARN account xpub unavailable for change oracle: {exc}", flush=True)
        return None


def expected_account_xpub_prefix(*, testnet: bool, script_type: messages.InputScriptType) -> str:
    if script_type == P2PKH_SCRIPT_TYPE:
        return "tpub" if testnet else "xpub"
    if script_type == P2SH_P2WPKH_SCRIPT_TYPE:
        return "upub" if testnet else "ypub"
    if script_type == P2WPKH_SCRIPT_TYPE:
        return "vpub" if testnet else "zpub"
    raise ValueError(f"unsupported account script type: {script_type}")


def test_account_xpubs(session: Any) -> None:
    print("RUN BTC account xpubs testnet/mainnet explicit, omitted and Sparrow/lark default script type", flush=True)
    cases = [
        ("Testnet", True, P2PKH_SCRIPT_TYPE),
        ("Testnet", True, P2SH_P2WPKH_SCRIPT_TYPE),
        ("Testnet", True, P2WPKH_SCRIPT_TYPE),
        ("Bitcoin", False, P2PKH_SCRIPT_TYPE),
        ("Bitcoin", False, P2SH_P2WPKH_SCRIPT_TYPE),
        ("Bitcoin", False, P2WPKH_SCRIPT_TYPE),
    ]
    for coin_name, testnet, script_type in cases:
        prefix = expected_account_xpub_prefix(testnet=testnet, script_type=script_type)
        request_modes: list[tuple[str, bool, messages.InputScriptType | None]] = [
            ("explicit", False, script_type),
            ("omitted", True, None),
        ]
        if script_type != P2PKH_SCRIPT_TYPE:
            request_modes.append(("sparrow-lark-default", False, P2PKH_SCRIPT_TYPE))
        for mode, omit_script_type, request_script_type in request_modes:
            xpub = account_xpub(
                session,
                coin_name=coin_name,
                testnet=testnet,
                script_type=script_type,
                expected_prefix=prefix,
                omit_script_type=omit_script_type,
                request_script_type=request_script_type,
            )
            print(f"  PASS {coin_name}/{enum_name(script_type)} {mode} account xpub={xpub[:8]}...", flush=True)


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
        if expected.address is not None:
            expected_script = script.address_to_scriptpubkey(expected.address).data
            actual_script = script.p2wpkh(pubkey).data
            if actual_script != expected_script:
                raise AssertionError(f"input {index} witness pubkey does not match requested path address")
        digest = tx.sighash_segwit(index, script.p2pkh(pubkey), expected.amount, sighash)
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


def assert_p2pkh_signed_tx(
    raw_tx: bytes,
    *,
    prev_hash: bytes,
    prev_index: int,
    amount: int,
    expected_pubkey: ec.PublicKey,
    expected_output: ExpectedOutput,
) -> None:
    tx = Transaction.parse(raw_tx)
    if tx.serialize() != raw_tx:
        raise AssertionError("P2PKH raw transaction does not round-trip through embit")
    if len(tx.vin) != 1 or len(tx.vout) != 1:
        raise AssertionError(f"P2PKH input/output count mismatch: {len(tx.vin)}/{len(tx.vout)}")

    txin = tx.vin[0]
    if txin.txid != prev_hash or txin.vout != prev_index:
        raise AssertionError("P2PKH outpoint mismatch")
    if len(txin.witness.items) != 0:
        raise AssertionError("P2PKH transaction must not include witness data")

    script_sig = txin.script_sig.data
    if len(script_sig) < 2:
        raise AssertionError("P2PKH scriptSig too short")
    sig_len = script_sig[0]
    signature_with_sighash = script_sig[1 : 1 + sig_len]
    pubkey_pos = 1 + sig_len
    if pubkey_pos >= len(script_sig):
        raise AssertionError("P2PKH scriptSig missing pubkey")
    pubkey_len = script_sig[pubkey_pos]
    pubkey_bytes = script_sig[pubkey_pos + 1 :]
    if pubkey_len != len(pubkey_bytes):
        raise AssertionError("P2PKH scriptSig pubkey push length mismatch")
    if not signature_with_sighash or signature_with_sighash[-1] != 1:
        raise AssertionError("P2PKH signature must end with SIGHASH_ALL")

    pubkey = ec.PublicKey.parse(pubkey_bytes)
    if pubkey.sec() != expected_pubkey.sec():
        raise AssertionError("P2PKH signing pubkey does not match account xpub derivation")
    signature = ec.Signature.parse(signature_with_sighash[:-1])
    digest = tx.sighash_legacy(0, script.p2pkh(pubkey), sighash=1)
    if not pubkey.verify(signature, digest):
        raise AssertionError("P2PKH signature verification failed")
    if amount <= 0:
        raise AssertionError("P2PKH prevout amount must be positive")

    txout = tx.vout[0]
    if txout.value != expected_output.amount:
        raise AssertionError(f"P2PKH output amount mismatch: {txout.value}")
    if expected_output.address is not None:
        expected_script = script.address_to_scriptpubkey(expected_output.address).data
        if txout.script_pubkey.data != expected_script:
            raise AssertionError(f"P2PKH output scriptPubKey mismatch: {txout.script_pubkey.data.hex()}")


def assert_p2sh_p2wpkh_signed_tx(
    raw_tx: bytes,
    *,
    prev_hash: bytes,
    prev_index: int,
    amount: int,
    expected_pubkey: ec.PublicKey,
    expected_output: ExpectedOutput,
) -> None:
    tx = Transaction.parse(raw_tx)
    if tx.serialize() != raw_tx:
        raise AssertionError("P2SH-P2WPKH raw transaction does not round-trip through embit")
    if len(tx.vin) != 1 or len(tx.vout) != 1:
        raise AssertionError(f"P2SH-P2WPKH input/output count mismatch: {len(tx.vin)}/{len(tx.vout)}")

    txin = tx.vin[0]
    if txin.txid != prev_hash or txin.vout != prev_index:
        raise AssertionError("P2SH-P2WPKH outpoint mismatch")
    if len(txin.witness.items) != 2:
        raise AssertionError("P2SH-P2WPKH witness item count mismatch")
    signature_with_sighash, pubkey_bytes = txin.witness.items
    if not signature_with_sighash or signature_with_sighash[-1] != 1:
        raise AssertionError("P2SH-P2WPKH signature must end with SIGHASH_ALL")

    pubkey = ec.PublicKey.parse(pubkey_bytes)
    if pubkey.sec() != expected_pubkey.sec():
        raise AssertionError("P2SH-P2WPKH signing pubkey does not match account xpub derivation")
    redeem_script = script.p2wpkh(pubkey).data
    if txin.script_sig.data != bytes([len(redeem_script)]) + redeem_script:
        raise AssertionError(f"P2SH-P2WPKH scriptSig mismatch: {txin.script_sig.data.hex()}")
    signature = ec.Signature.parse(signature_with_sighash[:-1])
    digest = tx.sighash_segwit(0, script.p2pkh(pubkey), amount, sighash=1)
    if not pubkey.verify(signature, digest):
        raise AssertionError("P2SH-P2WPKH signature verification failed")

    txout = tx.vout[0]
    if txout.value != expected_output.amount:
        raise AssertionError(f"P2SH-P2WPKH output amount mismatch: {txout.value}")
    if expected_output.address is not None:
        expected_script = script.address_to_scriptpubkey(expected_output.address).data
        if txout.script_pubkey.data != expected_script:
            raise AssertionError(f"P2SH-P2WPKH output scriptPubKey mismatch: {txout.script_pubkey.data.hex()}")


def enum_name(value: Any) -> str:
    return getattr(value, "name", str(value))


def public_key_for_xpub(xpub: str, *, change: int = 0, index: int = 0) -> ec.PublicKey:
    return bip32.HDKey.from_base58(xpub).child(change).child(index).get_public_key()


def prev_tx_from_outputs(outputs: list[PrevOutput]) -> PrevTx:
    prev_input = PrevInput(prev_hash=bytes.fromhex("aa" * 32), prev_index=7, script_sig=b"\x51")
    tx = Transaction(
        version=2,
        vin=[
            TransactionInput(
                prev_input.prev_hash,
                prev_input.prev_index,
                script_sig=script.Script(prev_input.script_sig),
                sequence=prev_input.sequence,
            )
        ],
        vout=[TransactionOutput(output.amount, script.Script(output.script_pubkey)) for output in outputs],
        locktime=0,
    )
    return PrevTx(version=2, lock_time=0, inputs=[prev_input], outputs=outputs, txid=tx.txid())


def tx_hash_from_request(response: messages.TxRequest) -> bytes | None:
    details = getattr(response, "details", None)
    return getattr(details, "tx_hash", None) if details is not None else None


def sign_tx_protocol_driver(
    session: Any,
    *,
    coin_name: str,
    inputs: list[messages.TxInputType],
    outputs: list[messages.TxOutputType],
    prev_txs: dict[bytes, PrevTx] | None = None,
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
        requested_tx_hash = tx_hash_from_request(response)
        if response.request_type == messages.RequestType.TXMETA:
            if requested_tx_hash:
                if not prev_txs or requested_tx_hash not in prev_txs:
                    raise AssertionError(f"missing prev_tx for {requested_tx_hash.hex()}")
                prev_tx = prev_txs[requested_tx_hash]
                tx.version = prev_tx.version
                tx.lock_time = prev_tx.lock_time
                tx.inputs_cnt = len(prev_tx.inputs)
                tx.outputs_cnt = len(prev_tx.outputs)
                ack_name = f"prev_meta[{requested_tx_hash.hex()}]"
            else:
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
        elif response.request_type == messages.RequestType.TXORIGINPUT:
            if not requested_tx_hash or not prev_txs or requested_tx_hash not in prev_txs:
                raise AssertionError("TXORIGINPUT missing known tx_hash")
            prev_tx = prev_txs[requested_tx_hash]
            if response.details.request_index is None or response.details.request_index >= len(prev_tx.inputs):
                raise AssertionError(f"bad prev input request index: {response.details.request_index}")
            prev_input = prev_tx.inputs[response.details.request_index]
            tx.inputs = [
                messages.TxInputType(
                    prev_hash=prev_input.prev_hash,
                    prev_index=prev_input.prev_index,
                    script_sig=prev_input.script_sig,
                    sequence=prev_input.sequence,
                )
            ]
            ack_name = f"prev_input[{response.details.request_index}]"
        elif response.request_type == messages.RequestType.TXORIGOUTPUT:
            if not requested_tx_hash or not prev_txs or requested_tx_hash not in prev_txs:
                raise AssertionError("TXORIGOUTPUT missing known tx_hash")
            prev_tx = prev_txs[requested_tx_hash]
            if response.details.request_index is None or response.details.request_index >= len(prev_tx.outputs):
                raise AssertionError(f"bad prev output request index: {response.details.request_index}")
            prev_output = prev_tx.outputs[response.details.request_index]
            tx.bin_outputs = [
                messages.TxOutputBinType(amount=prev_output.amount, script_pubkey=prev_output.script_pubkey)
            ]
            ack_name = f"prev_output[{response.details.request_index}]"
        else:
            raise AssertionError(f"unsupported device request type: {response.request_type}")

        print(f"  send TxAck {ack_name}", flush=True)
        response = session.call(messages.TxAck(tx=tx), expect=messages.TxRequest)

    return signatures, serialized_tx


def sign_btc(
    session: Any,
    *,
    coin_name: str,
    inputs: list[messages.TxInputType],
    outputs: list[messages.TxOutputType],
    prev_txs: dict[bytes, PrevTx] | None = None,
) -> tuple[list[bytes | None], bytes]:
    signatures, raw_tx = sign_tx_protocol_driver(
        session, coin_name=coin_name, inputs=inputs, outputs=outputs, prev_txs=prev_txs
    )
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
    xpub = optional_account_xpub(session, coin_name="Testnet", testnet=True)
    input_path = p2wpkh_path(testnet=True)
    input_address = (
        p2wpkh_address_from_xpub(xpub, testnet=True, change=0, index=0)
        if xpub
        else assert_address(session, coin_name="Testnet", path=input_path, expected_prefix="tb1")
    )
    inputs = [
        messages.TxInputType(
            address_n=input_path,
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
    signatures, raw_tx = sign_btc(session, coin_name="Testnet", inputs=inputs, outputs=outputs)
    assert_signed_tx(
        raw_tx,
        expected_inputs=[ExpectedInput(prev_hash, 0, 100_000, input_address)],
        expected_outputs=[ExpectedOutput(output_address, 90_000)],
    )
    print(
        f"PASS testnet single-input P2WPKH: from={input_address} to={output_address} amount=90000 "
        f"sigs={list(map(len, signatures))} raw_len={len(raw_tx)}",
        flush=True,
    )


def test_testnet_multi_change(session: Any) -> None:
    print("RUN testnet multi-input change P2WPKH", flush=True)
    prev_hash0 = bytes.fromhex("11" * 32)
    prev_hash1 = bytes.fromhex("22" * 32)
    output_address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
    xpub = optional_account_xpub(session, coin_name="Testnet", testnet=True)
    input_path0 = p2wpkh_path(testnet=True, index=0)
    input_path1 = p2wpkh_path(testnet=True, index=1)
    change_path = p2wpkh_path(testnet=True, change=1)
    input_address0 = (
        p2wpkh_address_from_xpub(xpub, testnet=True, change=0, index=0)
        if xpub
        else assert_address(session, coin_name="Testnet", path=input_path0, expected_prefix="tb1")
    )
    input_address1 = (
        p2wpkh_address_from_xpub(xpub, testnet=True, change=0, index=1)
        if xpub
        else assert_address(session, coin_name="Testnet", path=input_path1, expected_prefix="tb1")
    )
    change_address = p2wpkh_address_from_xpub(xpub, testnet=True, change=1, index=0) if xpub else None
    inputs = [
        messages.TxInputType(
            address_n=input_path0,
            prev_hash=prev_hash0,
            prev_index=0,
            script_type=P2WPKH_SCRIPT_TYPE,
            amount=100_000,
            sequence=0xFFFFFFFF,
        ),
        messages.TxInputType(
            address_n=input_path1,
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
            address_n=change_path,
            amount=45_000,
            script_type=PAYTOADDRESS,
        ),
    ]
    signatures, raw_tx = sign_btc(session, coin_name="Testnet", inputs=inputs, outputs=outputs)
    assert_signed_tx(
        raw_tx,
        expected_inputs=[
            ExpectedInput(prev_hash0, 0, 100_000, input_address0),
            ExpectedInput(prev_hash1, 1, 40_000, input_address1),
        ],
        expected_outputs=[ExpectedOutput(output_address, 90_000), ExpectedOutput(change_address, 45_000)],
    )
    print(
        f"PASS testnet multi-input change P2WPKH: from=[{input_address0},{input_address1}] "
        f"to={output_address} amount=90000 change={change_address or '<script-not-verified>'}:45000 "
        f"sigs={list(map(len, signatures))} raw_len={len(raw_tx)}",
        flush=True,
    )


def test_mainnet_single(session: Any) -> None:
    print("RUN mainnet single-input P2WPKH", flush=True)
    prev_hash = bytes.fromhex("33" * 32)
    output_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    xpub = optional_account_xpub(session, coin_name="Bitcoin", testnet=False)
    input_path = p2wpkh_path(testnet=False)
    input_address = (
        p2wpkh_address_from_xpub(xpub, testnet=False, change=0, index=0)
        if xpub
        else assert_address(session, coin_name="Bitcoin", path=input_path, expected_prefix="bc1")
    )
    inputs = [
        messages.TxInputType(
            address_n=input_path,
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
    signatures, raw_tx = sign_btc(session, coin_name="Bitcoin", inputs=inputs, outputs=outputs)
    assert_signed_tx(
        raw_tx,
        expected_inputs=[ExpectedInput(prev_hash, 0, 100_000, input_address)],
        expected_outputs=[ExpectedOutput(output_address, 90_000)],
    )
    print(
        f"PASS mainnet single-input P2WPKH: from={input_address} to={output_address} amount=90000 "
        f"sigs={list(map(len, signatures))} raw_len={len(raw_tx)}",
        flush=True,
    )


def test_legacy_p2pkh(session: Any, *, coin_name: str, testnet: bool) -> None:
    network_name = "testnet" if testnet else "mainnet"
    print(f"RUN {network_name} single-input legacy P2PKH with prev_tx verification", flush=True)
    output_address = (
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        if testnet
        else "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    )
    xpub = account_xpub(
        session,
        coin_name=coin_name,
        testnet=testnet,
        script_type=P2PKH_SCRIPT_TYPE,
        expected_prefix=expected_account_xpub_prefix(testnet=testnet, script_type=P2PKH_SCRIPT_TYPE),
    )
    pubkey = public_key_for_xpub(xpub)
    input_path = p2pkh_path(testnet=testnet)
    input_address = p2pkh_address_from_xpub(xpub, testnet=testnet, change=0, index=0)
    prev_tx = prev_tx_from_outputs(
        [
            PrevOutput(amount=100_000, script_pubkey=script.p2pkh(pubkey).data),
            PrevOutput(amount=1_000, script_pubkey=script.address_to_scriptpubkey(output_address).data),
        ]
    )
    inputs = [
        messages.TxInputType(
            address_n=input_path,
            prev_hash=prev_tx.txid,
            prev_index=0,
            script_type=P2PKH_SCRIPT_TYPE,
            sequence=0xFFFFFFFF,
        )
    ]
    outputs = [messages.TxOutputType(address=output_address, amount=90_000, script_type=PAYTOADDRESS)]
    signatures, raw_tx = sign_btc(
        session,
        coin_name=coin_name,
        inputs=inputs,
        outputs=outputs,
        prev_txs={prev_tx.txid: prev_tx},
    )
    assert_p2pkh_signed_tx(
        raw_tx,
        prev_hash=prev_tx.txid,
        prev_index=0,
        amount=100_000,
        expected_pubkey=pubkey,
        expected_output=ExpectedOutput(output_address, 90_000),
    )
    print(
        f"PASS {network_name} legacy P2PKH: from={input_address} to={output_address} amount=90000 "
        f"sigs={list(map(len, signatures))} raw_len={len(raw_tx)}",
        flush=True,
    )


def test_p2sh_p2wpkh(session: Any, *, coin_name: str, testnet: bool) -> None:
    network_name = "testnet" if testnet else "mainnet"
    print(f"RUN {network_name} single-input P2SH-P2WPKH with prev_tx verification", flush=True)
    output_address = (
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        if testnet
        else "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
    )
    xpub = account_xpub(
        session,
        coin_name=coin_name,
        testnet=testnet,
        script_type=P2SH_P2WPKH_SCRIPT_TYPE,
        expected_prefix=expected_account_xpub_prefix(testnet=testnet, script_type=P2SH_P2WPKH_SCRIPT_TYPE),
    )
    pubkey = public_key_for_xpub(xpub)
    input_path = p2sh_p2wpkh_path(testnet=testnet)
    input_address = p2sh_p2wpkh_address_from_xpub(xpub, testnet=testnet, change=0, index=0)
    prev_tx = prev_tx_from_outputs(
        [
            PrevOutput(amount=100_000, script_pubkey=script.p2sh(script.p2wpkh(pubkey)).data),
            PrevOutput(amount=1_000, script_pubkey=script.address_to_scriptpubkey(output_address).data),
        ]
    )
    inputs = [
        messages.TxInputType(
            address_n=input_path,
            prev_hash=prev_tx.txid,
            prev_index=0,
            script_type=P2SH_P2WPKH_SCRIPT_TYPE,
            sequence=0xFFFFFFFF,
        )
    ]
    outputs = [messages.TxOutputType(address=output_address, amount=90_000, script_type=PAYTOADDRESS)]
    signatures, raw_tx = sign_btc(
        session,
        coin_name=coin_name,
        inputs=inputs,
        outputs=outputs,
        prev_txs={prev_tx.txid: prev_tx},
    )
    assert_p2sh_p2wpkh_signed_tx(
        raw_tx,
        prev_hash=prev_tx.txid,
        prev_index=0,
        amount=100_000,
        expected_pubkey=pubkey,
        expected_output=ExpectedOutput(output_address, 90_000),
    )
    print(
        f"PASS {network_name} P2SH-P2WPKH: from={input_address} to={output_address} amount=90000 "
        f"sigs={list(map(len, signatures))} raw_len={len(raw_tx)}",
        flush=True,
    )


def test_testnet_legacy_p2pkh(session: Any) -> None:
    test_legacy_p2pkh(session, coin_name="Testnet", testnet=True)


def test_testnet_p2sh_p2wpkh(session: Any) -> None:
    test_p2sh_p2wpkh(session, coin_name="Testnet", testnet=True)


def test_mainnet_legacy_p2pkh(session: Any) -> None:
    test_legacy_p2pkh(session, coin_name="Bitcoin", testnet=False)


def test_mainnet_p2sh_p2wpkh(session: Any) -> None:
    test_p2sh_p2wpkh(session, coin_name="Bitcoin", testnet=False)


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
        "--skip-mainnet-sign",
        action="store_true",
        help="Skip the fake mainnet P2WPKH signing regression.",
    )
    parser.add_argument("--skip-rejections", action="store_true", help="Skip negative protocol tests.")
    parser.add_argument("--include-legacy", action="store_true", help="Run real-device P2PKH/P2SH-P2WPKH tests.")
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

    session = get_session("codex-btc-xpubs")
    try:
        test_account_xpubs(session)
    finally:
        close_session(session)

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

    if not args.skip_mainnet_sign:
        session = get_session("codex-btc-mainnet")
        try:
            test_mainnet_single(session)
        finally:
            close_session(session)
    else:
        print("SKIP mainnet signing", flush=True)
    if args.include_legacy:
        session = get_session("codex-btc-legacy-p2pkh")
        try:
            test_testnet_legacy_p2pkh(session)
        finally:
            close_session(session)
        session = get_session("codex-btc-mainnet-legacy-p2pkh")
        try:
            test_mainnet_legacy_p2pkh(session)
        finally:
            close_session(session)
        session = get_session("codex-btc-p2sh-p2wpkh")
        try:
            test_testnet_p2sh_p2wpkh(session)
        finally:
            close_session(session)
        session = get_session("codex-btc-mainnet-p2sh-p2wpkh")
        try:
            test_mainnet_p2sh_p2wpkh(session)
        finally:
            close_session(session)
    else:
        print("SKIP legacy/P2SH-P2WPKH signing; pass --include-legacy to enable", flush=True)
    if not args.skip_rejections:
        test_rejections()
    print("PASS btc_hardware_protocol_tests", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
