#!/usr/bin/env python3
"""Compare public local host-gate vectors with independent community libraries."""

from __future__ import annotations

import argparse
import hashlib
import io
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import base58
import rlp
from bech32 import bech32_encode, convertbits
from eth_account import Account
from eth_account.typed_transactions import TypedTransaction
from eth_abi import decode as abi_decode
from eth_keys import keys
from eth_utils import keccak, to_checksum_address
from trezorlib import messages, protobuf


PRIVATE_KEY_ONE = bytes.fromhex("00" * 31 + "01")
TESTNET_P2PKH_VERSION = b"\x6f"
WIRE_CHUNK_SIZE = 64
WIRE_INIT_HEADER_LEN = 9
WIRE_CONT_HEADER_LEN = 1
WIRE_MARKER = 0x3F
WIRE_MAGIC = 0x23


def parse_vectors(output: str) -> dict[str, str]:
    vectors: dict[str, str] = {}
    for line in output.splitlines():
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        vectors[key] = value
    return vectors


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def p2wpkh_address_testnet(pubkey_hash: bytes) -> str:
    return bech32_encode("tb", [0] + convertbits(pubkey_hash, 8, 5))


def ethereum_legacy_signing_fields(
    *, nonce: int, gas_price: int, gas_limit: int, to_address: bytes, value: int, data: bytes, chain_id: int
) -> list[int | bytes]:
    return [
        nonce,
        gas_price,
        gas_limit,
        to_address,
        value,
        data,
        chain_id,
        0,
        0,
    ]


def ethereum_legacy_signed_fields(
    *, nonce: int, gas_price: int, gas_limit: int, to_address: bytes, value: int, data: bytes, v: int, r: int, s: int
) -> list[int | bytes]:
    return [
        nonce,
        gas_price,
        gas_limit,
        to_address,
        value,
        data,
        v,
        r,
        s,
    ]


def decode_legacy_raw_tx(raw_tx: bytes) -> dict[str, object]:
    decoded = rlp.decode(raw_tx)
    if not isinstance(decoded, list) or len(decoded) != 9:
        field_count = len(decoded) if isinstance(decoded, list) else "not-list"
        raise AssertionError(f"unexpected legacy Ethereum raw tx field count: {field_count}")

    def as_int(value: bytes) -> int:
        return int.from_bytes(value, "big") if value else 0

    nonce, gas_price, gas_limit, to_address, value, data, v_bytes, r_bytes, s_bytes = decoded
    v = as_int(v_bytes)
    if v < 35:
        raise AssertionError(f"legacy Ethereum tx is missing EIP-155 v value: {v}")
    chain_id = (v - 35) // 2
    recovery_id = (v - 35) % 2
    if recovery_id not in (0, 1):
        raise AssertionError(f"invalid Ethereum recovery id: {recovery_id}")

    signing_payload = rlp.encode(
        ethereum_legacy_signing_fields(
            nonce=as_int(nonce),
            gas_price=as_int(gas_price),
            gas_limit=as_int(gas_limit),
            to_address=to_address,
            value=as_int(value),
            data=data,
            chain_id=chain_id,
        )
    )
    signing_hash = keccak(signing_payload)
    signature = keys.Signature(vrs=(recovery_id, as_int(r_bytes), as_int(s_bytes)))
    recovered_address = signature.recover_public_key_from_msg_hash(signing_hash).to_checksum_address()

    return {
        "nonce": as_int(nonce),
        "gas_price": as_int(gas_price),
        "gas_limit": as_int(gas_limit),
        "to": "0x" + to_address.hex(),
        "value": as_int(value),
        "data": "0x" + data.hex(),
        "chain_id": chain_id,
        "recovery_id": recovery_id,
        "signing_payload": signing_payload.hex(),
        "signing_hash": signing_hash.hex(),
        "from": recovered_address,
    }


def expected_vectors() -> dict[str, str]:
    private_key = keys.PrivateKey(PRIVATE_KEY_ONE)
    public_key = private_key.public_key
    eth_address_bytes = public_key.to_canonical_address()
    eth_checksum = to_checksum_address(eth_address_bytes)
    compressed_pubkey = public_key.to_compressed_bytes()
    pubkey_hash = hash160(compressed_pubkey)
    p2wpkh_script = b"\x00\x14" + pubkey_hash
    p2sh_p2wpkh_redeem_hash = hash160(p2wpkh_script)

    to_address = bytes([0x35] * 20)
    eip155_payload = rlp.encode(
        ethereum_legacy_signing_fields(
            nonce=9,
            gas_price=20_000_000_000,
            gas_limit=21_000,
            to_address=to_address,
            value=1_000_000_000_000_000_000,
            data=b"",
            chain_id=1,
        )
    )
    eip155_hash = keccak(eip155_payload)

    eip1559_payload = b"\x02" + rlp.encode(
        [
            1,
            0,
            1,
            2,
            21_000,
            to_address,
            b"",
            b"",
            [],
        ]
    )

    erc20_recipient = bytes.fromhex("7e5f4552091a69125d5dfcb7b8c2659029395bdf")
    erc20_amount = (50).to_bytes(32, "big")
    erc20_address_arg = b"\x00" * 12 + erc20_recipient
    transfer_selector = keccak(text="transfer(address,uint256)")[:4]
    approve_selector = keccak(text="approve(address,uint256)")[:4]

    return {
        "eth_checksum_address": eth_checksum,
        "tron_base58_address": base58.b58encode_check(b"\x41" + eth_address_bytes).decode(),
        "btc_testnet_p2pkh_address": base58.b58encode_check(
            TESTNET_P2PKH_VERSION + pubkey_hash
        ).decode(),
        "btc_testnet_p2wpkh_address": p2wpkh_address_testnet(pubkey_hash),
        "btc_testnet_p2sh_p2wpkh_address": base58.b58encode_check(b"\xc4" + p2sh_p2wpkh_redeem_hash).decode(),
        "eth_eip155_signing_payload": eip155_payload.hex(),
        "eth_eip155_signing_hash": eip155_hash.hex(),
        "eth_eip1559_signing_payload": eip1559_payload.hex(),
        "erc20_transfer_call": (transfer_selector + erc20_address_arg + erc20_amount).hex(),
        "erc20_approve_call": (approve_selector + erc20_address_arg + erc20_amount).hex(),
    }


def check_eth_signed_raw_tx_oracle(local_vectors: dict[str, str], expected: dict[str, str]) -> None:
    """Verify ETH raw tx semantics with independent Python libraries.

    The local C gate exposes a public EIP-155 payload/hash test vector. This
    oracle signs that vector with eth_keys, serializes a raw transaction with
    rlp, decodes it again, and recovers the sender address from v/r/s.
    """

    to_address = bytes.fromhex("35" * 20)
    signing_hash = bytes.fromhex(local_vectors["eth_eip155_signing_hash"])
    signature = keys.PrivateKey(PRIVATE_KEY_ONE).sign_msg_hash(signing_hash)
    eip155_v = 35 + (2 * 1) + signature.v
    raw_tx = rlp.encode(
        ethereum_legacy_signed_fields(
            nonce=9,
            gas_price=20_000_000_000,
            gas_limit=21_000,
            to_address=to_address,
            value=1_000_000_000_000_000_000,
            data=b"",
            v=eip155_v,
            r=signature.r,
            s=signature.s,
        )
    )
    decoded = decode_legacy_raw_tx(raw_tx)
    expected_decoded: dict[str, object] = {
        "nonce": 9,
        "gas_price": 20_000_000_000,
        "gas_limit": 21_000,
        "to": "0x" + to_address.hex(),
        "value": 1_000_000_000_000_000_000,
        "data": "0x",
        "chain_id": 1,
        "signing_payload": local_vectors["eth_eip155_signing_payload"],
        "signing_hash": local_vectors["eth_eip155_signing_hash"],
        "from": expected["eth_checksum_address"],
    }
    for key, expected_value in expected_decoded.items():
        actual_value = decoded[key]
        if actual_value != expected_value:
            raise AssertionError(
                f"Ethereum signed raw tx oracle mismatch for {key}: actual={actual_value} expected={expected_value}"
            )


def check_erc20_legacy_signed_raw_tx_oracle(local_vectors: dict[str, str], expected: dict[str, str]) -> None:
    token_contract = bytes.fromhex("11" * 20)
    cases = [
        ("erc20_transfer_call", "transfer(address,uint256)"),
        ("erc20_approve_call", "approve(address,uint256)"),
    ]
    for vector_key, abi_signature in cases:
        calldata = bytes.fromhex(local_vectors[vector_key])
        signing_fields = ethereum_legacy_signing_fields(
            nonce=9,
            gas_price=20_000_000_000,
            gas_limit=60_000,
            to_address=token_contract,
            value=0,
            data=calldata,
            chain_id=1,
        )
        signature = keys.PrivateKey(PRIVATE_KEY_ONE).sign_msg_hash(keccak(rlp.encode(signing_fields)))
        raw_tx = rlp.encode(
            ethereum_legacy_signed_fields(
                nonce=9,
                gas_price=20_000_000_000,
                gas_limit=60_000,
                to_address=token_contract,
                value=0,
                data=calldata,
                v=35 + (2 * 1) + signature.v,
                r=signature.r,
                s=signature.s,
            )
        )
        decoded = decode_legacy_raw_tx(raw_tx)
        recipient, amount = decode_erc20_address_uint256_call(bytes.fromhex(decoded["data"][2:]), abi_signature)
        expected_decoded: dict[str, object] = {
            "nonce": 9,
            "gas_price": 20_000_000_000,
            "gas_limit": 60_000,
            "to": "0x" + token_contract.hex(),
            "value": 0,
            "data": "0x" + calldata.hex(),
            "chain_id": 1,
            "from": expected["eth_checksum_address"],
            "recipient": expected["eth_checksum_address"],
            "amount": 50,
        }
        actual_decoded: dict[str, object] = {
            "nonce": decoded["nonce"],
            "gas_price": decoded["gas_price"],
            "gas_limit": decoded["gas_limit"],
            "to": decoded["to"],
            "value": decoded["value"],
            "data": decoded["data"],
            "chain_id": decoded["chain_id"],
            "from": decoded["from"],
            "recipient": recipient,
            "amount": amount,
        }
        for key, expected_value in expected_decoded.items():
            actual_value = actual_decoded[key]
            if actual_value != expected_value:
                raise AssertionError(
                    f"{vector_key} signed raw tx oracle mismatch for {key}: "
                    f"actual={actual_value} expected={expected_value}"
                )


def check_eth_eip1559_signed_raw_tx_oracle(local_vectors: dict[str, str], expected: dict[str, str]) -> None:
    """Verify EIP-1559 raw tx semantics with eth-account's typed tx support."""

    tx_before: dict[str, object] = {
        "type": 2,
        "chainId": 1,
        "nonce": 0,
        "maxPriorityFeePerGas": 1,
        "maxFeePerGas": 2,
        "gas": 21_000,
        "to": "0x3535353535353535353535353535353535353535",
        "value": 0,
        "data": b"",
        "accessList": [],
    }
    signed = Account.sign_transaction(tx_before, PRIVATE_KEY_ONE)
    raw_tx = signed.raw_transaction
    if not raw_tx or raw_tx[0] != 2:
        raise AssertionError(f"EIP1559 signed raw tx must start with type 0x02: {raw_tx.hex()}")

    decoded = TypedTransaction.from_bytes(raw_tx)
    decoded_dict = decoded.as_dict()
    signing_hash = decoded.hash()
    expected_signing_hash = keccak(bytes.fromhex(local_vectors["eth_eip1559_signing_payload"]))
    if signing_hash != expected_signing_hash:
        raise AssertionError(
            f"EIP1559 signing hash mismatch: actual={signing_hash.hex()} expected={expected_signing_hash.hex()}"
        )

    recovered = Account.recover_transaction(raw_tx)
    if recovered != expected["eth_checksum_address"]:
        raise AssertionError(f"EIP1559 recovered from mismatch: actual={recovered} expected={expected['eth_checksum_address']}")

    expected_after: dict[str, object] = {
        "type": tx_before["type"],
        "chainId": tx_before["chainId"],
        "nonce": tx_before["nonce"],
        "maxPriorityFeePerGas": tx_before["maxPriorityFeePerGas"],
        "maxFeePerGas": tx_before["maxFeePerGas"],
        "gas": tx_before["gas"],
        "to": tx_before["to"],
        "value": tx_before["value"],
        "data": "0x",
        "accessList": (),
    }
    actual_after: dict[str, object] = {
        "type": decoded_dict["type"],
        "chainId": decoded_dict["chainId"],
        "nonce": decoded_dict["nonce"],
        "maxPriorityFeePerGas": decoded_dict["maxPriorityFeePerGas"],
        "maxFeePerGas": decoded_dict["maxFeePerGas"],
        "gas": decoded_dict["gas"],
        "to": "0x" + bytes(decoded_dict["to"]).hex(),
        "value": decoded_dict["value"],
        "data": "0x" + bytes(decoded_dict["data"]).hex(),
        "accessList": decoded_dict["accessList"],
    }
    for key, expected_value in expected_after.items():
        actual_value = actual_after[key]
        if actual_value != expected_value:
            raise AssertionError(
                f"EIP1559 signed raw tx oracle mismatch for {key}: actual={actual_value} expected={expected_value}"
            )


def decode_erc20_address_uint256_call(calldata: bytes, signature: str) -> tuple[str, int]:
    selector = keccak(text=signature)[:4]
    if len(calldata) != 4 + 32 + 32:
        raise AssertionError(f"{signature} calldata has invalid length: {len(calldata)}")
    if calldata[:4] != selector:
        raise AssertionError(
            f"{signature} selector mismatch: actual={calldata[:4].hex()} expected={selector.hex()}"
        )
    recipient, amount = abi_decode(["address", "uint256"], calldata[4:])
    if not isinstance(recipient, str) or not isinstance(amount, int):
        raise AssertionError(f"{signature} ABI decode returned unexpected types")
    return to_checksum_address(recipient), amount


def check_erc20_calldata_oracle(local_vectors: dict[str, str], expected: dict[str, str]) -> None:
    expected_recipient = expected["eth_checksum_address"]
    expected_amount = 50
    cases = [
        ("erc20_transfer_call", "transfer(address,uint256)"),
        ("erc20_approve_call", "approve(address,uint256)"),
    ]
    for vector_key, signature in cases:
        recipient, amount = decode_erc20_address_uint256_call(bytes.fromhex(local_vectors[vector_key]), signature)
        if recipient != expected_recipient:
            raise AssertionError(
                f"{vector_key} recipient mismatch: actual={recipient} expected={expected_recipient}"
            )
        if amount != expected_amount:
            raise AssertionError(f"{vector_key} amount mismatch: actual={amount} expected={expected_amount}")


def message_payload(message: messages.MessageType) -> bytes:
    output = io.BytesIO()
    protobuf.dump_message(output, message)
    return output.getvalue()


def wire_encode(message_type: int, payload: bytes) -> bytes:
    first_capacity = WIRE_CHUNK_SIZE - WIRE_INIT_HEADER_LEN
    cont_capacity = WIRE_CHUNK_SIZE - WIRE_CONT_HEADER_LEN
    chunks: list[bytes] = []
    first = bytearray(WIRE_CHUNK_SIZE)
    first[0] = WIRE_MARKER
    first[1] = WIRE_MAGIC
    first[2] = WIRE_MAGIC
    first[3:5] = int(message_type).to_bytes(2, "big")
    first[5:9] = len(payload).to_bytes(4, "big")
    first_payload = payload[:first_capacity]
    first[WIRE_INIT_HEADER_LEN : WIRE_INIT_HEADER_LEN + len(first_payload)] = first_payload
    chunks.append(bytes(first))
    offset = len(first_payload)
    while offset < len(payload):
        chunk = bytearray(WIRE_CHUNK_SIZE)
        chunk[0] = WIRE_MARKER
        part = payload[offset : offset + cont_capacity]
        chunk[WIRE_CONT_HEADER_LEN : WIRE_CONT_HEADER_LEN + len(part)] = part
        chunks.append(bytes(chunk))
        offset += len(part)
    return b"".join(chunks)


def run_local_wire_oracle(gate: Path, message_type: int, message: messages.MessageType) -> tuple[int, bytes]:
    wire = wire_encode(message_type, message_payload(message))
    output = subprocess.check_output([str(gate), "--trezor-wire-oracle", wire.hex()], text=True)
    parsed = parse_vectors(output)
    return int(parsed["response_type"]), bytes.fromhex(parsed["response_payload"])


def assert_trezor_failure(
    gate: Path,
    message_type: int,
    message: messages.MessageType,
    expected_code: messages.FailureType,
    case_name: str,
) -> None:
    response_type, payload = run_local_wire_oracle(gate, message_type, message)
    if response_type != messages.MessageType.Failure:
        raise AssertionError(f"{case_name} must fail, got response type {response_type}")
    failure = protobuf.load_message(io.BytesIO(payload), messages.Failure)
    if failure.code != expected_code:
        raise AssertionError(f"{case_name} failure code mismatch: actual={failure.code} expected={expected_code}")


@dataclass(frozen=True)
class BtcSignTxHostStep:
    request_type: messages.RequestType
    ack_kind: str
    request_index: int | None = None
    signature_index: int | None = None
    signature: bytes | None = None
    serialized_tx: bytes | None = None


class ScriptedBtcSignTxClient:
    def __init__(
        self,
        script: list[BtcSignTxHostStep],
        final_signature: bytes,
        final_tx: bytes,
        *,
        final_signature_index: int = 0,
        coin_name: str = "Testnet",
        inputs_count: int = 1,
        outputs_count: int = 1,
        input_prev_hashes: list[bytes] | None = None,
        input_amounts: list[int] | None = None,
        output_amounts: list[int] | None = None,
    ) -> None:
        self.script = script
        self.final_signature = final_signature
        self.final_tx = final_tx
        self.final_signature_index = final_signature_index
        self.coin_name = coin_name
        self.inputs_count = inputs_count
        self.outputs_count = outputs_count
        self.input_prev_hashes = input_prev_hashes or [btc_tx_prev_hash()]
        self.input_amounts = input_amounts or [100_000]
        self.output_amounts = output_amounts or [90_000]
        self.calls: list[messages.MessageType] = []
        self.ack_index = 0
        self.started = False
        self.opened = False
        self.closed = False

    def call(self, message: messages.MessageType, expect: type[messages.MessageType] | None = None) -> messages.TxRequest:
        if not self.opened or self.closed:
            raise AssertionError("trezorlib BTC SignTx call happened outside an open session")
        self.calls.append(message)
        if not self.started:
            if not isinstance(message, messages.SignTx):
                raise AssertionError(f"first BTC SignTx call was {type(message).__name__}")
            if expect is not messages.TxRequest:
                raise AssertionError(f"unexpected SignTx expect type: {expect}")
            if (
                message.coin_name != self.coin_name
                or message.inputs_count != self.inputs_count
                or message.outputs_count != self.outputs_count
            ):
                raise AssertionError(f"unexpected SignTx message: {message}")
            if message.version != 2 or message.lock_time != 0:
                raise AssertionError(f"unexpected SignTx version/lock_time: {message}")
            self.started = True
            return self._next_request()

        if not isinstance(message, messages.TxAck):
            raise AssertionError(f"BTC host flow expected TxAck, got {type(message).__name__}")
        if expect is not messages.TxRequest:
            raise AssertionError(f"unexpected TxAck expect type: {expect}")
        if message.tx is None:
            raise AssertionError("TxAck missing TransactionType")

        previous = self.script[self.ack_index]
        if previous.ack_kind == "meta":
            if message.tx.inputs or message.tx.outputs or message.tx.bin_outputs:
                raise AssertionError(f"TXMETA ack leaked full transaction data: {message.tx}")
            if message.tx.inputs_cnt != self.inputs_count or message.tx.outputs_cnt != self.outputs_count:
                raise AssertionError(f"unexpected TXMETA counts: {message.tx}")
        elif previous.ack_kind == "input":
            assert previous.request_index is not None
            if (
                len(message.tx.inputs) != 1
                or message.tx.inputs[0].prev_hash != self.input_prev_hashes[previous.request_index]
            ):
                raise AssertionError(f"unexpected TXINPUT ack: {message.tx}")
            if message.tx.inputs[0].script_type != messages.InputScriptType.SPENDWITNESS:
                raise AssertionError(f"unexpected BTC input script type: {message.tx.inputs[0].script_type}")
            if message.tx.inputs[0].amount != self.input_amounts[previous.request_index]:
                raise AssertionError(f"unexpected BTC input amount: {message.tx.inputs[0].amount}")
        elif previous.ack_kind == "output":
            assert previous.request_index is not None
            if len(message.tx.outputs) != 1:
                raise AssertionError(f"unexpected TXOUTPUT ack: {message.tx}")
            if (
                message.tx.outputs[0].address != btc_tx_output_address()
                or message.tx.outputs[0].amount != self.output_amounts[previous.request_index]
            ):
                raise AssertionError(f"unexpected BTC output: {message.tx.outputs[0]}")
        else:
            raise AssertionError(f"unhandled BTC ack kind: {previous.ack_kind}")

        self.ack_index += 1
        return self._next_request()

    def open(self) -> None:
        if self.opened or self.closed:
            raise AssertionError("trezorlib BTC SignTx session opened more than once")
        self.opened = True

    def close(self) -> None:
        if not self.opened or self.closed:
            raise AssertionError("trezorlib BTC SignTx session closed out of order")
        self.closed = True

    def _next_request(self) -> messages.TxRequest:
        if self.ack_index > len(self.script):
            raise AssertionError("BTC host script advanced past the end")

        if self.ack_index == len(self.script):
            return messages.TxRequest(
                request_type=messages.RequestType.TXFINISHED,
                serialized=messages.TxRequestSerializedType(
                    signature_index=self.final_signature_index,
                    signature=self.final_signature,
                    serialized_tx=self.final_tx,
                ),
            )

        step = self.script[self.ack_index]
        serialized = None
        if step.signature_index is not None:
            serialized = messages.TxRequestSerializedType(
                signature_index=step.signature_index,
                signature=step.signature,
                serialized_tx=step.serialized_tx,
            )
        return messages.TxRequest(
            request_type=step.request_type,
            details=messages.TxRequestDetailsType(request_index=step.request_index),
            serialized=serialized,
        )


def btc_tx_prev_hash() -> bytes:
    return bytes.fromhex("11" * 32)


def btc_tx_output_address() -> str:
    return "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"


def check_trezorlib_btc_signtx_host_flow_oracle() -> None:
    from trezorlib import btc

    input_path = [0x80000054, 0x80000001, 0x80000000, 0, 0]
    tx_input = messages.TxInputType(
        address_n=input_path,
        prev_hash=btc_tx_prev_hash(),
        prev_index=0,
        script_type=messages.InputScriptType.SPENDWITNESS,
        amount=100_000,
        sequence=0xFFFFFFFF,
    )
    tx_output = messages.TxOutputType(
        address=btc_tx_output_address(),
        amount=90_000,
        script_type=messages.OutputScriptType.PAYTOADDRESS,
    )

    signature = bytes.fromhex("30" + "44" * 70)
    serialized_tx = bytes.fromhex("02000000000100")
    client = ScriptedBtcSignTxClient(
        [
            BtcSignTxHostStep(messages.RequestType.TXMETA, "meta"),
            BtcSignTxHostStep(messages.RequestType.TXINPUT, "input", request_index=0),
            BtcSignTxHostStep(messages.RequestType.TXOUTPUT, "output", request_index=0),
        ],
        signature,
        serialized_tx,
    )

    signatures, signed_tx = btc.sign_tx(
        client,
        "Testnet",
        [tx_input],
        [tx_output],
        version=2,
        lock_time=0,
    )
    if signatures != [signature]:
        raise AssertionError(f"trezorlib BTC SignTx signatures mismatch: {signatures}")
    if signed_tx != serialized_tx:
        raise AssertionError(f"trezorlib BTC SignTx serialized tx mismatch: {signed_tx.hex()}")

    call_types = [type(call).__name__ for call in client.calls]
    if call_types != ["SignTx", "TxAck", "TxAck", "TxAck"]:
        raise AssertionError(f"unexpected trezorlib BTC host call sequence: {call_types}")
    if not client.closed:
        raise AssertionError("trezorlib BTC SignTx session did not close")

    input_path_1 = [0x80000054, 0x80000001, 0x80000000, 0, 1]
    tx_input_1 = messages.TxInputType(
        address_n=input_path_1,
        prev_hash=bytes.fromhex("22" * 32),
        prev_index=1,
        script_type=messages.InputScriptType.SPENDWITNESS,
        amount=40_000,
        sequence=0xFFFFFFFF,
    )
    signature_0 = bytes.fromhex("30" + "55" * 70)
    signature_1 = bytes.fromhex("30" + "66" * 70)
    multi_serialized_tx = bytes.fromhex("0200000000010201")
    multi_client = ScriptedBtcSignTxClient(
        [
            BtcSignTxHostStep(messages.RequestType.TXMETA, "meta"),
            BtcSignTxHostStep(messages.RequestType.TXINPUT, "input", request_index=0),
            BtcSignTxHostStep(messages.RequestType.TXINPUT, "input", request_index=1),
            BtcSignTxHostStep(messages.RequestType.TXOUTPUT, "output", request_index=0),
            BtcSignTxHostStep(
                messages.RequestType.TXMETA,
                "meta",
                signature_index=0,
                signature=signature_0,
            ),
        ],
        signature_1,
        multi_serialized_tx,
        final_signature_index=1,
        inputs_count=2,
        outputs_count=1,
        input_prev_hashes=[btc_tx_prev_hash(), bytes.fromhex("22" * 32)],
        input_amounts=[100_000, 40_000],
        output_amounts=[90_000],
    )

    signatures, signed_tx = btc.sign_tx(
        multi_client,
        "Testnet",
        [tx_input, tx_input_1],
        [tx_output],
        version=2,
        lock_time=0,
    )
    if signatures != [signature_0, signature_1]:
        raise AssertionError(f"trezorlib multi-input BTC signatures mismatch: {signatures}")
    if signed_tx != multi_serialized_tx:
        raise AssertionError(f"trezorlib multi-input BTC serialized tx mismatch: {signed_tx.hex()}")

    call_types = [type(call).__name__ for call in multi_client.calls]
    if call_types != ["SignTx", "TxAck", "TxAck", "TxAck", "TxAck", "TxAck"]:
        raise AssertionError(f"unexpected trezorlib multi-input BTC host call sequence: {call_types}")
    if not multi_client.closed:
        raise AssertionError("trezorlib multi-input BTC SignTx session did not close")


def check_trezorlib_btc_protobuf_oracle() -> None:
    signtx_payload = message_payload(
        messages.SignTx(outputs_count=1, inputs_count=1, coin_name="Testnet", version=2, lock_time=0)
    )
    if signtx_payload.hex() != "080110011a07546573746e657420022800580060006801":
        raise AssertionError(f"unexpected trezorlib BTC SignTx protobuf: {signtx_payload.hex()}")

    txinput_request = message_payload(
        messages.TxRequest(
            request_type=messages.RequestType.TXINPUT,
            details=messages.TxRequestDetailsType(request_index=0),
        )
    )
    if txinput_request.hex() != "080012020800":
        raise AssertionError(f"unexpected trezorlib BTC TxRequest(TXINPUT) protobuf: {txinput_request.hex()}")

    txmeta_request = message_payload(
        messages.TxRequest(
            request_type=messages.RequestType.TXMETA,
            details=messages.TxRequestDetailsType(),
        )
    )
    if txmeta_request.hex() != "08021200":
        raise AssertionError(f"unexpected trezorlib BTC TxRequest(TXMETA) protobuf: {txmeta_request.hex()}")

    txfinished_request = message_payload(messages.TxRequest(request_type=messages.RequestType.TXFINISHED))
    if txfinished_request.hex() != "0803":
        raise AssertionError(f"unexpected trezorlib BTC TxRequest(TXFINISHED) protobuf: {txfinished_request.hex()}")


def check_trezorlib_protocol_oracle(gate: Path, local_vectors: dict[str, str]) -> None:
    response_type, payload = run_local_wire_oracle(gate, messages.MessageType.Initialize, messages.Initialize())
    if response_type != messages.MessageType.Features:
        raise AssertionError(f"Initialize response type mismatch: {response_type}")
    features = protobuf.load_message(io.BytesIO(payload), messages.Features)
    if not features.initialized or not features.pin_protection or features.passphrase_protection:
        raise AssertionError(f"unexpected Features state: {features}")
    if messages.Capability.Ethereum not in features.capabilities:
        raise AssertionError(f"missing Ethereum capability: {features.capabilities}")
    if messages.Capability.Bitcoin not in features.capabilities:
        raise AssertionError(f"missing Bitcoin capability: {features.capabilities}")

    response_type, payload = run_local_wire_oracle(gate, messages.MessageType.GetFeatures, messages.GetFeatures())
    if response_type != messages.MessageType.Features:
        raise AssertionError(f"GetFeatures response type mismatch: {response_type}")
    protobuf.load_message(io.BytesIO(payload), messages.Features)

    eth_path = [0x8000002C, 0x8000003C, 0x80000000, 0, 0]
    response_type, payload = run_local_wire_oracle(
        gate,
        messages.MessageType.EthereumGetAddress,
        messages.EthereumGetAddress(address_n=eth_path, show_display=False),
    )
    if response_type != messages.MessageType.EthereumAddress:
        raise AssertionError(f"EthereumGetAddress response type mismatch: {response_type}")
    eth_addr = protobuf.load_message(io.BytesIO(payload), messages.EthereumAddress)
    if eth_addr.address != "0x52908400098527886E0F7030069857D2E4169EE7":
        raise AssertionError(f"unexpected Ethereum address response: {eth_addr.address}")

    btc_address_cases = [
        (messages.InputScriptType.SPENDADDRESS, "btc_testnet_p2pkh_address"),
        (messages.InputScriptType.SPENDWITNESS, "btc_testnet_p2wpkh_address"),
        (messages.InputScriptType.SPENDP2SHWITNESS, "btc_testnet_p2sh_p2wpkh_address"),
    ]
    for script_type, vector_key in btc_address_cases:
        response_type, payload = run_local_wire_oracle(
            gate,
            messages.MessageType.GetAddress,
            messages.GetAddress(
                address_n=[0x8000002C, 0x80000001, 0x80000000, 0, 0],
                coin_name="Testnet",
                show_display=False,
                script_type=script_type,
            ),
        )
        if response_type != messages.MessageType.Address:
            raise AssertionError(f"GetAddress response type mismatch for {script_type}: {response_type}")
        btc_addr = protobuf.load_message(io.BytesIO(payload), messages.Address)
        if btc_addr.address != local_vectors[vector_key]:
            raise AssertionError(f"unexpected Bitcoin address response for {script_type}: {btc_addr.address}")

    response_type, payload = run_local_wire_oracle(
        gate,
        messages.MessageType.GetPublicKey,
        messages.GetPublicKey(
            address_n=[0x8000002C, 0x80000001, 0x80000000],
            coin_name="Testnet",
            script_type=messages.InputScriptType.SPENDADDRESS,
        ),
    )
    if response_type != messages.MessageType.PublicKey:
        raise AssertionError(f"GetPublicKey response type mismatch: {response_type}")
    public_key = protobuf.load_message(io.BytesIO(payload), messages.PublicKey)
    if getattr(public_key.node, "private_key", None):
        raise AssertionError("PublicKey response unexpectedly contains private_key")
    if not public_key.xpub:
        raise AssertionError("PublicKey response missing xpub")

    response_type, payload = run_local_wire_oracle(
        gate,
        messages.MessageType.EthereumSignTx,
        messages.EthereumSignTx(
            address_n=eth_path,
            nonce=b"\x09",
            gas_price=b"\x04\xa8\x17\xc8\x00",
            gas_limit=b"\x52\x08",
            to="0x52908400098527886E0F7030069857D2E4169EE7",
            value=b"\x01",
            data_initial_chunk=b"",
            data_length=0,
            chain_id=1,
        ),
    )
    if response_type != messages.MessageType.EthereumTxRequest:
        raise AssertionError(f"EthereumSignTx response type mismatch: {response_type}")
    tx_request = protobuf.load_message(io.BytesIO(payload), messages.EthereumTxRequest)
    if tx_request.signature_v not in (37, 38):
        raise AssertionError(f"unexpected Ethereum signature v: {tx_request.signature_v}")
    if len(tx_request.signature_r or b"") != 32 or len(tx_request.signature_s or b"") != 32:
        raise AssertionError("Ethereum signature response has invalid r/s length")

    response_type, payload = run_local_wire_oracle(
        gate,
        messages.MessageType.EthereumSignTxEIP1559,
        messages.EthereumSignTxEIP1559(
            address_n=eth_path,
            nonce=b"",
            max_gas_fee=b"\x02",
            max_priority_fee=b"\x01",
            gas_limit=b"\x52\x08",
            to="0x" + "35" * 20,
            value=b"",
            data_initial_chunk=b"",
            data_length=0,
            chain_id=1,
        ),
    )
    if response_type != messages.MessageType.EthereumTxRequest:
        raise AssertionError(f"EthereumSignTxEIP1559 response type mismatch: {response_type}")
    tx_request = protobuf.load_message(io.BytesIO(payload), messages.EthereumTxRequest)
    if tx_request.signature_v != 1:
        raise AssertionError(f"unexpected EIP1559 signature v: {tx_request.signature_v}")
    if len(tx_request.signature_r or b"") != 32 or len(tx_request.signature_s or b"") != 32:
        raise AssertionError("EIP1559 signature response has invalid r/s length")

    response_type, payload = run_local_wire_oracle(
        gate,
        messages.MessageType.EthereumSignTx,
        messages.EthereumSignTx(
            address_n=eth_path,
            nonce=b"\x09",
            gas_price=b"\x04\xa8\x17\xc8\x00",
            gas_limit=b"\x52\x08",
            to="0x" + "11" * 20,
            value=b"",
            data_initial_chunk=bytes.fromhex(local_vectors["erc20_transfer_call"]),
            data_length=len(bytes.fromhex(local_vectors["erc20_transfer_call"])),
            chain_id=1,
            definitions=messages.EthereumDefinitions(
                encoded_token=bytes.fromhex(local_vectors["trezor_usdt_signed_token_definition"])
            ),
        ),
    )
    if response_type != messages.MessageType.EthereumTxRequest:
        raise AssertionError(f"ERC20 definitions EthereumSignTx response type mismatch: {response_type}")
    tx_request = protobuf.load_message(io.BytesIO(payload), messages.EthereumTxRequest)
    if tx_request.signature_v not in (37, 38):
        raise AssertionError(f"unexpected ERC20 definitions signature v: {tx_request.signature_v}")
    if len(tx_request.signature_r or b"") != 32 or len(tx_request.signature_s or b"") != 32:
        raise AssertionError("ERC20 definitions signature response has invalid r/s length")

    assert_trezor_failure(
        gate,
        messages.MessageType.EthereumSignTx,
        messages.EthereumSignTx(
            address_n=eth_path,
            nonce=b"\x01",
            gas_price=b"\x01",
            gas_limit=b"\x52\x08",
            to="",
            value=b"",
            data_initial_chunk=b"\x60",
            data_length=1,
            chain_id=1,
        ),
        messages.FailureType.DataError,
        "Ethereum contract creation",
    )
    assert_trezor_failure(
        gate,
        messages.MessageType.EthereumSignTx,
        messages.EthereumSignTx(
            address_n=eth_path,
            nonce=b"\x09",
            gas_price=b"\x04\xa8\x17\xc8\x00",
            gas_limit=b"\xea\x60",
            to="0x" + "11" * 20,
            value=b"",
            data_initial_chunk=bytes.fromhex(local_vectors["erc20_transfer_call"]),
            data_length=len(bytes.fromhex(local_vectors["erc20_transfer_call"])),
            chain_id=2,
            definitions=messages.EthereumDefinitions(
                encoded_token=bytes.fromhex(local_vectors["trezor_usdt_signed_token_definition"])
            ),
        ),
        messages.FailureType.ActionCancelled,
        "Ethereum token definition chain mismatch",
    )
    assert_trezor_failure(
        gate,
        messages.MessageType.EthereumSignTx,
        messages.EthereumSignTx(
            address_n=eth_path,
            nonce=b"\x09",
            gas_price=b"\x04\xa8\x17\xc8\x00",
            gas_limit=b"\xea\x60",
            to="0x" + "11" * 20,
            value=b"",
            data_initial_chunk=bytes.fromhex(local_vectors["erc20_transfer_call"]),
            data_length=len(bytes.fromhex(local_vectors["erc20_transfer_call"])),
            chain_id=1,
            definitions=messages.EthereumDefinitions(encoded_token=b"not-a-signed-definition"),
        ),
        messages.FailureType.DataError,
        "Ethereum malformed token definition",
    )
    assert_trezor_failure(
        gate,
        messages.MessageType.EthereumSignTxEIP1559,
        messages.EthereumSignTxEIP1559(
            address_n=eth_path,
            nonce=b"",
            max_gas_fee=b"\x02",
            max_priority_fee=b"\x01",
            gas_limit=b"\x52\x08",
            to="0x" + "35" * 20,
            value=b"",
            data_initial_chunk=b"",
            data_length=0,
            chain_id=1,
            access_list=[
                messages.EthereumAccessList(address="0x" + "12" * 20, storage_keys=[b"\x00" * 32])
            ],
        ),
        messages.FailureType.DataError,
        "Ethereum EIP1559 access list",
    )

    response_type, payload = run_local_wire_oracle(
        gate,
        messages.MessageType.SignTx,
        messages.SignTx(coin_name="Testnet", inputs_count=1, outputs_count=1, version=2, lock_time=0),
    )
    if response_type != messages.MessageType.TxRequest:
        raise AssertionError(f"BTC SignTx preflight response type mismatch: {response_type}")
    btc_tx_request = protobuf.load_message(io.BytesIO(payload), messages.TxRequest)
    if btc_tx_request.request_type != messages.RequestType.TXMETA or btc_tx_request.details is None:
        raise AssertionError(f"BTC SignTx must start with TxRequest(TXMETA): {btc_tx_request}")

    response_type, payload = run_local_wire_oracle(
        gate,
        messages.MessageType.SignTx,
        messages.SignTx(coin_name="Bitcoin", inputs_count=1, outputs_count=1),
    )
    if response_type != messages.MessageType.TxRequest:
        raise AssertionError(f"BTC mainnet SignTx preflight response type mismatch: {response_type}")
    btc_tx_request = protobuf.load_message(io.BytesIO(payload), messages.TxRequest)
    if btc_tx_request.request_type != messages.RequestType.TXMETA or btc_tx_request.details is None:
        raise AssertionError(f"BTC mainnet SignTx must start with TxRequest(TXMETA): {btc_tx_request}")

    response_type, payload = run_local_wire_oracle(
        gate, messages.MessageType.TxAck, messages.TxAck(tx=messages.TransactionType())
    )
    if response_type != messages.MessageType.Failure:
        raise AssertionError(f"orphan BTC TxAck must fail: {response_type}")
    failure = protobuf.load_message(io.BytesIO(payload), messages.Failure)
    if failure.code != messages.FailureType.DataError:
        raise AssertionError(f"orphan BTC TxAck unexpected failure code: {failure.code}")

    response_type, payload = run_local_wire_oracle(
        gate,
        messages.MessageType.TxAckPaymentRequest,
        messages.TxAckPaymentRequest(recipient_name="merchant", signature=b"\x00" * 64),
    )
    if response_type != messages.MessageType.Failure:
        raise AssertionError(f"TxAckPaymentRequest must be rejected until BTC signing is implemented: {response_type}")
    failure = protobuf.load_message(io.BytesIO(payload), messages.Failure)
    if failure.code != messages.FailureType.UnexpectedMessage:
        raise AssertionError(f"TxAckPaymentRequest unexpected failure code: {failure.code}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--build-dir",
        default="build-tdisplays3-hardened-ok",
        help="Build directory containing eth_tron_address_gate",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    gate = repo_root / args.build_dir / "eth_tron_address_gate"
    if not gate.exists():
        print(f"missing local gate binary: {gate}", file=sys.stderr)
        return 1

    output = subprocess.check_output([str(gate), "--dump-oracle-vectors"], text=True)
    local = parse_vectors(output)
    expected = expected_vectors()

    missing = sorted(set(expected) - set(local))
    if missing:
        print(f"local oracle vector dump missing keys: {', '.join(missing)}", file=sys.stderr)
        return 1

    for key, expected_value in expected.items():
        local_value = local[key]
        if local_value != expected_value:
            print(f"external oracle mismatch for {key}", file=sys.stderr)
            print(f"  local:    {local_value}", file=sys.stderr)
            print(f"  external: {expected_value}", file=sys.stderr)
            return 1

    check_eth_signed_raw_tx_oracle(local, expected)
    check_erc20_legacy_signed_raw_tx_oracle(local, expected)
    check_eth_eip1559_signed_raw_tx_oracle(local, expected)
    check_erc20_calldata_oracle(local, expected)
    check_trezorlib_btc_protobuf_oracle()
    check_trezorlib_btc_signtx_host_flow_oracle()
    check_trezorlib_protocol_oracle(gate, local)
    print("PASS external_oracle_gates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
