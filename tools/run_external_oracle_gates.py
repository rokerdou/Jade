#!/usr/bin/env python3
"""Compare public local host-gate vectors with independent community libraries."""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import base58
import rlp
import safe_cli
from bech32 import bech32_encode, convertbits
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_account.typed_transactions import TypedTransaction
from eth_abi import decode as abi_decode
from eth_keys import keys
from eth_utils import keccak, to_checksum_address
from safe_eth.eth.eip712 import eip712_encode, eip712_encode_hash
from ecdsa import SECP256k1, SigningKey, VerifyingKey, util as ecdsa_util
from trezorlib import messages, protobuf
from trezorlib.tools import parse_path


PRIVATE_KEY_ONE = bytes.fromhex("00" * 31 + "01")
BTC_TEST_COMPRESSED_PUBKEY = keys.PrivateKey(PRIVATE_KEY_ONE).public_key.to_compressed_bytes()
TESTNET_P2PKH_VERSION = b"\x6f"
WIRE_CHUNK_SIZE = 64
WIRE_INIT_HEADER_LEN = 9
WIRE_CONT_HEADER_LEN = 1
WIRE_MARKER = 0x3F
WIRE_MAGIC = 0x23
ONEKEY_SIGN_PSBT_MESSAGE_TYPE = 10052
ETHEREUM_GNOSIS_SAFE_TX_ACK_MESSAGE_TYPE = 20118
ETHEREUM_GNOSIS_SAFE_TX_REQUEST_MESSAGE_TYPE = 20119
ETHEREUM_TYPED_DATA_SIGNATURE_MESSAGE_TYPE = 469


def safe_usdt_transfer_typed_data() -> dict[str, object]:
    recipient = "0x1111111111111111111111111111111111111111"
    amount = 1_234_567
    calldata = "0xa9059cbb" + ("0" * 24) + recipient[2:] + amount.to_bytes(32, "big").hex()
    return {
        "types": {
            "EIP712Domain": [
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "SafeTx": [
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "data", "type": "bytes"},
                {"name": "operation", "type": "uint8"},
                {"name": "safeTxGas", "type": "uint256"},
                {"name": "baseGas", "type": "uint256"},
                {"name": "gasPrice", "type": "uint256"},
                {"name": "gasToken", "type": "address"},
                {"name": "refundReceiver", "type": "address"},
                {"name": "nonce", "type": "uint256"},
            ],
        },
        "primaryType": "SafeTx",
        "domain": {
            "chainId": 1,
            "verifyingContract": "0x1234567890abcdef1234567890abcdef12345678",
        },
        "message": {
            "to": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            "value": 0,
            "data": calldata,
            "operation": 0,
            "safeTxGas": 50_000,
            "baseGas": 21_000,
            "gasPrice": 1_000_000_000,
            "gasToken": "0x0000000000000000000000000000000000000000",
            "refundReceiver": "0x0000000000000000000000000000000000000000",
            "nonce": 7,
        },
    }


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


def p2wpkh_address_mainnet(pubkey_hash: bytes) -> str:
    return bech32_encode("bc", [0] + convertbits(pubkey_hash, 8, 5))


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
    if not safe_cli.__file__:
        raise AssertionError("safe-cli import failed")

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
    safe_typed_data = safe_usdt_transfer_typed_data()
    safe_magic, safe_domain_hash, safe_message_hash = eip712_encode(safe_typed_data)
    safe_signable = encode_typed_data(full_message=safe_typed_data)
    safe_signing_hash = eip712_encode_hash(safe_typed_data)
    eth_account_safe_hash = keccak(b"\x19" + safe_signable.version + safe_signable.header + safe_signable.body)
    if safe_magic != b"\x19\x01":
        raise AssertionError(f"safe-eth-py EIP712 magic mismatch: {safe_magic.hex()}")
    if safe_signable.header != safe_domain_hash or safe_signable.body != safe_message_hash:
        raise AssertionError("safe-eth-py and eth-account SafeTx domain/message hashes differ")
    if eth_account_safe_hash != safe_signing_hash:
        raise AssertionError("safe-eth-py and eth-account SafeTx signing hashes differ")
    safe_calldata = bytes.fromhex(str(safe_typed_data["message"]["data"])[2:])

    return {
        "eth_checksum_address": eth_checksum,
        "tron_base58_address": base58.b58encode_check(b"\x41" + eth_address_bytes).decode(),
        "btc_testnet_p2pkh_address": base58.b58encode_check(
            TESTNET_P2PKH_VERSION + pubkey_hash
        ).decode(),
        "btc_mainnet_p2pkh_address": base58.b58encode_check(b"\x00" + pubkey_hash).decode(),
        "btc_testnet_p2wpkh_address": p2wpkh_address_testnet(pubkey_hash),
        "btc_mainnet_p2wpkh_address": p2wpkh_address_mainnet(pubkey_hash),
        "btc_testnet_p2sh_p2wpkh_address": base58.b58encode_check(b"\xc4" + p2sh_p2wpkh_redeem_hash).decode(),
        "btc_mainnet_p2sh_p2wpkh_address": base58.b58encode_check(b"\x05" + p2sh_p2wpkh_redeem_hash).decode(),
        "eth_eip155_signing_payload": eip155_payload.hex(),
        "eth_eip155_signing_hash": eip155_hash.hex(),
        "eth_eip1559_signing_payload": eip1559_payload.hex(),
        "erc20_transfer_call": (transfer_selector + erc20_address_arg + erc20_amount).hex(),
        "erc20_approve_call": (approve_selector + erc20_address_arg + erc20_amount).hex(),
        "safe_domain_hash": safe_domain_hash.hex(),
        "safe_message_hash": safe_message_hash.hex(),
        "safe_signing_hash": safe_signing_hash.hex(),
        "safe_usdt_transfer_call": safe_calldata.hex(),
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


def protobuf_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint cannot encode negative values")
    output = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            output.append(byte | 0x80)
        else:
            output.append(byte)
            return bytes(output)


def protobuf_len_field(field_number: int, value: bytes) -> bytes:
    return protobuf_varint((field_number << 3) | 2) + protobuf_varint(len(value)) + value


def protobuf_string_field(field_number: int, value: str) -> bytes:
    return protobuf_len_field(field_number, value.encode("ascii"))


def protobuf_varint_field(field_number: int, value: int) -> bytes:
    return protobuf_varint((field_number << 3) | 0) + protobuf_varint(value)


def minimal_uint256_bytes(value: int) -> bytes:
    if value < 0 or value >= 1 << 256:
        raise ValueError("uint256 out of range")
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def make_safe_tx_ack_payload(safe_typed_data: dict[str, object]) -> bytes:
    domain = safe_typed_data["domain"]
    message = safe_typed_data["message"]
    if not isinstance(domain, dict) or not isinstance(message, dict):
        raise AssertionError("invalid SafeTx typed data shape")

    payload = bytearray()
    payload += protobuf_string_field(1, str(message["to"]))
    payload += protobuf_len_field(2, minimal_uint256_bytes(int(message["value"])))
    payload += protobuf_len_field(3, bytes.fromhex(str(message["data"])[2:]))
    payload += protobuf_varint_field(4, int(message["operation"]))
    payload += protobuf_len_field(5, minimal_uint256_bytes(int(message["safeTxGas"])))
    payload += protobuf_len_field(6, minimal_uint256_bytes(int(message["baseGas"])))
    payload += protobuf_len_field(7, minimal_uint256_bytes(int(message["gasPrice"])))
    payload += protobuf_string_field(8, str(message["gasToken"]))
    payload += protobuf_string_field(9, str(message["refundReceiver"]))
    payload += protobuf_len_field(10, minimal_uint256_bytes(int(message["nonce"])))
    payload += protobuf_varint_field(11, int(domain["chainId"]))
    payload += protobuf_string_field(12, str(domain["verifyingContract"]))
    return bytes(payload)


def decode_typed_data_signature_payload(payload: bytes) -> tuple[bytes, str]:
    signature: bytes | None = None
    address: str | None = None
    pos = 0
    while pos < len(payload):
        key = 0
        shift = 0
        while True:
            if pos >= len(payload) or shift > 63:
                raise AssertionError("malformed typed-data signature protobuf key")
            byte = payload[pos]
            pos += 1
            key |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        field_number = key >> 3
        wire_type = key & 0x07
        if wire_type != 2:
            raise AssertionError(f"unexpected typed-data signature wire type: {wire_type}")
        length = 0
        shift = 0
        while True:
            if pos >= len(payload) or shift > 63:
                raise AssertionError("malformed typed-data signature protobuf length")
            byte = payload[pos]
            pos += 1
            length |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        if length > len(payload) - pos:
            raise AssertionError("typed-data signature payload overruns buffer")
        value = payload[pos : pos + length]
        pos += length
        if field_number == 1:
            if signature is not None:
                raise AssertionError("duplicate typed-data signature field")
            signature = value
        elif field_number == 2:
            if address is not None:
                raise AssertionError("duplicate typed-data address field")
            address = value.decode("ascii")
        else:
            raise AssertionError(f"unexpected typed-data signature field: {field_number}")
    if signature is None or address is None:
        raise AssertionError("typed-data signature response missing fields")
    return signature, address


def run_local_wire_oracle(gate: Path, message_type: int, message: messages.MessageType) -> tuple[int, bytes]:
    wire = wire_encode(message_type, message_payload(message))
    output = subprocess.check_output([str(gate), "--trezor-wire-oracle", wire.hex()], text=True)
    parsed = parse_vectors(output)
    return int(parsed["response_type"]), bytes.fromhex(parsed["response_payload"])


def run_local_raw_wire_oracle(gate: Path, message_type: int, payload: bytes) -> tuple[int, bytes]:
    wire = wire_encode(message_type, payload)
    output = subprocess.check_output([str(gate), "--trezor-wire-oracle", wire.hex()], text=True)
    parsed = parse_vectors(output)
    return int(parsed["response_type"]), bytes.fromhex(parsed["response_payload"])


def run_local_wire_script(
    gate: Path,
    script: list[tuple[int, messages.MessageType]],
    *,
    btc_compact_signatures: list[bytes] | None = None,
) -> list[tuple[int, bytes]]:
    wires = [wire_encode(message_type, message_payload(message)).hex() for message_type, message in script]
    env = None
    if btc_compact_signatures is not None:
        env = os.environ.copy()
        env["TREZOR_TEST_BTC_COMPACT_SIGNATURES"] = ",".join(sig.hex() for sig in btc_compact_signatures)
    output = subprocess.check_output([str(gate), "--trezor-wire-script", *wires], text=True, env=env)
    parsed = parse_vectors(output)
    responses: list[tuple[int, bytes]] = []
    for index in range(len(script)):
        responses.append((int(parsed[f"response_type_{index}"]), bytes.fromhex(parsed[f"response_payload_{index}"])))
    return responses


def run_local_raw_wire_script(
    gate: Path,
    script: list[tuple[int, bytes]],
    *,
    eth_compact_signature: bytes | None = None,
) -> list[tuple[int, bytes]]:
    wires = [wire_encode(message_type, payload).hex() for message_type, payload in script]
    env = None
    if eth_compact_signature is not None:
        if len(eth_compact_signature) != 65:
            raise AssertionError("ETH compact signature must be recid/header + r + s")
        env = os.environ.copy()
        env["TREZOR_TEST_ETH_COMPACT_SIGNATURE"] = eth_compact_signature.hex()
    output = subprocess.check_output([str(gate), "--trezor-wire-script", *wires], text=True, env=env)
    parsed = parse_vectors(output)
    responses: list[tuple[int, bytes]] = []
    for index in range(len(script)):
        responses.append((int(parsed[f"response_type_{index}"]), bytes.fromhex(parsed[f"response_payload_{index}"])))
    return responses


def c_gate_fake_sha256(data: bytes) -> bytes:
    """Mirror the host-gate hash shim; production firmware uses libwally."""
    output = bytearray(32)
    for index, value in enumerate(data):
        output[index % len(output)] ^= value
        slot = (index * 7 + 3) % len(output)
        output[slot] = (output[slot] + value + index) & 0xFF
    data_len = len(data)
    output[0] ^= data_len & 0xFF
    output[1] ^= (data_len >> 8) & 0xFF
    output[2] ^= (data_len >> 16) & 0xFF
    output[3] ^= (data_len >> 24) & 0xFF
    return bytes(output)


def c_gate_fake_hash160(data: bytes) -> bytes:
    """Mirror the host-gate hash160 shim; used only to exercise C binding flow."""
    output = bytearray(20)
    for index, value in enumerate(data):
        output[index % len(output)] ^= value
        slot = (index * 5 + 1) % len(output)
        output[slot] = (output[slot] + value + index) & 0xFF
    data_len = len(data)
    output[0] ^= data_len & 0xFF
    output[1] ^= (data_len >> 8) & 0xFF
    return bytes(output)


def c_gate_fake_multisig_script_pubkey(script_type: messages.InputScriptType, redeem_script: bytes) -> bytes:
    if script_type == messages.InputScriptType.SPENDMULTISIG:
        return b"\xa9\x14" + c_gate_fake_hash160(redeem_script) + b"\x87"
    if script_type == messages.InputScriptType.SPENDWITNESS:
        return b"\x00\x20" + c_gate_fake_sha256(redeem_script)
    if script_type == messages.InputScriptType.SPENDP2SHWITNESS:
        witness_program = b"\x00\x20" + c_gate_fake_sha256(redeem_script)
        return b"\xa9\x14" + c_gate_fake_hash160(witness_program) + b"\x87"
    raise AssertionError(f"unsupported multisig script type for host gate: {script_type}")


def onekey_multisig_fingerprint_material(multisig: messages.MultisigRedeemScriptType) -> bytes:
    if multisig.nodes:
        nodes = list(multisig.nodes)
    else:
        nodes = [hd.node for hd in multisig.pubkeys]
    if not nodes or not multisig.m or multisig.m > len(nodes):
        raise AssertionError("invalid multisig fingerprint fixture")

    def u32(value: int) -> bytes:
        return int(value).to_bytes(4, "little")

    material = bytearray()
    material += u32(multisig.m)
    material += u32(len(nodes))
    for node in sorted(nodes, key=lambda item: bytes(item.public_key)):
        material += u32(node.depth)
        material += u32(node.fingerprint)
        material += u32(node.child_num)
        material += bytes(node.chain_code)
        material += bytes(node.public_key)
    return bytes(material)


def c_gate_fake_multisig_fingerprint(multisig: messages.MultisigRedeemScriptType) -> bytes:
    return c_gate_fake_sha256(onekey_multisig_fingerprint_material(multisig))


def sha256_multisig_fingerprint(multisig: messages.MultisigRedeemScriptType) -> bytes:
    return hashlib.sha256(onekey_multisig_fingerprint_material(multisig)).digest()


def hdnode_type_from_xpub(xpub: str) -> messages.HDNodeType:
    raw = base58.b58decode_check(xpub)
    if len(raw) != 78:
        raise AssertionError(f"unexpected xpub payload length: {len(raw)}")
    return messages.HDNodeType(
        depth=raw[4],
        fingerprint=int.from_bytes(raw[5:9], "big"),
        child_num=int.from_bytes(raw[9:13], "big"),
        chain_code=raw[13:45],
        public_key=raw[45:78],
    )


def run_multisig_normalizer_gate(
    gate: Path,
    multisig: messages.MultisigRedeemScriptType,
    script_type: messages.InputScriptType,
    expected_redeem_script: bytes,
) -> dict[str, str]:
    expected_script_pubkey = c_gate_fake_multisig_script_pubkey(script_type, expected_redeem_script)
    output = subprocess.check_output(
        [
            str(gate),
            "--trezor-multisig-normalizer",
            message_payload(multisig).hex(),
            str(int(script_type)),
            expected_script_pubkey.hex(),
        ],
        text=True,
    )
    parsed = parse_vectors(output)
    if parsed.get("decoded") != "1" or parsed.get("normalized") != "1" or parsed.get("matched") != "1":
        raise AssertionError(f"multisig normalizer failed: {parsed}")
    if bytes.fromhex(parsed["redeem_script"]) != expected_redeem_script:
        raise AssertionError(
            f"multisig redeem script mismatch: actual={parsed['redeem_script']} expected={expected_redeem_script.hex()}"
        )
    if bytes.fromhex(parsed["fingerprint"]) != c_gate_fake_multisig_fingerprint(multisig):
        raise AssertionError(f"multisig fingerprint mismatch: {parsed['fingerprint']}")
    if parsed.get("descriptor_ok") != "1":
        raise AssertionError(f"multisig descriptor normalization failed: {parsed}")
    if parsed.get("descriptor_fingerprint") != parsed.get("fingerprint"):
        raise AssertionError(f"multisig descriptor fingerprint mismatch: {parsed}")
    if parsed.get("descriptor_threshold") != str(multisig.m):
        raise AssertionError(f"multisig descriptor threshold mismatch: {parsed}")
    signer_count = len(multisig.pubkeys) if multisig.pubkeys else len(multisig.nodes)
    if parsed.get("descriptor_num_pubkeys") != str(signer_count):
        raise AssertionError(f"multisig descriptor signer count mismatch: {parsed}")
    if parsed.get("descriptor_sorted") != ("1" if multisig.pubkeys_order == messages.MultisigPubkeysOrder.LEXICOGRAPHIC else "0"):
        raise AssertionError(f"multisig descriptor sorted flag mismatch: {parsed}")
    if parsed.get("descriptor_has_shared_path") != ("1" if multisig.address_n else "0"):
        raise AssertionError(f"multisig descriptor shared path flag mismatch: {parsed}")
    if parsed.get("descriptor_has_local_pubkey") != "1":
        raise AssertionError(f"multisig descriptor lost local signer membership: {parsed}")
    if parsed.get("descriptor_redeem_script_len") != str(len(expected_redeem_script)):
        raise AssertionError(f"multisig descriptor redeem script length mismatch: {parsed}")
    if parsed.get("descriptor_script_pubkey_len") != str(len(expected_script_pubkey)):
        raise AssertionError(f"multisig descriptor scriptPubKey length mismatch: {parsed}")
    return parsed


def assert_multisig_normalizer_rejects(
    gate: Path,
    multisig: messages.MultisigRedeemScriptType,
    script_type: messages.InputScriptType,
    expected_redeem_script: bytes,
    case_name: str,
) -> None:
    expected_script_pubkey = c_gate_fake_multisig_script_pubkey(script_type, expected_redeem_script)
    result = subprocess.run(
        [
            str(gate),
            "--trezor-multisig-normalizer",
            message_payload(multisig).hex(),
            str(int(script_type)),
            expected_script_pubkey.hex(),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode == 0:
        raise AssertionError(f"{case_name} unexpectedly passed")


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
        output_addresses: list[str | None] | None = None,
        output_paths: list[list[int] | None] | None = None,
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
        self.output_addresses = output_addresses or [btc_tx_output_address()]
        self.output_paths = output_paths or [None]
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
            expected_address = self.output_addresses[previous.request_index]
            expected_path = self.output_paths[previous.request_index]
            actual_output = message.tx.outputs[0]
            if expected_address is None:
                if actual_output.address or list(actual_output.address_n or []) != expected_path:
                    raise AssertionError(f"unexpected BTC change output: {actual_output}")
            elif actual_output.address != expected_address or actual_output.address_n:
                raise AssertionError(f"unexpected BTC external output: {actual_output}")
            if (
                message.tx.outputs[0].amount != self.output_amounts[previous.request_index]
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


def btc_tx_output_address_mainnet() -> str:
    return "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"


def btc_tx_p2pkh_address_testnet() -> str:
    return base58.b58encode_check(b"\x6f" + hash160(BTC_TEST_COMPRESSED_PUBKEY)).decode()


def btc_tx_p2pkh_address_mainnet() -> str:
    return base58.b58encode_check(b"\x00" + hash160(BTC_TEST_COMPRESSED_PUBKEY)).decode()


def btc_tx_p2sh_p2wpkh_address_testnet() -> str:
    return base58.b58encode_check(b"\xc4" + hash160(btc_p2wpkh_script_pubkey())).decode()


def btc_embit_public_key():
    from embit import ec

    return ec.PublicKey.parse(BTC_TEST_COMPRESSED_PUBKEY)


def btc_p2pkh_script_pubkey() -> bytes:
    from embit import script

    return script.p2pkh(btc_embit_public_key()).data


def btc_p2wpkh_script_pubkey() -> bytes:
    from embit import script

    return script.p2wpkh(btc_embit_public_key()).data


def btc_p2sh_p2wpkh_script_pubkey() -> bytes:
    from embit import script

    return script.p2sh(script.p2wpkh(btc_embit_public_key())).data


def btc_p2pkh_script_code() -> bytes:
    return btc_p2pkh_script_pubkey()


def btc_p2sh_p2wpkh_scriptsig() -> bytes:
    return bytes([len(btc_p2wpkh_script_pubkey())]) + btc_p2wpkh_script_pubkey()


def btc_sign_digest_compact(digest: bytes) -> bytes:
    signature = SigningKey.from_string(PRIVATE_KEY_ONE, curve=SECP256k1).sign_digest_deterministic(
        digest, hashfunc=hashlib.sha256, sigencode=ecdsa_util.sigencode_string_canonize
    )
    if len(signature) != 64:
        raise AssertionError(f"unexpected compact BTC signature length: {len(signature)}")
    return b"\x1f" + signature


def btc_verify_der_signature(digest: bytes, der_signature: bytes) -> None:
    verifying_key = VerifyingKey.from_string(
        keys.PrivateKey(PRIVATE_KEY_ONE).public_key.to_bytes(), curve=SECP256k1
    )
    if not verifying_key.verify_digest(der_signature, digest, sigdecode=ecdsa_util.sigdecode_der):
        raise AssertionError("BTC ECDSA signature verification failed")


def btc_input_path(index: int = 0, *, account: int = 0, change: int = 0, mainnet: bool = False) -> list[int]:
    coin = 0 if mainnet else 1
    return [0x80000054, 0x80000000 + coin, 0x80000000 + account, change, index]


def btc_p2sh_input_path(index: int = 0, *, account: int = 0, change: int = 0, mainnet: bool = False) -> list[int]:
    coin = 0 if mainnet else 1
    return [0x80000031, 0x80000000 + coin, 0x80000000 + account, change, index]


def btc_p2pkh_input_path(index: int = 0, *, account: int = 0, change: int = 0, mainnet: bool = False) -> list[int]:
    coin = 0 if mainnet else 1
    return [0x8000002C, 0x80000000 + coin, 0x80000000 + account, change, index]


def btc_tx_input(
    *,
    path: list[int] | None = None,
    prev_hash: bytes | None = None,
    prev_index: int = 0,
    amount: int = 100_000,
    script_type: messages.InputScriptType = messages.InputScriptType.SPENDWITNESS,
    multisig: messages.MultisigRedeemScriptType | None = None,
) -> messages.TxInputType:
    return messages.TxInputType(
        address_n=path or btc_input_path(),
        prev_hash=prev_hash or btc_tx_prev_hash(),
        prev_index=prev_index,
        script_type=script_type,
        amount=amount,
        sequence=0xFFFFFFFF,
        multisig=multisig,
    )


def btc_tx_output_external(amount: int = 90_000, address: str | None = None) -> messages.TxOutputType:
    return messages.TxOutputType(
        address=address or btc_tx_output_address(),
        amount=amount,
        script_type=messages.OutputScriptType.PAYTOADDRESS,
    )


def btc_tx_output_change(
    amount: int = 5_000,
    *,
    path: list[int] | None = None,
    script_type: messages.OutputScriptType = messages.OutputScriptType.PAYTOADDRESS,
    multisig: messages.MultisigRedeemScriptType | None = None,
) -> messages.TxOutputType:
    return messages.TxOutputType(
        address_n=path or btc_input_path(change=1),
        amount=amount,
        script_type=script_type,
        multisig=multisig,
    )


def btc_tx_ack_meta(inputs_count: int, outputs_count: int, *, version: int = 2, lock_time: int = 0) -> messages.TxAck:
    return messages.TxAck(
        tx=messages.TransactionType(
            version=version,
            inputs_cnt=inputs_count,
            outputs_cnt=outputs_count,
            lock_time=lock_time,
        )
    )


def btc_tx_ack_input(tx_input: messages.TxInputType) -> messages.TxAck:
    return messages.TxAck(tx=messages.TransactionType(inputs=[tx_input]))


def btc_tx_ack_output(tx_output: messages.TxOutputType) -> messages.TxAck:
    return messages.TxAck(tx=messages.TransactionType(outputs=[tx_output]))


def btc_tx_ack_prev_input(
    *, prev_hash: bytes = bytes.fromhex("aa" * 32), prev_index: int = 7, script_sig: bytes = b"\x51"
) -> messages.TxAck:
    return messages.TxAck(
        tx=messages.TransactionType(
            inputs=[
                messages.TxInputType(
                    prev_hash=prev_hash,
                    prev_index=prev_index,
                    script_sig=script_sig,
                    sequence=0xFFFFFFFE,
                )
            ]
        )
    )


def btc_tx_ack_prev_output(amount: int = 100_000, script_pubkey: bytes | None = None) -> messages.TxAck:
    return messages.TxAck(
        tx=messages.TransactionType(
            bin_outputs=[
                messages.TxOutputBinType(
                    amount=amount,
                    script_pubkey=script_pubkey or btc_p2wpkh_script_pubkey(),
                )
            ]
        )
    )


def btc_prev_txid_for_single_input_two_outputs(
    *,
    prev_hash: bytes = bytes.fromhex("aa" * 32),
    prev_index: int = 7,
    script_sig: bytes = b"\x51",
    prevout0_script_pubkey: bytes | None = None,
) -> bytes:
    prevout0_script = prevout0_script_pubkey or btc_p2wpkh_script_pubkey()
    p2wpkh_script = btc_p2wpkh_script_pubkey()
    raw = (
        bytes.fromhex("02000000")
        + b"\x01"
        + prev_hash
        + prev_index.to_bytes(4, "little")
        + bytes([len(script_sig)])
        + script_sig
        + (0xFFFFFFFE).to_bytes(4, "little")
        + b"\x02"
        + (100_000).to_bytes(8, "little")
        + bytes([len(prevout0_script)])
        + prevout0_script
        + (1_000).to_bytes(8, "little")
        + bytes([len(p2wpkh_script)])
        + p2wpkh_script
        + bytes.fromhex("00000000")
    )
    return local_gate_double_sha256(raw)[::-1]


def local_gate_sha256(data: bytes) -> bytes:
    """Mirror the lightweight wally_sha256 shim used by eth_tron_address_gate."""
    out = bytearray(32)
    for index, value in enumerate(data):
        out[index % len(out)] ^= value
        out[(index * 7 + 3) % len(out)] = (out[(index * 7 + 3) % len(out)] + value + index) & 0xFF
    data_len = len(data)
    out[0] ^= data_len & 0xFF
    out[1] ^= (data_len >> 8) & 0xFF
    out[2] ^= (data_len >> 16) & 0xFF
    out[3] ^= (data_len >> 24) & 0xFF
    return bytes(out)


def local_gate_double_sha256(data: bytes) -> bytes:
    return local_gate_sha256(local_gate_sha256(data))


def check_trezorlib_btc_signtx_host_flow_oracle() -> None:
    from trezorlib import btc

    input_path = btc_input_path()
    tx_input = btc_tx_input(path=input_path)
    tx_output = btc_tx_output_external()

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

    input_path_1 = btc_input_path(1)
    tx_input_1 = btc_tx_input(path=input_path_1, prev_hash=bytes.fromhex("22" * 32), prev_index=1, amount=40_000)
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

    change_output = btc_tx_output_change(amount=45_000)
    multi_change_signature_0 = bytes.fromhex("30" + "77" * 70)
    multi_change_signature_1 = bytes.fromhex("30" + "88" * 70)
    multi_change_serialized_tx = bytes.fromhex("0200000000010202")
    multi_change_client = ScriptedBtcSignTxClient(
        [
            BtcSignTxHostStep(messages.RequestType.TXMETA, "meta"),
            BtcSignTxHostStep(messages.RequestType.TXINPUT, "input", request_index=0),
            BtcSignTxHostStep(messages.RequestType.TXINPUT, "input", request_index=1),
            BtcSignTxHostStep(messages.RequestType.TXOUTPUT, "output", request_index=0),
            BtcSignTxHostStep(messages.RequestType.TXOUTPUT, "output", request_index=1),
            BtcSignTxHostStep(
                messages.RequestType.TXMETA,
                "meta",
                signature_index=0,
                signature=multi_change_signature_0,
            ),
        ],
        multi_change_signature_1,
        multi_change_serialized_tx,
        final_signature_index=1,
        inputs_count=2,
        outputs_count=2,
        input_prev_hashes=[btc_tx_prev_hash(), bytes.fromhex("22" * 32)],
        input_amounts=[100_000, 40_000],
        output_amounts=[90_000, 45_000],
        output_addresses=[btc_tx_output_address(), None],
        output_paths=[None, btc_input_path(change=1)],
    )

    signatures, signed_tx = btc.sign_tx(
        multi_change_client,
        "Testnet",
        [tx_input, tx_input_1],
        [tx_output, change_output],
        version=2,
        lock_time=0,
    )
    if signatures != [multi_change_signature_0, multi_change_signature_1]:
        raise AssertionError(f"trezorlib multi-output BTC signatures mismatch: {signatures}")
    if signed_tx != multi_change_serialized_tx:
        raise AssertionError(f"trezorlib multi-output BTC serialized tx mismatch: {signed_tx.hex()}")

    call_types = [type(call).__name__ for call in multi_change_client.calls]
    if call_types != ["SignTx", "TxAck", "TxAck", "TxAck", "TxAck", "TxAck", "TxAck"]:
        raise AssertionError(f"unexpected trezorlib multi-output BTC host call sequence: {call_types}")
    if not multi_change_client.closed:
        raise AssertionError("trezorlib multi-output BTC SignTx session did not close")


def assert_btc_tx_request(
    response: tuple[int, bytes],
    request_type: messages.RequestType,
    *,
    request_index: int | None = None,
    tx_hash: bytes | None = None,
    signature_index: int | None = None,
    expect_serialized_tx: bool = False,
) -> messages.TxRequest:
    response_type, payload = response
    if response_type != messages.MessageType.TxRequest:
        raise AssertionError(f"BTC response must be TxRequest, got {response_type}")
    tx_request = protobuf.load_message(io.BytesIO(payload), messages.TxRequest)
    if tx_request.request_type != request_type:
        raise AssertionError(f"BTC request type mismatch: actual={tx_request.request_type} expected={request_type}")
    if request_index is not None:
        if tx_request.details is None or tx_request.details.request_index != request_index:
            raise AssertionError(f"BTC request index mismatch: {tx_request}")
    if tx_hash is not None:
        if tx_request.details is None or tx_request.details.tx_hash != tx_hash:
            raise AssertionError(f"BTC request tx_hash mismatch: {tx_request}")
    if signature_index is not None:
        if tx_request.serialized is None or tx_request.serialized.signature_index != signature_index:
            raise AssertionError(f"BTC signature index mismatch: {tx_request}")
        if len(tx_request.serialized.signature or b"") < 64:
            raise AssertionError("BTC signed response missing DER signature")
    if expect_serialized_tx:
        if tx_request.serialized is None or len(tx_request.serialized.serialized_tx or b"") == 0:
            raise AssertionError("BTC final signed response missing serialized tx")
    return tx_request


def assert_btc_failure(
    response: tuple[int, bytes],
    expected_code: messages.FailureType,
    case_name: str,
    expected_message_contains: str | None = None,
) -> None:
    response_type, payload = response
    if response_type != messages.MessageType.Failure:
        raise AssertionError(f"{case_name} must fail, got response type {response_type}")
    failure = protobuf.load_message(io.BytesIO(payload), messages.Failure)
    if failure.code != expected_code:
        raise AssertionError(f"{case_name} failure code mismatch: actual={failure.code} expected={expected_code}")
    if expected_message_contains is not None and expected_message_contains not in failure.message:
        raise AssertionError(f"{case_name} failure message mismatch: {failure.message}")


def btc_verified_multisig_signing_calls(
    multisig: messages.MultisigRedeemScriptType,
    redeem_script: bytes,
    script_type: messages.InputScriptType,
    *,
    include_mismatched_change: bool = False,
) -> list[tuple[int, object]]:
    prevout_script = c_gate_fake_multisig_script_pubkey(script_type, redeem_script)
    prev_hash = btc_prev_txid_for_single_input_two_outputs(prevout0_script_pubkey=prevout_script)
    if script_type == messages.InputScriptType.SPENDMULTISIG:
        path = [0x8000002D, 0, 0, 0]
    elif script_type == messages.InputScriptType.SPENDP2SHWITNESS:
        path = [0x80000030, 0x80000001, 0x80000000, 0x80000001, 0, 0]
    else:
        path = [0x80000030, 0x80000001, 0x80000000, 0x80000002, 0, 0]
    outputs_count = 2 if include_mismatched_change else 1
    calls: list[tuple[int, object]] = [
        (
            messages.MessageType.SignTx,
            messages.SignTx(coin_name="Testnet", inputs_count=1, outputs_count=outputs_count, version=2, lock_time=0),
        ),
        (messages.MessageType.TxAck, btc_tx_ack_meta(1, outputs_count)),
        (
            messages.MessageType.TxAck,
            btc_tx_ack_input(
                btc_tx_input(
                    path=path,
                    prev_hash=prev_hash,
                    script_type=script_type,
                    multisig=multisig,
                )
            ),
        ),
        (messages.MessageType.TxAck, btc_tx_ack_output(btc_tx_output_external(amount=90_000))),
    ]
    if include_mismatched_change:
        calls.append(
            (
                messages.MessageType.TxAck,
                btc_tx_ack_output(
                    btc_tx_output_change(
                        amount=5_000,
                        path=path,
                        script_type=messages.OutputScriptType.PAYTOMULTISIG,
                        multisig=multisig,
                    )
                ),
            )
        )
    calls.extend(
        [
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 2)),
            (messages.MessageType.TxAck, btc_tx_ack_prev_input()),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(100_000, prevout_script)),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(1_000, btc_p2wpkh_script_pubkey())),
        ]
    )
    return calls


def assert_btc_verified_multisig_signs(
    gate: Path,
    multisig: messages.MultisigRedeemScriptType,
    redeem_script: bytes,
    script_type: messages.InputScriptType,
) -> None:
    prevout_script = c_gate_fake_multisig_script_pubkey(script_type, redeem_script)
    prev_hash = btc_prev_txid_for_single_input_two_outputs(prevout0_script_pubkey=prevout_script)
    responses = run_local_wire_script(gate, btc_verified_multisig_signing_calls(multisig, redeem_script, script_type))
    assert_btc_tx_request(responses[0], messages.RequestType.TXMETA)
    assert_btc_tx_request(responses[1], messages.RequestType.TXINPUT, request_index=0)
    assert_btc_tx_request(responses[2], messages.RequestType.TXOUTPUT, request_index=0)
    assert_btc_tx_request(responses[3], messages.RequestType.TXMETA, tx_hash=prev_hash)
    assert_btc_tx_request(responses[4], messages.RequestType.TXORIGINPUT, request_index=0, tx_hash=prev_hash)
    assert_btc_tx_request(responses[5], messages.RequestType.TXORIGOUTPUT, request_index=0, tx_hash=prev_hash)
    assert_btc_tx_request(responses[6], messages.RequestType.TXORIGOUTPUT, request_index=1, tx_hash=prev_hash)
    tx_request = assert_btc_tx_request(
        responses[-1], messages.RequestType.TXFINISHED, signature_index=0, expect_serialized_tx=False
    )
    signature = tx_request.serialized.signature if tx_request.serialized else None
    if not signature or signature[0] != 0x30:
        raise AssertionError("BTC multisig partial signature is not DER encoded")


def assert_btc_verified_multisig_rejects_mismatched_change(
    gate: Path,
    multisig: messages.MultisigRedeemScriptType,
    redeem_script: bytes,
    script_type: messages.InputScriptType,
) -> None:
    responses = run_local_wire_script(
        gate,
        btc_verified_multisig_signing_calls(
            multisig, redeem_script, script_type, include_mismatched_change=True
        ),
    )
    assert_btc_failure(
        responses[-1],
        messages.FailureType.DataError,
        "BTC verified multisig mismatched change",
    )


def assert_btc_multisig_prevout_mismatch_rejects(
    gate: Path,
    multisig: messages.MultisigRedeemScriptType,
    redeem_script: bytes,
    script_type: messages.InputScriptType,
) -> None:
    correct_prevout_script = c_gate_fake_multisig_script_pubkey(script_type, redeem_script)
    prev_hash = btc_prev_txid_for_single_input_two_outputs(prevout0_script_pubkey=correct_prevout_script)
    responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Testnet", inputs_count=1, outputs_count=1, version=2, lock_time=0),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 1)),
            (
                messages.MessageType.TxAck,
                btc_tx_ack_input(
                    btc_tx_input(
                        path=[0x80000030, 0x80000001, 0x80000000, 0x80000002, 0, 0],
                        prev_hash=prev_hash,
                        script_type=script_type,
                        multisig=multisig,
                    )
                ),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_output(btc_tx_output_external(amount=90_000))),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 2)),
            (messages.MessageType.TxAck, btc_tx_ack_prev_input()),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(100_000, btc_p2wpkh_script_pubkey())),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(1_000, btc_p2wpkh_script_pubkey())),
        ],
    )
    assert_btc_tx_request(responses[3], messages.RequestType.TXMETA, tx_hash=prev_hash)
    assert_btc_tx_request(responses[4], messages.RequestType.TXORIGINPUT, request_index=0, tx_hash=prev_hash)
    assert_btc_tx_request(responses[5], messages.RequestType.TXORIGOUTPUT, request_index=0, tx_hash=prev_hash)
    assert_btc_tx_request(responses[6], messages.RequestType.TXORIGOUTPUT, request_index=1, tx_hash=prev_hash)
    assert_btc_failure(
        responses[-1],
        messages.FailureType.DataError,
        "BTC multisig prevout script mismatch",
    )


def check_embit_btc_signed_tx_oracle(
    raw_tx: bytes,
    *,
    version: int,
    locktime: int,
    inputs: list[tuple[bytes, int]],
    outputs: list[tuple[int, bytes]],
    witness_pubkeys: list[bytes],
) -> None:
    """Verify BTC signed tx semantics with an independent community library."""
    from embit.transaction import Transaction

    tx = Transaction.parse(raw_tx)
    if tx.serialize() != raw_tx:
        raise AssertionError("BTC signed tx oracle failed round-trip serialization")
    if tx.version != version or tx.locktime != locktime:
        raise AssertionError(f"BTC signed tx version/locktime mismatch: {tx.version}/{tx.locktime}")
    if len(tx.vin) != len(inputs) or len(tx.vout) != len(outputs):
        raise AssertionError(f"BTC signed tx input/output count mismatch: {len(tx.vin)}/{len(tx.vout)}")

    for index, (expected_txid, expected_vout) in enumerate(inputs):
        txin = tx.vin[index]
        if txin.txid != expected_txid or txin.vout != expected_vout:
            raise AssertionError(f"BTC input {index} outpoint mismatch: {txin.txid.hex()}:{txin.vout}")
        if txin.script_sig.data != b"":
            raise AssertionError(f"BTC input {index} scriptSig must be empty for native segwit")
        if txin.sequence != 0xFFFFFFFF:
            raise AssertionError(f"BTC input {index} sequence mismatch: {txin.sequence}")
        if len(txin.witness.items) != 2:
            raise AssertionError(f"BTC input {index} witness item count mismatch: {len(txin.witness.items)}")
        signature, pubkey = txin.witness.items
        if len(signature) < 9 or signature[-1] != 1:
            raise AssertionError(f"BTC input {index} witness signature missing SIGHASH_ALL")
        if pubkey != witness_pubkeys[index]:
            raise AssertionError(f"BTC input {index} witness pubkey mismatch: {pubkey.hex()}")

    for index, (expected_amount, expected_script_pubkey) in enumerate(outputs):
        txout = tx.vout[index]
        if txout.value != expected_amount:
            raise AssertionError(f"BTC output {index} amount mismatch: {txout.value}")
        if txout.script_pubkey.data != expected_script_pubkey:
            raise AssertionError(f"BTC output {index} scriptPubKey mismatch: {txout.script_pubkey.data.hex()}")


def check_embit_btc_p2sh_p2wpkh_signed_tx_oracle(
    raw_tx: bytes, *, prev_txid: bytes, amount: int, expected_output_script: bytes | None = None
) -> None:
    from embit import script
    from embit.transaction import Transaction

    tx = Transaction.parse(raw_tx)
    if tx.serialize() != raw_tx:
        raise AssertionError("P2SH-P2WPKH signed tx oracle failed round-trip serialization")
    if tx.version != 2 or tx.locktime != 0:
        raise AssertionError(f"P2SH-P2WPKH signed tx version/locktime mismatch: {tx.version}/{tx.locktime}")
    if len(tx.vin) != 1 or len(tx.vout) != 1:
        raise AssertionError(f"P2SH-P2WPKH signed tx input/output count mismatch: {len(tx.vin)}/{len(tx.vout)}")

    txin = tx.vin[0]
    if txin.txid != prev_txid or txin.vout != 0:
        raise AssertionError(f"P2SH-P2WPKH outpoint mismatch: {txin.txid.hex()}:{txin.vout}")
    if txin.script_sig.data != btc_p2sh_p2wpkh_scriptsig():
        raise AssertionError(f"P2SH-P2WPKH scriptSig mismatch: {txin.script_sig.data.hex()}")
    if txin.sequence != 0xFFFFFFFF:
        raise AssertionError(f"P2SH-P2WPKH sequence mismatch: {txin.sequence}")
    if len(txin.witness.items) != 2:
        raise AssertionError(f"P2SH-P2WPKH witness item count mismatch: {len(txin.witness.items)}")
    signature_with_hash, pubkey = txin.witness.items
    if pubkey != BTC_TEST_COMPRESSED_PUBKEY:
        raise AssertionError(f"P2SH-P2WPKH witness pubkey mismatch: {pubkey.hex()}")
    if not signature_with_hash or signature_with_hash[-1] != 1:
        raise AssertionError("P2SH-P2WPKH signature is missing SIGHASH_ALL")

    digest = tx.sighash_segwit(0, script.Script(btc_p2pkh_script_code()), amount, sighash=1)
    btc_verify_der_signature(digest, signature_with_hash[:-1])

    txout = tx.vout[0]
    if txout.value != 90_000:
        raise AssertionError(f"P2SH-P2WPKH output amount mismatch: {txout.value}")
    if txout.script_pubkey.data != (expected_output_script or btc_p2wpkh_script_pubkey()):
        raise AssertionError(f"P2SH-P2WPKH output script mismatch: {txout.script_pubkey.data.hex()}")


def check_embit_btc_p2pkh_signed_tx_oracle(
    raw_tx: bytes, *, prev_txid: bytes, expected_output_script: bytes | None = None
) -> None:
    from embit import script
    from embit.transaction import Transaction

    tx = Transaction.parse(raw_tx)
    if tx.serialize() != raw_tx:
        raise AssertionError("P2PKH signed tx oracle failed round-trip serialization")
    if tx.version != 2 or tx.locktime != 0:
        raise AssertionError(f"P2PKH signed tx version/locktime mismatch: {tx.version}/{tx.locktime}")
    if len(tx.vin) != 1 or len(tx.vout) != 1:
        raise AssertionError(f"P2PKH signed tx input/output count mismatch: {len(tx.vin)}/{len(tx.vout)}")

    txin = tx.vin[0]
    if txin.txid != prev_txid or txin.vout != 0:
        raise AssertionError(f"P2PKH outpoint mismatch: {txin.txid.hex()}:{txin.vout}")
    if txin.sequence != 0xFFFFFFFF:
        raise AssertionError(f"P2PKH sequence mismatch: {txin.sequence}")
    if len(txin.witness.items) != 0:
        raise AssertionError(f"P2PKH transaction must not carry witness data: {len(txin.witness.items)}")

    script_sig = txin.script_sig.data
    if len(script_sig) < 2:
        raise AssertionError("P2PKH scriptSig too short")
    sig_len = script_sig[0]
    if sig_len == 0 or 1 + sig_len >= len(script_sig):
        raise AssertionError(f"P2PKH scriptSig invalid signature push: {script_sig.hex()}")
    signature_with_hash = script_sig[1 : 1 + sig_len]
    pubkey_len_pos = 1 + sig_len
    pubkey_len = script_sig[pubkey_len_pos]
    pubkey = script_sig[pubkey_len_pos + 1 :]
    if pubkey_len != len(pubkey) or pubkey != BTC_TEST_COMPRESSED_PUBKEY:
        raise AssertionError(f"P2PKH scriptSig pubkey mismatch: {pubkey.hex()}")
    if not signature_with_hash or signature_with_hash[-1] != 1:
        raise AssertionError("P2PKH signature is missing SIGHASH_ALL")

    digest = tx.sighash_legacy(0, script.Script(btc_p2pkh_script_pubkey()), sighash=1)
    btc_verify_der_signature(digest, signature_with_hash[:-1])

    txout = tx.vout[0]
    if txout.value != 90_000:
        raise AssertionError(f"P2PKH output amount mismatch: {txout.value}")
    if txout.script_pubkey.data != (expected_output_script or btc_p2wpkh_script_pubkey()):
        raise AssertionError(f"P2PKH output script mismatch: {txout.script_pubkey.data.hex()}")


def check_embit_psbt_oracle() -> bytes:
    """Build and parse a minimal unsigned PSBT with independent community code."""
    from embit import psbt, script
    from embit.transaction import Transaction, TransactionInput, TransactionOutput

    prev_hash = bytes.fromhex("44" * 32)
    input_script = script.Script(btc_p2wpkh_script_pubkey())
    output_script = script.Script(btc_p2pkh_script_pubkey())
    unsigned = Transaction(
        version=2,
        vin=[TransactionInput(prev_hash, 3)],
        vout=[TransactionOutput(90_000, output_script)],
        locktime=0,
    )
    packet = psbt.PSBT(unsigned)
    packet.inputs[0].witness_utxo = TransactionOutput(100_000, input_script)

    raw = packet.serialize()
    parsed = psbt.PSBT.parse(raw)
    if parsed.serialize() != raw:
        raise AssertionError("PSBT oracle failed round-trip serialization")
    if parsed.tx.version != 2 or parsed.tx.locktime != 0:
        raise AssertionError("PSBT oracle unsigned tx version/locktime mismatch")
    if len(parsed.tx.vin) != 1 or len(parsed.tx.vout) != 1:
        raise AssertionError("PSBT oracle input/output count mismatch")
    if parsed.tx.vin[0].txid != prev_hash or parsed.tx.vin[0].vout != 3:
        raise AssertionError("PSBT oracle input outpoint mismatch")
    if parsed.tx.vout[0].value != 90_000 or parsed.tx.vout[0].script_pubkey.data != btc_p2pkh_script_pubkey():
        raise AssertionError("PSBT oracle output mismatch")
    if parsed.inputs[0].witness_utxo is None:
        raise AssertionError("PSBT oracle missing witness_utxo")
    if parsed.inputs[0].witness_utxo.value != 100_000:
        raise AssertionError("PSBT oracle witness_utxo amount mismatch")
    if parsed.inputs[0].witness_utxo.script_pubkey.data != btc_p2wpkh_script_pubkey():
        raise AssertionError("PSBT oracle witness_utxo script mismatch")
    return raw


def trezor_multisig_fixture() -> tuple[
    list[messages.HDNodeType],
    list[object],
    bytes,
    bytes,
]:
    from embit import bip32, ec, script

    local_hd_node = messages.HDNodeType(
        depth=5,
        fingerprint=0x01020304,
        child_num=0,
        chain_code=b"\x44" * 32,
        public_key=BTC_TEST_COMPRESSED_PUBKEY,
    )
    local_pubkey = ec.PublicKey.parse(BTC_TEST_COMPRESSED_PUBKEY)
    seeds = [bytes([0x22]) * 32, bytes([0x33]) * 32]
    account_nodes = [bip32.HDKey.from_seed(seed).derive("m/48h/1h/0h/2h").to_public() for seed in seeds]
    child_nodes = [node.child(0).child(0) for node in account_nodes]
    child_pubkeys = [local_pubkey] + [node.get_public_key() for node in child_nodes]
    child_hd_nodes = [local_hd_node] + [hdnode_type_from_xpub(str(node)) for node in child_nodes]

    preserved_redeem = script.multisig(2, child_pubkeys).data
    sorted_redeem = script.multisig(2, sorted(child_pubkeys, key=lambda pubkey: pubkey.sec())).data
    return child_hd_nodes, child_pubkeys, preserved_redeem, sorted_redeem


def check_trezor_multisig_normalizer_oracle(gate: Path) -> None:
    """Validate Trezor multisig protobuf normalization against embit scripts."""
    from embit import script

    child_hd_nodes, child_pubkeys, preserved_redeem, sorted_redeem = trezor_multisig_fixture()

    old_style = messages.MultisigRedeemScriptType(
        pubkeys=[messages.HDNodePathType(node=node, address_n=[]) for node in child_hd_nodes],
        signatures=[b"", b"", b""],
        m=2,
        pubkeys_order=messages.MultisigPubkeysOrder.PRESERVED,
    )
    parsed = run_multisig_normalizer_gate(
        gate, old_style, messages.InputScriptType.SPENDMULTISIG, preserved_redeem
    )
    if parsed.get("threshold") != "2" or parsed.get("num_pubkeys") != "3" or parsed.get("sorted") != "0":
        raise AssertionError(f"unexpected old-style multisig policy: {parsed}")
    old_style_sha256_fingerprint = sha256_multisig_fingerprint(old_style)

    new_style_p2wsh = messages.MultisigRedeemScriptType(
        nodes=child_hd_nodes,
        address_n=[],
        signatures=[b"", b"", b""],
        m=2,
        pubkeys_order=messages.MultisigPubkeysOrder.PRESERVED,
    )
    parsed = run_multisig_normalizer_gate(
        gate, new_style_p2wsh, messages.InputScriptType.SPENDWITNESS, preserved_redeem
    )
    if parsed.get("threshold") != "2" or parsed.get("num_pubkeys") != "3" or parsed.get("sorted") != "0":
        raise AssertionError(f"unexpected new-style P2WSH multisig policy: {parsed}")
    if sha256_multisig_fingerprint(new_style_p2wsh) != old_style_sha256_fingerprint:
        raise AssertionError("multisig fingerprint changed between old-style and new-style protobuf forms")

    new_style_p2sh_p2wsh_sorted = messages.MultisigRedeemScriptType(
        nodes=child_hd_nodes,
        address_n=[],
        signatures=[b"", b"", b""],
        m=2,
        pubkeys_order=messages.MultisigPubkeysOrder.LEXICOGRAPHIC,
    )
    parsed = run_multisig_normalizer_gate(
        gate, new_style_p2sh_p2wsh_sorted, messages.InputScriptType.SPENDP2SHWITNESS, sorted_redeem
    )
    if parsed.get("threshold") != "2" or parsed.get("num_pubkeys") != "3" or parsed.get("sorted") != "1":
        raise AssertionError(f"unexpected sorted P2SH-P2WSH multisig policy: {parsed}")
    if sha256_multisig_fingerprint(new_style_p2sh_p2wsh_sorted) != old_style_sha256_fingerprint:
        raise AssertionError("multisig fingerprint changed when pubkey order mode changed")

    threshold_one = messages.MultisigRedeemScriptType(
        nodes=child_hd_nodes,
        address_n=[],
        signatures=[b"", b"", b""],
        m=1,
        pubkeys_order=messages.MultisigPubkeysOrder.PRESERVED,
    )
    if sha256_multisig_fingerprint(threshold_one) == old_style_sha256_fingerprint:
        raise AssertionError("multisig fingerprint did not change when threshold changed")

    private_key_node = messages.HDNodeType(
        depth=child_hd_nodes[0].depth,
        fingerprint=child_hd_nodes[0].fingerprint,
        child_num=child_hd_nodes[0].child_num,
        chain_code=child_hd_nodes[0].chain_code,
        public_key=child_hd_nodes[0].public_key,
    )
    private_key_node.private_key = b"\x01" * 32
    assert_multisig_normalizer_rejects(
        gate,
        messages.MultisigRedeemScriptType(
            pubkeys=[messages.HDNodePathType(node=private_key_node, address_n=[])],
            signatures=[b""],
            m=1,
            pubkeys_order=messages.MultisigPubkeysOrder.PRESERVED,
        ),
        messages.InputScriptType.SPENDMULTISIG,
        script.multisig(1, [child_pubkeys[0]]).data,
        "multisig HDNodeType.private_key",
    )

    assert_multisig_normalizer_rejects(
        gate,
        messages.MultisigRedeemScriptType(
            nodes=child_hd_nodes,
            address_n=[0x80000000],
            signatures=[b"", b"", b""],
            m=2,
            pubkeys_order=messages.MultisigPubkeysOrder.PRESERVED,
        ),
        messages.InputScriptType.SPENDWITNESS,
        preserved_redeem,
        "multisig hardened child suffix",
    )

    assert_multisig_normalizer_rejects(
        gate,
        messages.MultisigRedeemScriptType(
            nodes=child_hd_nodes,
            address_n=[],
            signatures=[b"", b"", b""],
            m=4,
            pubkeys_order=messages.MultisigPubkeysOrder.PRESERVED,
        ),
        messages.InputScriptType.SPENDWITNESS,
        preserved_redeem,
        "multisig threshold greater than signer count",
    )


def compact_signature_to_der(compact_signature: bytes) -> bytes:
    if len(compact_signature) != 64:
        raise AssertionError("compact signature fixture must be 64 bytes")
    return ecdsa_util.sigencode_der(
        int.from_bytes(compact_signature[:32], "big"),
        int.from_bytes(compact_signature[32:], "big"),
        SECP256k1.order,
    )


def run_multisig_partial_gate(
    gate: Path,
    multisig: messages.MultisigRedeemScriptType,
    script_type: messages.InputScriptType,
    local_compact_signature: bytes,
) -> dict[str, str]:
    output = subprocess.check_output(
        [
            str(gate),
            "--trezor-multisig-partial",
            message_payload(multisig).hex(),
            str(int(script_type)),
            local_compact_signature.hex(),
        ],
        text=True,
    )
    return parse_vectors(output)


def assert_multisig_partial_rejects(
    gate: Path,
    multisig: messages.MultisigRedeemScriptType,
    script_type: messages.InputScriptType,
    local_compact_signature: bytes,
    label: str,
) -> None:
    result = subprocess.run(
        [
            str(gate),
            "--trezor-multisig-partial",
            message_payload(multisig).hex(),
            str(int(script_type)),
            local_compact_signature.hex(),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        raise AssertionError(f"multisig partial gate accepted invalid {label}")


def check_trezor_multisig_partial_oracle(gate: Path) -> None:
    """Verify Trezor-style multisig slot semantics before enabling real signing."""

    child_hd_nodes, child_pubkeys, _, _ = trezor_multisig_fixture()
    local_compact = b"\x11" * 64
    other_compact = b"\x22" * 64
    local_der = compact_signature_to_der(local_compact)
    other_der = compact_signature_to_der(other_compact)

    sorted_pubkeys = sorted(pubkey.sec() for pubkey in child_pubkeys)
    sorted_local_slot = sorted_pubkeys.index(BTC_TEST_COMPRESSED_PUBKEY)
    sorted_signatures = [b"", b"", b""]
    sorted_other_slot = 1 if sorted_local_slot != 1 else 2
    sorted_signatures[sorted_other_slot] = other_der
    sorted_expected = []
    for slot in range(len(sorted_pubkeys)):
        if slot == sorted_local_slot:
            sorted_expected.append(local_compact)
        elif slot == sorted_other_slot:
            sorted_expected.append(other_compact)

    cases = [
        (
            "preserved",
            messages.MultisigPubkeysOrder.PRESERVED,
            [b"", other_der, b""],
            0,
            [local_compact, other_compact],
        ),
        (
            "sorted",
            messages.MultisigPubkeysOrder.LEXICOGRAPHIC,
            sorted_signatures,
            sorted_local_slot,
            sorted_expected,
        ),
    ]

    for label, order, signatures, expected_slot, expected_compacts in cases:
        multisig = messages.MultisigRedeemScriptType(
            nodes=child_hd_nodes,
            address_n=[],
            signatures=signatures,
            m=2,
            pubkeys_order=order,
        )
        parsed = run_multisig_partial_gate(gate, multisig, messages.InputScriptType.SPENDWITNESS, local_compact)
        if (
            parsed.get("partial_ok") != "1"
            or parsed.get("local_slot") != str(expected_slot)
            or parsed.get("existing_signatures") != "1"
            or parsed.get("final_signatures") != "2"
            or parsed.get("threshold") != "2"
            or parsed.get("num_pubkeys") != "3"
            or bytes.fromhex(parsed["local_der_signature"]) != local_der
            or bytes.fromhex(parsed["final_compact_signatures"]) != b"".join(expected_compacts)
        ):
            raise AssertionError(f"multisig partial slot oracle mismatch for {label}: {parsed}")

    local_already_signed = messages.MultisigRedeemScriptType(
        nodes=child_hd_nodes,
        address_n=[],
        signatures=[local_der, b"", b""],
        m=2,
        pubkeys_order=messages.MultisigPubkeysOrder.PRESERVED,
    )
    assert_multisig_partial_rejects(
        gate,
        local_already_signed,
        messages.InputScriptType.SPENDWITNESS,
        local_compact,
        "local slot already signed",
    )

    threshold_already_met = messages.MultisigRedeemScriptType(
        nodes=child_hd_nodes,
        address_n=[],
        signatures=[b"", other_der, compact_signature_to_der(b"\x33" * 64)],
        m=2,
        pubkeys_order=messages.MultisigPubkeysOrder.PRESERVED,
    )
    assert_multisig_partial_rejects(
        gate,
        threshold_already_met,
        messages.InputScriptType.SPENDWITNESS,
        local_compact,
        "threshold already met",
    )

    malformed_existing = messages.MultisigRedeemScriptType(
        nodes=child_hd_nodes,
        address_n=[],
        signatures=[b"", b"\x30\x01\x01", b""],
        m=2,
        pubkeys_order=messages.MultisigPubkeysOrder.PRESERVED,
    )
    assert_multisig_partial_rejects(
        gate,
        malformed_existing,
        messages.InputScriptType.SPENDWITNESS,
        local_compact,
        "malformed existing signature",
    )


def parse_push_only_script(raw: bytes) -> list[bytes]:
    """Parse the strict push-only subset used by multisig scriptSig."""
    items: list[bytes] = []
    offset = 0
    while offset < len(raw):
        opcode = raw[offset]
        offset += 1
        if opcode == 0:
            items.append(b"")
            continue
        if opcode <= 75:
            item_len = opcode
        elif opcode == 0x4C:
            if offset >= len(raw):
                raise AssertionError("truncated OP_PUSHDATA1")
            item_len = raw[offset]
            offset += 1
        elif opcode == 0x4D:
            if offset + 2 > len(raw):
                raise AssertionError("truncated OP_PUSHDATA2")
            item_len = int.from_bytes(raw[offset : offset + 2], "little")
            offset += 2
        else:
            raise AssertionError(f"non-push opcode in multisig scriptSig: 0x{opcode:02x}")
        if item_len == 0 or item_len > len(raw) - offset:
            raise AssertionError("invalid multisig scriptSig push length")
        items.append(raw[offset : offset + item_len])
        offset += item_len
    return items


def check_trezor_multisig_tx_structure_oracle(gate: Path) -> None:
    """Verify multisig digest, raw transaction, and review binding with embit."""
    from embit import ec, script
    from embit.transaction import Transaction

    child_hd_nodes, _, redeem_script, _ = trezor_multisig_fixture()
    multisig = messages.MultisigRedeemScriptType(
        nodes=child_hd_nodes,
        address_n=[],
        signatures=[b"", b"", b""],
        m=2,
        pubkeys_order=messages.MultisigPubkeysOrder.PRESERVED,
    )
    compact_signatures = [b"\x11" * 64, b"\x22" * 64]
    expected_signatures = [
        ecdsa_util.sigencode_der(
            int.from_bytes(value[:32], "big"),
            int.from_bytes(value[32:], "big"),
            SECP256k1.order,
        )
        + b"\x01"
        for value in compact_signatures
    ]
    witness_program = b"\x00\x20" + hashlib.sha256(redeem_script).digest()
    cases = [
        (
            messages.InputScriptType.SPENDMULTISIG,
            b"\xa9\x14" + hash160(redeem_script) + b"\x87",
            b"",
            "2-of-3 P2SH",
        ),
        (
            messages.InputScriptType.SPENDWITNESS,
            witness_program,
            witness_program,
            "2-of-3 P2WSH",
        ),
        (
            messages.InputScriptType.SPENDP2SHWITNESS,
            b"\xa9\x14" + hash160(witness_program) + b"\x87",
            witness_program,
            "2-of-3 P2SH-P2WSH",
        ),
    ]

    for script_type, prevout_script, expected_witness_program, policy_text in cases:
        expected_path_type = {
            messages.InputScriptType.SPENDMULTISIG: 0,
            messages.InputScriptType.SPENDP2SHWITNESS: 1,
            messages.InputScriptType.SPENDWITNESS: 2,
        }[script_type]
        expected_path = f"2147483696/2147483649/2147483648/{0x80000000 | expected_path_type}/0/0"
        output = subprocess.check_output(
            [
                str(gate),
                "--trezor-multisig-tx",
                message_payload(multisig).hex(),
                str(int(script_type)),
                prevout_script.hex(),
                expected_witness_program.hex() if expected_witness_program else "-",
                b"".join(compact_signatures).hex(),
            ],
            text=True,
        )
        parsed = parse_vectors(output)
        if parsed.get("summary_ok") != "1" or parsed.get("digest_ok") != "1" or parsed.get("tx_ok") != "1":
            raise AssertionError(f"multisig tx C gate failed for {script_type}: {parsed}")

        raw_tx = bytes.fromhex(parsed["raw_tx"])
        tx = Transaction.parse(raw_tx)
        if tx.serialize() != raw_tx:
            raise AssertionError(f"multisig raw tx round-trip mismatch for {script_type}")
        if tx.version != 2 or tx.locktime != 0 or len(tx.vin) != 1 or len(tx.vout) != 2:
            raise AssertionError(f"multisig raw tx shape mismatch for {script_type}")
        tx_input = tx.vin[0]
        if tx_input.txid != bytes(range(32)) or tx_input.vout != 1 or tx_input.sequence != 0xFFFFFFFD:
            raise AssertionError(f"multisig outpoint/sequence mismatch for {script_type}")
        if tx.vout[0].value != 90_000 or tx.vout[0].script_pubkey.data != btc_p2wpkh_script_pubkey():
            raise AssertionError(f"multisig external output mismatch for {script_type}")
        if tx.vout[1].value != 5_000 or tx.vout[1].script_pubkey.data != prevout_script:
            raise AssertionError(f"multisig change output mismatch for {script_type}")

        if (
            parsed.get("summary_to") != btc_tx_output_address()
            or parsed.get("summary_policy") != policy_text
            or parsed.get("summary_amount") != "90000"
            or parsed.get("summary_change") != "5000"
            or parsed.get("summary_fee") != "5000"
            or parsed.get("summary_fee_rate") != "10"
            or parsed.get("path_len") != "6"
            or parsed.get("path") != expected_path
        ):
            raise AssertionError(f"multisig UI summary is not bound to raw tx for {script_type}: {parsed}")
        if 100_000 - sum(output.value for output in tx.vout) != int(parsed["summary_fee"]):
            raise AssertionError(f"multisig fee/raw tx mismatch for {script_type}")

        expected_digest = (
            tx.sighash_legacy(0, script.Script(redeem_script), sighash=1)
            if script_type == messages.InputScriptType.SPENDMULTISIG
            else tx.sighash_segwit(0, script.Script(redeem_script), 100_000, sighash=1)
        )
        if bytes.fromhex(parsed["digest"]) != expected_digest:
            raise AssertionError(
                f"multisig digest mismatch for {script_type}: "
                f"actual={parsed['digest']} expected={expected_digest.hex()}"
            )

        for encoded in expected_signatures:
            if ec.Signature.parse(encoded[:-1]).serialize() != encoded[:-1]:
                raise AssertionError("fake multisig signature is not canonical DER")
        if script_type == messages.InputScriptType.SPENDMULTISIG:
            if tx_input.witness.items:
                raise AssertionError("legacy P2SH multisig unexpectedly contains witness")
            if parse_push_only_script(tx_input.script_sig.data) != [b"", *expected_signatures, redeem_script]:
                raise AssertionError("P2SH multisig signature/redeem-script placement mismatch")
        else:
            expected_script_sig_items = (
                []
                if script_type == messages.InputScriptType.SPENDWITNESS
                else [witness_program]
            )
            if parse_push_only_script(tx_input.script_sig.data) != expected_script_sig_items:
                raise AssertionError(f"multisig nested scriptSig mismatch for {script_type}")
            if tx_input.witness.items != [b"", *expected_signatures, redeem_script]:
                raise AssertionError(f"multisig witness signature/script placement mismatch for {script_type}")

    bad_prevout = bytearray(cases[1][1])
    bad_prevout[-1] ^= 1
    bad_calls = [
        [bad_prevout.hex(), witness_program.hex(), b"".join(compact_signatures).hex()],
        [cases[1][1].hex(), witness_program.hex(), compact_signatures[0].hex()],
        [cases[1][1].hex(), (witness_program[:-1] + bytes([witness_program[-1] ^ 1])).hex(), b"".join(compact_signatures).hex()],
    ]
    for prevout_hex, witness_hex, signatures_hex in bad_calls:
        result = subprocess.run(
            [
                str(gate),
                "--trezor-multisig-tx",
                message_payload(multisig).hex(),
                str(int(messages.InputScriptType.SPENDWITNESS)),
                prevout_hex,
                witness_hex,
                signatures_hex,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            raise AssertionError("multisig tx gate accepted corrupted policy/signature input")

    for script_type, prevout_script, expected_witness_program, _ in cases:
        for path_case in (
            "external-change",
            "wrong-account",
            "wrong-coin",
            "wrong-script",
            "wrong-input-script",
            "oversized-index",
        ):
            result = subprocess.run(
                [
                    str(gate),
                    "--trezor-multisig-tx",
                    message_payload(multisig).hex(),
                    str(int(script_type)),
                    prevout_script.hex(),
                    expected_witness_program.hex() if expected_witness_program else "-",
                    b"".join(compact_signatures).hex(),
                    path_case,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                raise AssertionError(
                    f"multisig tx gate accepted invalid {path_case} path for {script_type}"
                )

    bip45_path = parse_path("m/45h/0/0/0")
    bip45_output = subprocess.check_output(
        [
            str(gate),
            "--trezor-multisig-tx",
            message_payload(multisig).hex(),
            str(int(messages.InputScriptType.SPENDMULTISIG)),
            cases[0][1].hex(),
            "-",
            b"".join(compact_signatures).hex(),
            "bip45-valid",
        ],
        text=True,
    )
    bip45_parsed = parse_vectors(bip45_output)
    if (
        bip45_parsed.get("summary_ok") != "1"
        or bip45_parsed.get("digest_ok") != "1"
        or bip45_parsed.get("tx_ok") != "1"
        or bip45_parsed.get("path") != "/".join(str(part) for part in bip45_path)
    ):
        raise AssertionError(f"BIP45 multisig path gate mismatch: {bip45_parsed}")

    for script_type, prevout_script, expected_witness_program, policy_text in cases:
        expected_path_type = {
            messages.InputScriptType.SPENDMULTISIG: 0,
            messages.InputScriptType.SPENDP2SHWITNESS: 1,
            messages.InputScriptType.SPENDWITNESS: 2,
        }[script_type]
        mainnet_output = subprocess.check_output(
            [
                str(gate),
                "--trezor-multisig-tx",
                message_payload(multisig).hex(),
                str(int(script_type)),
                prevout_script.hex(),
                expected_witness_program.hex() if expected_witness_program else "-",
                b"".join(compact_signatures).hex(),
                "mainnet-valid",
            ],
            text=True,
        )
        mainnet_parsed = parse_vectors(mainnet_output)
        mainnet_path = f"2147483696/2147483648/2147483648/{0x80000000 | expected_path_type}/0/0"
        if (
            mainnet_parsed.get("summary_ok") != "1"
            or mainnet_parsed.get("digest_ok") != "1"
            or mainnet_parsed.get("tx_ok") != "1"
            or mainnet_parsed.get("summary_to") != btc_tx_output_address_mainnet()
            or mainnet_parsed.get("summary_policy") != policy_text
            or mainnet_parsed.get("path") != mainnet_path
        ):
            raise AssertionError(f"mainnet BIP48 multisig path gate mismatch: {mainnet_parsed}")
        mainnet_tx = Transaction.parse(bytes.fromhex(mainnet_parsed["raw_tx"]))
        if mainnet_tx.vout[0].script_pubkey.data != btc_p2wpkh_script_pubkey():
            raise AssertionError(f"mainnet multisig external output mismatch for {script_type}")


def check_local_btc_signtx_wire_script_oracle(gate: Path) -> None:
    btc_pubkey_hash = hash160(BTC_TEST_COMPRESSED_PUBKEY)
    btc_p2wpkh_script = b"\x00\x14" + btc_pubkey_hash
    tx_input_0 = btc_tx_input(path=btc_input_path())
    tx_input_1 = btc_tx_input(path=btc_input_path(1), prev_hash=bytes.fromhex("22" * 32), prev_index=1, amount=40_000)
    external_output = btc_tx_output_external(amount=90_000)
    change_output = btc_tx_output_change(amount=45_000)
    common_meta = btc_tx_ack_meta(2, 2)
    multisig_nodes, _, preserved_redeem, _ = trezor_multisig_fixture()
    multisig = messages.MultisigRedeemScriptType(
        nodes=multisig_nodes,
        address_n=[],
        signatures=[b"", b"", b""],
        m=2,
        pubkeys_order=messages.MultisigPubkeysOrder.PRESERVED,
    )

    single_responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Testnet", inputs_count=1, outputs_count=1, version=2, lock_time=0),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 1)),
            (messages.MessageType.TxAck, btc_tx_ack_input(tx_input_0)),
            (messages.MessageType.TxAck, btc_tx_ack_output(external_output)),
        ],
    )
    single_final = assert_btc_tx_request(
        single_responses[-1],
        messages.RequestType.TXFINISHED,
        signature_index=0,
        expect_serialized_tx=True,
    )
    check_embit_btc_signed_tx_oracle(
        single_final.serialized.serialized_tx,
        version=2,
        locktime=0,
        inputs=[(btc_tx_prev_hash(), 0)],
        outputs=[(90_000, btc_p2wpkh_script)],
        witness_pubkeys=[BTC_TEST_COMPRESSED_PUBKEY],
    )

    mainnet_input = btc_tx_input(path=btc_input_path(mainnet=True))
    mainnet_output = btc_tx_output_external(amount=90_000, address=btc_tx_output_address_mainnet())
    mainnet_responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Bitcoin", inputs_count=1, outputs_count=1, version=2, lock_time=0),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 1)),
            (messages.MessageType.TxAck, btc_tx_ack_input(mainnet_input)),
            (messages.MessageType.TxAck, btc_tx_ack_output(mainnet_output)),
        ],
    )
    mainnet_final = assert_btc_tx_request(
        mainnet_responses[-1],
        messages.RequestType.TXFINISHED,
        signature_index=0,
        expect_serialized_tx=True,
    )
    check_embit_btc_signed_tx_oracle(
        mainnet_final.serialized.serialized_tx,
        version=2,
        locktime=0,
        inputs=[(btc_tx_prev_hash(), 0)],
        outputs=[(90_000, btc_p2wpkh_script)],
        witness_pubkeys=[BTC_TEST_COMPRESSED_PUBKEY],
    )

    responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Testnet", inputs_count=2, outputs_count=2, version=2, lock_time=0),
            ),
            (messages.MessageType.TxAck, common_meta),
            (messages.MessageType.TxAck, btc_tx_ack_input(tx_input_0)),
            (messages.MessageType.TxAck, btc_tx_ack_input(tx_input_1)),
            (messages.MessageType.TxAck, btc_tx_ack_output(external_output)),
            (messages.MessageType.TxAck, btc_tx_ack_output(change_output)),
            (messages.MessageType.TxAck, common_meta),
        ],
    )
    expected = [
        (messages.RequestType.TXMETA, None, None, False),
        (messages.RequestType.TXINPUT, 0, None, False),
        (messages.RequestType.TXINPUT, 1, None, False),
        (messages.RequestType.TXOUTPUT, 0, None, False),
        (messages.RequestType.TXOUTPUT, 1, None, False),
        (messages.RequestType.TXMETA, None, 0, False),
        (messages.RequestType.TXFINISHED, None, 1, True),
    ]
    for response, (request_type, request_index, signature_index, expect_serialized_tx) in zip(responses, expected):
        tx_request = assert_btc_tx_request(
            response,
            request_type,
            request_index=request_index,
            signature_index=signature_index,
            expect_serialized_tx=expect_serialized_tx,
        )
    check_embit_btc_signed_tx_oracle(
        tx_request.serialized.serialized_tx,
        version=2,
        locktime=0,
        inputs=[(btc_tx_prev_hash(), 0), (bytes.fromhex("22" * 32), 1)],
        outputs=[(90_000, btc_p2wpkh_script), (45_000, btc_p2wpkh_script)],
        witness_pubkeys=[BTC_TEST_COMPRESSED_PUBKEY, BTC_TEST_COMPRESSED_PUBKEY],
    )

    overflow_responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Testnet", inputs_count=1, outputs_count=1, version=2, lock_time=0),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 1)),
            (messages.MessageType.TxAck, btc_tx_ack_input(tx_input_0)),
            (messages.MessageType.TxAck, btc_tx_ack_output(btc_tx_output_external(amount=100_001))),
        ],
    )
    assert_btc_failure(overflow_responses[-1], messages.FailureType.DataError, "BTC output greater than input")

    high_fee_responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Testnet", inputs_count=1, outputs_count=1, version=2, lock_time=0),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 1)),
            (messages.MessageType.TxAck, btc_tx_ack_input(btc_tx_input(amount=200_000))),
            (messages.MessageType.TxAck, btc_tx_ack_output(btc_tx_output_external(amount=80_000))),
        ],
    )
    assert_btc_failure(high_fee_responses[-1], messages.FailureType.DataError, "BTC fee-rate too high")

    hidden_locktime_responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Testnet", inputs_count=1, outputs_count=1, version=2, lock_time=1),
            ),
        ],
    )
    assert_btc_failure(hidden_locktime_responses[-1], messages.FailureType.DataError, "BTC hidden lock_time")

    mixed_account_responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Testnet", inputs_count=2, outputs_count=1, version=2, lock_time=0),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_meta(2, 1)),
            (messages.MessageType.TxAck, btc_tx_ack_input(tx_input_0)),
            (
                messages.MessageType.TxAck,
                btc_tx_ack_input(
                    btc_tx_input(
                        path=btc_input_path(1, account=1),
                        prev_hash=bytes.fromhex("33" * 32),
                        prev_index=1,
                        amount=40_000,
                    )
                ),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_output(external_output)),
        ],
    )
    assert_btc_failure(mixed_account_responses[-1], messages.FailureType.DataError, "BTC mixed-account inputs")

    two_external_responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Testnet", inputs_count=1, outputs_count=2, version=2, lock_time=0),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 2)),
            (messages.MessageType.TxAck, btc_tx_ack_input(tx_input_0)),
            (messages.MessageType.TxAck, btc_tx_ack_output(btc_tx_output_external(amount=50_000))),
            (
                messages.MessageType.TxAck,
                btc_tx_ack_output(
                    btc_tx_output_external(
                        amount=40_000,
                        address="tb1qgj8n7c7e9s2vtz0z9w3lzggr5lk6ndeg29dh7a",
                    )
                ),
            ),
        ],
    )
    assert_btc_failure(two_external_responses[-1], messages.FailureType.DataError, "BTC multiple external outputs")

    unsupported_script_responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Testnet", inputs_count=1, outputs_count=1, version=2, lock_time=0),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 1)),
            (
                messages.MessageType.TxAck,
                btc_tx_ack_input(btc_tx_input(script_type=messages.InputScriptType.SPENDMULTISIG)),
            ),
        ],
    )
    assert_btc_failure(unsupported_script_responses[-1], messages.FailureType.DataError, "BTC unsupported input script")

    get_multisig_address_res = run_local_wire_oracle(
        gate,
        messages.MessageType.GetAddress,
        messages.GetAddress(
            address_n=[0x80000030, 0x80000001, 0x80000000, 0x80000002, 0, 0],
            coin_name="Testnet",
            show_display=False,
            script_type=messages.InputScriptType.SPENDMULTISIG,
            multisig=multisig,
        ),
    )
    if get_multisig_address_res[0] != messages.MessageType.Address:
        raise AssertionError(f"BTC multisig address request must return Address, got {get_multisig_address_res[0]}")
    multisig_address = protobuf.load_message(io.BytesIO(get_multisig_address_res[1]), messages.Address)
    if multisig_address.address != "2NGateMultisigP2SHTestnet1111111":
        raise AssertionError(f"unexpected BTC multisig address response: {multisig_address.address}")

    multisig_address_cases = [
        (
            messages.InputScriptType.SPENDWITNESS,
            "tb1qgatemultisigp2wsh000000000000000000000000000000000",
        ),
        (
            messages.InputScriptType.SPENDP2SHWITNESS,
            "2NGateMultisigNestedTestnet111111",
        ),
    ]
    for script_type, expected_address in multisig_address_cases:
        response = run_local_wire_oracle(
            gate,
            messages.MessageType.GetAddress,
            messages.GetAddress(
                address_n=[0x80000030, 0x80000001, 0x80000000, 0x80000002, 0, 0],
                coin_name="Testnet",
                show_display=False,
                script_type=script_type,
                multisig=multisig,
            ),
        )
        if response[0] != messages.MessageType.Address:
            raise AssertionError(f"BTC multisig address request {script_type} must return Address, got {response[0]}")
        actual_address = protobuf.load_message(io.BytesIO(response[1]), messages.Address).address
        if actual_address != expected_address:
            raise AssertionError(
                f"unexpected BTC multisig address response for {script_type}: {actual_address}"
            )

    no_local_multisig = messages.MultisigRedeemScriptType(
        nodes=multisig_nodes[1:],
        address_n=[],
        signatures=[b"", b""],
        m=2,
        pubkeys_order=messages.MultisigPubkeysOrder.PRESERVED,
    )
    no_local_multisig_address_res = run_local_wire_oracle(
        gate,
        messages.MessageType.GetAddress,
        messages.GetAddress(
            address_n=[0x80000030, 0x80000001, 0x80000000, 0x80000002, 0, 0],
            coin_name="Testnet",
            show_display=False,
            script_type=messages.InputScriptType.SPENDMULTISIG,
            multisig=no_local_multisig,
        ),
    )
    assert_btc_failure(
        no_local_multisig_address_res,
        messages.FailureType.ActionCancelled,
        "BTC multisig address without local signer",
    )

    for multisig_script_type in (
        messages.InputScriptType.SPENDMULTISIG,
        messages.InputScriptType.SPENDWITNESS,
        messages.InputScriptType.SPENDP2SHWITNESS,
    ):
        assert_btc_verified_multisig_signs(
            gate, multisig, preserved_redeem, multisig_script_type
        )

    assert_btc_multisig_prevout_mismatch_rejects(
        gate, multisig, preserved_redeem, messages.InputScriptType.SPENDWITNESS
    )
    assert_btc_verified_multisig_rejects_mismatched_change(
        gate,
        multisig,
        preserved_redeem,
        messages.InputScriptType.SPENDWITNESS,
    )

    get_taproot_address_res = run_local_wire_oracle(
        gate,
        messages.MessageType.GetAddress,
        messages.GetAddress(
            address_n=[0x80000056, 0x80000001, 0x80000000, 0, 0],
            coin_name="Testnet",
            show_display=False,
            script_type=messages.InputScriptType.SPENDTAPROOT,
        ),
    )
    assert_btc_failure(get_taproot_address_res, messages.FailureType.DataError, "BTC taproot address request")

    get_taproot_xpub_res = run_local_wire_oracle(
        gate,
        messages.MessageType.GetPublicKey,
        messages.GetPublicKey(
            address_n=[0x80000056, 0x80000001, 0x80000000],
            coin_name="Testnet",
            script_type=messages.InputScriptType.SPENDTAPROOT,
        ),
    )
    assert_btc_failure(get_taproot_xpub_res, messages.FailureType.DataError, "BTC taproot public key request")

    taproot_input_responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Testnet", inputs_count=1, outputs_count=1, version=2, lock_time=0),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 1)),
            (
                messages.MessageType.TxAck,
                btc_tx_ack_input(
                    btc_tx_input(
                        path=[0x80000056, 0x80000001, 0x80000000, 0, 0],
                        script_type=messages.InputScriptType.SPENDTAPROOT,
                        amount=100_000,
                    )
                ),
            ),
        ],
    )
    assert_btc_failure(taproot_input_responses[-1], messages.FailureType.DataError, "BTC taproot input script")

    multisig_output_responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Testnet", inputs_count=1, outputs_count=1, version=2, lock_time=0),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 1)),
            (messages.MessageType.TxAck, btc_tx_ack_input(tx_input_0)),
            (
                messages.MessageType.TxAck,
                btc_tx_ack_output(
                    messages.TxOutputType(
                        address_n=[0x80000030, 0x80000001, 0x80000000, 0x80000002, 1, 0],
                        amount=90_000,
                        script_type=messages.OutputScriptType.PAYTOMULTISIG,
                        multisig=multisig,
                    )
                ),
            ),
        ],
    )
    assert_btc_failure(multisig_output_responses[-1], messages.FailureType.DataError, "BTC multisig output")

    legacy_script_pubkey = btc_p2pkh_script_pubkey()
    legacy_prev_txid = btc_prev_txid_for_single_input_two_outputs(prevout0_script_pubkey=legacy_script_pubkey)
    legacy_input = btc_tx_input(
        path=btc_p2pkh_input_path(),
        prev_hash=legacy_prev_txid,
        prev_index=0,
        amount=1,
        script_type=messages.InputScriptType.SPENDADDRESS,
    )
    from embit import script
    from embit.transaction import Transaction, TransactionInput, TransactionOutput

    legacy_unsigned_tx = Transaction(
        version=2,
        vin=[TransactionInput(legacy_prev_txid, 0)],
        vout=[TransactionOutput(90_000, script.Script(btc_p2wpkh_script_pubkey()))],
        locktime=0,
    )
    legacy_digest = legacy_unsigned_tx.sighash_legacy(0, script.Script(btc_p2pkh_script_pubkey()), sighash=1)
    legacy_prev_tx_responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Testnet", inputs_count=1, outputs_count=1, version=2, lock_time=0),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 1)),
            (messages.MessageType.TxAck, btc_tx_ack_input(legacy_input)),
            (messages.MessageType.TxAck, btc_tx_ack_output(external_output)),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 2)),
            (messages.MessageType.TxAck, btc_tx_ack_prev_input()),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(100_000, legacy_script_pubkey)),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(1_000)),
        ],
        btc_compact_signatures=[btc_sign_digest_compact(legacy_digest)],
    )
    expected_legacy_prev = [
        (messages.RequestType.TXMETA, None),
        (messages.RequestType.TXINPUT, None),
        (messages.RequestType.TXOUTPUT, None),
        (messages.RequestType.TXMETA, legacy_prev_txid),
        (messages.RequestType.TXORIGINPUT, legacy_prev_txid),
        (messages.RequestType.TXORIGOUTPUT, legacy_prev_txid),
        (messages.RequestType.TXORIGOUTPUT, legacy_prev_txid),
    ]
    for index, (request_type, tx_hash) in enumerate(expected_legacy_prev):
        assert_btc_tx_request(
            legacy_prev_tx_responses[index],
            request_type,
            request_index=0 if request_type in (messages.RequestType.TXINPUT, messages.RequestType.TXOUTPUT, messages.RequestType.TXORIGINPUT) else None,
            tx_hash=tx_hash,
        )
    legacy_final = assert_btc_tx_request(
        legacy_prev_tx_responses[-1],
        messages.RequestType.TXFINISHED,
        signature_index=0,
        expect_serialized_tx=True,
    )
    check_embit_btc_p2pkh_signed_tx_oracle(
        legacy_final.serialized.serialized_tx,
        prev_txid=legacy_prev_txid,
    )

    legacy_base58_output = btc_tx_output_external(amount=90_000, address=btc_tx_p2pkh_address_testnet())
    legacy_base58_unsigned_tx = Transaction(
        version=2,
        vin=[TransactionInput(legacy_prev_txid, 0)],
        vout=[TransactionOutput(90_000, script.Script(btc_p2pkh_script_pubkey()))],
        locktime=0,
    )
    legacy_base58_digest = legacy_base58_unsigned_tx.sighash_legacy(
        0, script.Script(btc_p2pkh_script_pubkey()), sighash=1
    )
    legacy_base58_responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Testnet", inputs_count=1, outputs_count=1, version=2, lock_time=0),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 1)),
            (messages.MessageType.TxAck, btc_tx_ack_input(legacy_input)),
            (messages.MessageType.TxAck, btc_tx_ack_output(legacy_base58_output)),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 2)),
            (messages.MessageType.TxAck, btc_tx_ack_prev_input()),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(100_000, legacy_script_pubkey)),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(1_000)),
        ],
        btc_compact_signatures=[btc_sign_digest_compact(legacy_base58_digest)],
    )
    legacy_base58_final = assert_btc_tx_request(
        legacy_base58_responses[-1],
        messages.RequestType.TXFINISHED,
        signature_index=0,
        expect_serialized_tx=True,
    )
    check_embit_btc_p2pkh_signed_tx_oracle(
        legacy_base58_final.serialized.serialized_tx,
        prev_txid=legacy_prev_txid,
        expected_output_script=btc_p2pkh_script_pubkey(),
    )

    wrong_network_base58_responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Testnet", inputs_count=1, outputs_count=1, version=2, lock_time=0),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 1)),
            (messages.MessageType.TxAck, btc_tx_ack_input(legacy_input)),
            (
                messages.MessageType.TxAck,
                btc_tx_ack_output(btc_tx_output_external(amount=90_000, address=btc_tx_p2pkh_address_mainnet())),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 2)),
            (messages.MessageType.TxAck, btc_tx_ack_prev_input()),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(100_000, legacy_script_pubkey)),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(1_000)),
        ],
        btc_compact_signatures=[btc_sign_digest_compact(legacy_base58_digest)],
    )
    assert_btc_failure(
        wrong_network_base58_responses[-1],
        messages.FailureType.DataError,
        "BTC wrong-network base58 output",
    )

    legacy_mismatch_prev_txid = btc_prev_txid_for_single_input_two_outputs(
        prevout0_script_pubkey=btc_p2wpkh_script_pubkey()
    )
    legacy_mismatch_responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Testnet", inputs_count=1, outputs_count=1, version=2, lock_time=0),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 1)),
            (
                messages.MessageType.TxAck,
                btc_tx_ack_input(
                    btc_tx_input(
                        path=[0x8000002C, 0x80000001, 0x80000000, 0, 0],
                        prev_hash=legacy_mismatch_prev_txid,
                        prev_index=0,
                        amount=1,
                        script_type=messages.InputScriptType.SPENDADDRESS,
                    )
                ),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_output(external_output)),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 2)),
            (messages.MessageType.TxAck, btc_tx_ack_prev_input()),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(100_000, btc_p2wpkh_script_pubkey())),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(1_000)),
        ],
    )
    assert_btc_failure(
        legacy_mismatch_responses[-1],
        messages.FailureType.DataError,
        "BTC legacy prevout script/path mismatch",
        "Invalid Bitcoin transaction data",
    )

    p2sh_script_pubkey = btc_p2sh_p2wpkh_script_pubkey()
    p2sh_prev_txid = btc_prev_txid_for_single_input_two_outputs(
        script_sig=b"\x52",
        prevout0_script_pubkey=p2sh_script_pubkey,
    )
    p2sh_input = btc_tx_input(
        path=[0x80000031, 0x80000001, 0x80000000, 0, 0],
        prev_hash=p2sh_prev_txid,
        prev_index=0,
        amount=1,
        script_type=messages.InputScriptType.SPENDP2SHWITNESS,
    )
    p2sh_witness_prev_tx_responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Testnet", inputs_count=1, outputs_count=1, version=2, lock_time=0),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 1)),
            (messages.MessageType.TxAck, btc_tx_ack_input(p2sh_input)),
            (messages.MessageType.TxAck, btc_tx_ack_output(external_output)),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 2)),
            (messages.MessageType.TxAck, btc_tx_ack_prev_input(script_sig=b"\x52")),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(100_000, p2sh_script_pubkey)),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(1_000)),
        ],
    )
    assert_btc_tx_request(p2sh_witness_prev_tx_responses[3], messages.RequestType.TXMETA, tx_hash=p2sh_prev_txid)
    assert_btc_tx_request(
        p2sh_witness_prev_tx_responses[4],
        messages.RequestType.TXORIGINPUT,
        request_index=0,
        tx_hash=p2sh_prev_txid,
    )
    assert_btc_tx_request(
        p2sh_witness_prev_tx_responses[5],
        messages.RequestType.TXORIGOUTPUT,
        request_index=0,
        tx_hash=p2sh_prev_txid,
    )
    assert_btc_tx_request(
        p2sh_witness_prev_tx_responses[6],
        messages.RequestType.TXORIGOUTPUT,
        request_index=1,
        tx_hash=p2sh_prev_txid,
    )
    assert_btc_tx_request(
        p2sh_witness_prev_tx_responses[-1],
        messages.RequestType.TXFINISHED,
        signature_index=0,
        expect_serialized_tx=True,
    )

    p2sh_mismatch_prev_txid = btc_prev_txid_for_single_input_two_outputs(
        script_sig=b"\x52",
        prevout0_script_pubkey=btc_p2wpkh_script_pubkey(),
    )
    p2sh_mismatch_responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Testnet", inputs_count=1, outputs_count=1, version=2, lock_time=0),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 1)),
            (
                messages.MessageType.TxAck,
                btc_tx_ack_input(
                    btc_tx_input(
                        path=[0x80000031, 0x80000001, 0x80000000, 0, 0],
                        prev_hash=p2sh_mismatch_prev_txid,
                        prev_index=0,
                        amount=1,
                        script_type=messages.InputScriptType.SPENDP2SHWITNESS,
                    )
                ),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_output(external_output)),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 2)),
            (messages.MessageType.TxAck, btc_tx_ack_prev_input(script_sig=b"\x52")),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(100_000, btc_p2wpkh_script_pubkey())),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(1_000)),
        ],
    )
    assert_btc_failure(
        p2sh_mismatch_responses[-1],
        messages.FailureType.DataError,
        "BTC P2SH-P2WPKH prevout script/path mismatch",
        "Invalid Bitcoin transaction data",
    )

    p2sh_true_sig_prev_txid = btc_prev_txid_for_single_input_two_outputs(
        script_sig=b"\x53",
        prevout0_script_pubkey=btc_p2sh_p2wpkh_script_pubkey(),
    )
    p2sh_true_sig_input = btc_tx_input(
        path=btc_p2sh_input_path(),
        prev_hash=p2sh_true_sig_prev_txid,
        prev_index=0,
        amount=1,
        script_type=messages.InputScriptType.SPENDP2SHWITNESS,
    )
    unsigned_tx = Transaction(
        version=2,
        vin=[TransactionInput(p2sh_true_sig_prev_txid, 0)],
        vout=[TransactionOutput(90_000, script.Script(btc_p2wpkh_script_pubkey()))],
        locktime=0,
    )
    p2sh_digest = unsigned_tx.sighash_segwit(0, script.Script(btc_p2pkh_script_code()), 100_000, sighash=1)
    p2sh_true_sig_responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Testnet", inputs_count=1, outputs_count=1, version=2, lock_time=0),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 1)),
            (messages.MessageType.TxAck, btc_tx_ack_input(p2sh_true_sig_input)),
            (messages.MessageType.TxAck, btc_tx_ack_output(external_output)),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 2)),
            (messages.MessageType.TxAck, btc_tx_ack_prev_input(script_sig=b"\x53")),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(100_000, btc_p2sh_p2wpkh_script_pubkey())),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(1_000)),
        ],
        btc_compact_signatures=[btc_sign_digest_compact(p2sh_digest)],
    )
    p2sh_final = assert_btc_tx_request(
        p2sh_true_sig_responses[-1],
        messages.RequestType.TXFINISHED,
        signature_index=0,
        expect_serialized_tx=True,
    )
    check_embit_btc_p2sh_p2wpkh_signed_tx_oracle(
        p2sh_final.serialized.serialized_tx,
        prev_txid=p2sh_true_sig_prev_txid,
        amount=100_000,
    )

    p2sh_base58_output = btc_tx_output_external(amount=90_000, address=btc_tx_p2sh_p2wpkh_address_testnet())
    p2sh_base58_unsigned_tx = Transaction(
        version=2,
        vin=[TransactionInput(p2sh_true_sig_prev_txid, 0)],
        vout=[TransactionOutput(90_000, script.Script(btc_p2sh_p2wpkh_script_pubkey()))],
        locktime=0,
    )
    p2sh_base58_digest = p2sh_base58_unsigned_tx.sighash_segwit(
        0, script.Script(btc_p2pkh_script_code()), 100_000, sighash=1
    )
    p2sh_base58_responses = run_local_wire_script(
        gate,
        [
            (
                messages.MessageType.SignTx,
                messages.SignTx(coin_name="Testnet", inputs_count=1, outputs_count=1, version=2, lock_time=0),
            ),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 1)),
            (messages.MessageType.TxAck, btc_tx_ack_input(p2sh_true_sig_input)),
            (messages.MessageType.TxAck, btc_tx_ack_output(p2sh_base58_output)),
            (messages.MessageType.TxAck, btc_tx_ack_meta(1, 2)),
            (messages.MessageType.TxAck, btc_tx_ack_prev_input(script_sig=b"\x53")),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(100_000, btc_p2sh_p2wpkh_script_pubkey())),
            (messages.MessageType.TxAck, btc_tx_ack_prev_output(1_000)),
        ],
        btc_compact_signatures=[btc_sign_digest_compact(p2sh_base58_digest)],
    )
    p2sh_base58_final = assert_btc_tx_request(
        p2sh_base58_responses[-1],
        messages.RequestType.TXFINISHED,
        signature_index=0,
        expect_serialized_tx=True,
    )
    check_embit_btc_p2sh_p2wpkh_signed_tx_oracle(
        p2sh_base58_final.serialized.serialized_tx,
        prev_txid=p2sh_true_sig_prev_txid,
        amount=100_000,
        expected_output_script=btc_p2sh_p2wpkh_script_pubkey(),
    )


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

    prev_hash = bytes.fromhex("11" * 32)
    txoriginput_request = message_payload(
        messages.TxRequest(
            request_type=messages.RequestType.TXORIGINPUT,
            details=messages.TxRequestDetailsType(request_index=0, tx_hash=prev_hash),
        )
    )
    if txoriginput_request.hex() != "08051224080012201111111111111111111111111111111111111111111111111111111111111111":
        raise AssertionError(
            f"unexpected trezorlib BTC TxRequest(TXORIGINPUT) protobuf: {txoriginput_request.hex()}"
        )

    txorigoutput_request = message_payload(
        messages.TxRequest(
            request_type=messages.RequestType.TXORIGOUTPUT,
            details=messages.TxRequestDetailsType(request_index=1, tx_hash=prev_hash),
        )
    )
    if txorigoutput_request.hex() != "08061224080112201111111111111111111111111111111111111111111111111111111111111111":
        raise AssertionError(
            f"unexpected trezorlib BTC TxRequest(TXORIGOUTPUT) protobuf: {txorigoutput_request.hex()}"
        )

    prevmeta_request = message_payload(
        messages.TxRequest(
            request_type=messages.RequestType.TXMETA,
            details=messages.TxRequestDetailsType(tx_hash=prev_hash),
        )
    )
    if prevmeta_request.hex() != "0802122212201111111111111111111111111111111111111111111111111111111111111111":
        raise AssertionError(f"unexpected trezorlib BTC TxRequest prev TXMETA protobuf: {prevmeta_request.hex()}")

    txfinished_request = message_payload(messages.TxRequest(request_type=messages.RequestType.TXFINISHED))
    if txfinished_request.hex() != "0803":
        raise AssertionError(f"unexpected trezorlib BTC TxRequest(TXFINISHED) protobuf: {txfinished_request.hex()}")


def check_trezorlib_protocol_oracle(gate: Path, local_vectors: dict[str, str]) -> None:
    response_type, payload = run_local_wire_oracle(gate, messages.MessageType.Initialize, messages.Initialize())
    if response_type != messages.MessageType.Features:
        raise AssertionError(f"Initialize response type mismatch: {response_type}")
    features = protobuf.load_message(io.BytesIO(payload), messages.Features)
    if features.major_version not in (1, 2):
        raise AssertionError(f"Connect-incompatible Features.major_version: {features.major_version}")
    if features.firmware_present is not False and features.bootloader_mode is not None and features.bootloader_mode is not True:
        raise AssertionError(
            "Connect-incompatible Features shape: normal firmware mode must omit bootloader_mode=false"
        )
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
        (
            messages.InputScriptType.SPENDADDRESS,
            [0x8000002C, 0x80000001, 0x80000000, 0, 0],
            "Testnet",
            "btc_testnet_p2pkh_address",
        ),
        (
            messages.InputScriptType.SPENDWITNESS,
            [0x80000054, 0x80000001, 0x80000000, 0, 0],
            "Testnet",
            "btc_testnet_p2wpkh_address",
        ),
        (
            messages.InputScriptType.SPENDP2SHWITNESS,
            [0x80000031, 0x80000001, 0x80000000, 0, 0],
            "Testnet",
            "btc_testnet_p2sh_p2wpkh_address",
        ),
        (
            messages.InputScriptType.SPENDADDRESS,
            [0x8000002C, 0x80000000, 0x80000000, 0, 0],
            "Bitcoin",
            "btc_mainnet_p2pkh_address",
        ),
        (
            messages.InputScriptType.SPENDWITNESS,
            [0x80000054, 0x80000000, 0x80000000, 0, 0],
            "Bitcoin",
            "btc_mainnet_p2wpkh_address",
        ),
        (
            messages.InputScriptType.SPENDP2SHWITNESS,
            [0x80000031, 0x80000000, 0x80000000, 0, 0],
            "Bitcoin",
            "btc_mainnet_p2sh_p2wpkh_address",
        ),
    ]
    for script_type, address_n, coin_name, vector_key in btc_address_cases:
        response_type, payload = run_local_wire_oracle(
            gate,
            messages.MessageType.GetAddress,
            messages.GetAddress(
                address_n=address_n,
                coin_name=coin_name,
                show_display=False,
                script_type=script_type,
            ),
        )
        if response_type != messages.MessageType.Address:
            raise AssertionError(f"GetAddress response type mismatch for {coin_name}/{script_type}: {response_type}")
        btc_addr = protobuf.load_message(io.BytesIO(payload), messages.Address)
        if btc_addr.address != local_vectors[vector_key]:
            raise AssertionError(
                f"unexpected Bitcoin address response for {coin_name}/{script_type}: {btc_addr.address}"
            )

    btc_public_key_cases = [
        (
            "explicit",
            messages.InputScriptType.SPENDADDRESS,
            [0x8000002C, 0x80000001, 0x80000000],
            "Testnet",
            "tpub",
            bytes.fromhex("043587cf"),
        ),
        (
            "explicit",
            messages.InputScriptType.SPENDWITNESS,
            [0x80000054, 0x80000001, 0x80000000],
            "Testnet",
            "vpub",
            bytes.fromhex("045f1cf6"),
        ),
        (
            "sparrow-lark-default",
            messages.InputScriptType.SPENDADDRESS,
            [0x80000054, 0x80000001, 0x80000000],
            "Testnet",
            "vpub",
            bytes.fromhex("045f1cf6"),
        ),
        (
            "explicit",
            messages.InputScriptType.SPENDP2SHWITNESS,
            [0x80000031, 0x80000001, 0x80000000],
            "Testnet",
            "upub",
            bytes.fromhex("044a5262"),
        ),
        (
            "sparrow-lark-default",
            messages.InputScriptType.SPENDADDRESS,
            [0x80000031, 0x80000001, 0x80000000],
            "Testnet",
            "upub",
            bytes.fromhex("044a5262"),
        ),
        (
            "bip45-default",
            messages.InputScriptType.SPENDADDRESS,
            [0x8000002D],
            "Testnet",
            "tpub",
            bytes.fromhex("043587cf"),
        ),
        (
            "bip45-explicit-multisig",
            messages.InputScriptType.SPENDMULTISIG,
            [0x8000002D],
            "Bitcoin",
            "xpub",
            bytes.fromhex("0488b21e"),
        ),
        (
            "bip48-p2sh-p2wsh-default",
            messages.InputScriptType.SPENDADDRESS,
            [0x80000030, 0x80000001, 0x80000000, 0x80000001],
            "Testnet",
            "Upub",
            bytes.fromhex("024289ef"),
        ),
        (
            "bip48-p2sh-p2wsh-explicit-multisig",
            messages.InputScriptType.SPENDMULTISIG,
            [0x80000030, 0x80000000, 0x80000000, 0x80000001],
            "Bitcoin",
            "Ypub",
            bytes.fromhex("0295b43f"),
        ),
        (
            "bip48-p2wsh-default",
            messages.InputScriptType.SPENDADDRESS,
            [0x80000030, 0x80000001, 0x80000000, 0x80000002],
            "Testnet",
            "Vpub",
            bytes.fromhex("02575483"),
        ),
        (
            "bip48-p2wsh-explicit-multisig",
            messages.InputScriptType.SPENDMULTISIG,
            [0x80000030, 0x80000000, 0x80000000, 0x80000002],
            "Bitcoin",
            "Zpub",
            bytes.fromhex("02aa7ed3"),
        ),
        (
            "explicit",
            messages.InputScriptType.SPENDADDRESS,
            [0x8000002C, 0x80000000, 0x80000000],
            "Bitcoin",
            "xpub",
            bytes.fromhex("0488b21e"),
        ),
        (
            "explicit",
            messages.InputScriptType.SPENDWITNESS,
            [0x80000054, 0x80000000, 0x80000000],
            "Bitcoin",
            "zpub",
            bytes.fromhex("04b24746"),
        ),
        (
            "sparrow-lark-default",
            messages.InputScriptType.SPENDADDRESS,
            [0x80000054, 0x80000000, 0x80000000],
            "Bitcoin",
            "zpub",
            bytes.fromhex("04b24746"),
        ),
        (
            "explicit",
            messages.InputScriptType.SPENDP2SHWITNESS,
            [0x80000031, 0x80000000, 0x80000000],
            "Bitcoin",
            "ypub",
            bytes.fromhex("049d7cb2"),
        ),
        (
            "sparrow-lark-default",
            messages.InputScriptType.SPENDADDRESS,
            [0x80000031, 0x80000000, 0x80000000],
            "Bitcoin",
            "ypub",
            bytes.fromhex("049d7cb2"),
        ),
    ]
    for mode, script_type, address_n, coin_name, expected_prefix, expected_version in btc_public_key_cases:
        response_type, payload = run_local_wire_oracle(
            gate,
            messages.MessageType.GetPublicKey,
            messages.GetPublicKey(
                address_n=address_n,
                coin_name=coin_name,
                script_type=script_type,
            ),
        )
        if response_type != messages.MessageType.PublicKey:
            raise AssertionError(
                f"GetPublicKey response type mismatch for {coin_name}/{script_type}: {response_type}"
            )
        public_key = protobuf.load_message(io.BytesIO(payload), messages.PublicKey)
        if getattr(public_key.node, "private_key", None):
            raise AssertionError("PublicKey response unexpectedly contains private_key")
        if not public_key.xpub:
            raise AssertionError("PublicKey response missing xpub")
        if not public_key.xpub.startswith(expected_prefix):
            raise AssertionError(
                f"GetPublicKey {mode} {coin_name}/{script_type} xpub prefix mismatch: "
                f"expected {expected_prefix}, got {public_key.xpub[:4]}"
            )
        decoded_xpub = base58.b58decode_check(public_key.xpub)
        if len(decoded_xpub) != 78 or decoded_xpub[:4] != expected_version:
            raise AssertionError(
                f"GetPublicKey {mode} {coin_name}/{script_type} xpub version mismatch: "
                f"expected {expected_version.hex()}, got {decoded_xpub[:4].hex()}"
            )

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
        messages.MessageType.EthereumSignTypedHash,
        messages.EthereumSignTypedHash(
            address_n=eth_path,
            domain_separator_hash=bytes.fromhex(local_vectors["safe_domain_hash"]),
            message_hash=bytes.fromhex(local_vectors["safe_message_hash"]),
        ),
    )
    if response_type != 20119:
        raise AssertionError(f"EthereumSignTypedHash must request SafeTx payload, got {response_type}")
    if payload:
        raise AssertionError("EthereumGnosisSafeTxRequest payload must be empty")

    safe_typed_data = safe_usdt_transfer_typed_data()
    safe_signing_hash = bytes.fromhex(local_vectors["safe_signing_hash"])
    safe_signature = keys.PrivateKey(PRIVATE_KEY_ONE).sign_msg_hash(safe_signing_hash)
    safe_compact_signature = bytes([safe_signature.v + 27]) + int(safe_signature.r).to_bytes(32, "big") + int(
        safe_signature.s
    ).to_bytes(32, "big")
    safe_responses = run_local_raw_wire_script(
        gate,
        [
            (
                int(messages.MessageType.EthereumSignTypedHash),
                message_payload(
                    messages.EthereumSignTypedHash(
                        address_n=eth_path,
                        domain_separator_hash=bytes.fromhex(local_vectors["safe_domain_hash"]),
                        message_hash=bytes.fromhex(local_vectors["safe_message_hash"]),
                    )
                ),
            ),
            (ETHEREUM_GNOSIS_SAFE_TX_ACK_MESSAGE_TYPE, make_safe_tx_ack_payload(safe_typed_data)),
        ],
        eth_compact_signature=safe_compact_signature,
    )
    if safe_responses[0][0] != ETHEREUM_GNOSIS_SAFE_TX_REQUEST_MESSAGE_TYPE or safe_responses[0][1]:
        raise AssertionError(f"SafeTx first response mismatch: {safe_responses[0][0]}")
    if safe_responses[1][0] != ETHEREUM_TYPED_DATA_SIGNATURE_MESSAGE_TYPE:
        raise AssertionError(f"SafeTx signature response type mismatch: {safe_responses[1][0]}")
    typed_signature, typed_address = decode_typed_data_signature_payload(safe_responses[1][1])
    if len(typed_signature) != 65:
        raise AssertionError(f"SafeTx typed signature length mismatch: {len(typed_signature)}")
    if typed_address != local_vectors["eth_checksum_address"]:
        raise AssertionError(f"SafeTx typed signature address mismatch: {typed_address}")
    safe_recovered = keys.Signature(
        vrs=(
            typed_signature[64],
            int.from_bytes(typed_signature[:32], "big"),
            int.from_bytes(typed_signature[32:64], "big"),
        )
    ).recover_public_key_from_msg_hash(safe_signing_hash).to_checksum_address()
    if safe_recovered != local_vectors["eth_checksum_address"]:
        raise AssertionError(f"SafeTx signature recover mismatch: {safe_recovered}")

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

    psbt_payload = check_embit_psbt_oracle()
    response_type, payload = run_local_raw_wire_oracle(gate, ONEKEY_SIGN_PSBT_MESSAGE_TYPE, psbt_payload)
    if response_type != messages.MessageType.Failure:
        raise AssertionError(f"OneKey SignPsbt must be rejected until adapter policy exists: {response_type}")
    failure = protobuf.load_message(io.BytesIO(payload), messages.Failure)
    if failure.code != messages.FailureType.DataError:
        raise AssertionError(f"OneKey SignPsbt unexpected failure code: {failure.code}")


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
    check_embit_psbt_oracle()
    check_trezor_multisig_normalizer_oracle(gate)
    check_trezor_multisig_partial_oracle(gate)
    check_trezor_multisig_tx_structure_oracle(gate)
    check_local_btc_signtx_wire_script_oracle(gate)
    check_trezorlib_protocol_oracle(gate, local)
    print("PASS external_oracle_gates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
