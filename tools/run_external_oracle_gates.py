#!/usr/bin/env python3
"""Compare public local host-gate vectors with independent community libraries."""

from __future__ import annotations

import argparse
import hashlib
import io
import subprocess
import sys
from pathlib import Path

import base58
import rlp
from bech32 import bech32_encode, convertbits
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
        [
            9,
            20_000_000_000,
            21_000,
            to_address,
            1_000_000_000_000_000_000,
            b"",
            1,
            0,
            0,
        ]
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

    response_type, payload = run_local_wire_oracle(
        gate,
        messages.MessageType.SignTx,
        messages.SignTx(coin_name="Bitcoin", inputs_count=1, outputs_count=1),
    )
    if response_type != messages.MessageType.Failure:
        raise AssertionError(f"BTC SignTx must be rejected until fully implemented: {response_type}")
    failure = protobuf.load_message(io.BytesIO(payload), messages.Failure)
    if failure.code != messages.FailureType.UnexpectedMessage:
        raise AssertionError(f"BTC SignTx unexpected failure code: {failure.code}")


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

    check_trezorlib_protocol_oracle(gate, local)
    print("PASS external_oracle_gates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
