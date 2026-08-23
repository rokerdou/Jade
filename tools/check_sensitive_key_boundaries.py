#!/usr/bin/env python3
"""Gate sensitive key access in multichain protocol code.

Chain/protocol modules run on host-supplied data. They may derive public data
or ask wallet_core to sign an already reviewed digest, but they must not touch
seed, mnemonic, xpriv, or raw private-key derivation/signing APIs directly.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

SCAN_ROOTS = (
    REPO_ROOT / "main" / "chains",
    REPO_ROOT / "main" / "protocols" / "trezor",
)

FORBIDDEN_PATTERNS = (
    ("direct keychain access", re.compile(r"\bkeychain_get\s*\(")),
    ("direct keychain derivation/cache", re.compile(r"\bkeychain_(derive|get_new_mnemonic|cache_mnemonic_entropy)\b")),
    ("direct HD key derivation", re.compile(r"\bwallet_get_hdkey\s*\(")),
    ("private BIP32 derivation flag", re.compile(r"\bBIP32_FLAG_KEY_PRIVATE\b")),
    ("direct private-key ECDSA signing", re.compile(r"\bwally_ec_sig_from_bytes\s*\(")),
    ("raw sensitive material name", re.compile(r"\b(private_key|xpriv|mnemonic|seed)\b", re.IGNORECASE)),
)

STRONG_RANDOM_REQUIRED_PATTERNS = (
    (
        REPO_ROOT / "main" / "keychain.c",
        "legacy BIP39 mnemonic entropy",
        re.compile(r"void\s+keychain_get_new_mnemonic\b.*?get_strong_random\s*\(\s*entropy\s*,\s*entropy_len\s*\)", re.S),
    ),
    (
        REPO_ROOT / "main" / "keychain.c",
        "new secp256k1 private key",
        re.compile(r"bool\s+keychain_get_new_privatekey\b.*?get_strong_random\s*\(\s*privatekey\s*,\s*size\s*\)", re.S),
    ),
)

WALLET_ENTROPY_REQUIRED_PATTERNS = (
    (
        REPO_ROOT / "main" / "wallet_entropy.c",
        "wallet creation system entropy must use raw HWRNG helper",
        re.compile(r"bool\s+wallet_entropy_system_256\b.*?get_hardware_random\s*\(\s*entropy\s*,\s*WALLET_ENTROPY_256_LEN\s*\)", re.S),
    ),
    (
        REPO_ROOT / "main" / "wallet_entropy.c",
        "standard wallet entropy must copy system entropy directly",
        re.compile(r"bool\s+wallet_entropy_standard\b.*?memcpy\s*\(\s*final_entropy\s*,\s*system_entropy\s*,\s*WALLET_ENTROPY_256_LEN\s*\)", re.S),
    ),
    (
        REPO_ROOT / "main" / "wallet_entropy.c",
        "enhanced wallet entropy must XOR system and dice entropy without replacing the result with a hash",
        re.compile(r"final_entropy\s*\[\s*i\s*\]\s*=\s*system_entropy\s*\[\s*i\s*\]\s*\^\s*user_entropy\s*\[\s*i\s*\]", re.S),
    ),
    (
        REPO_ROOT / "main" / "wallet_entropy.c",
        "dice entropy domain separation must be stable",
        re.compile(r'WALLET_DICE_DOMAIN\[\]\s*=\s*"WALLET_DICE_V1"'),
    ),
)

RPC_CONFIRMATION_REQUIRED_PATTERNS = (
    (
        REPO_ROOT / "main" / "process" / "sign_message.c",
        "message signing, including GDK login challenges, must require on-device confirmation",
        re.compile(
            r"isGdkLoginChallenge\b.*?GDK login challenge requires user confirmation.*?"
            r"confirm_sign_message\s*\(.*?wallet_sign_message_hash\s*\(",
            re.S,
        ),
    ),
    (
        REPO_ROOT / "main" / "process" / "get_identity_shared_key.c",
        "identity shared key export must require on-device confirmation",
        re.compile(r"await_yesno_activity\s*\(.*?get_identity_shared_key\s*\(", re.S),
    ),
    (
        REPO_ROOT / "main" / "process" / "get_master_blinding_key.c",
        "master blinding key export must always require on-device confirmation",
        re.compile(r"only_if_silent\s*\|\|\s*!\s*await_yesno_activity\s*\(", re.S),
    ),
    (
        REPO_ROOT / "main" / "process" / "get_xpubs.c",
        "xpub export must require on-device confirmation",
        re.compile(r"await_yesno_activity\s*\(.*?wallet_get_xpub\s*\(", re.S),
    ),
    (
        REPO_ROOT / "main" / "process" / "sign_identity.c",
        "identity signing must require on-device confirmation",
        re.compile(r"show_sign_identity_activity\s*\(.*?sign_identity\s*\(", re.S),
    ),
    (
        REPO_ROOT / "main" / "process" / "sign_bip85_digest.c",
        "BIP85 RSA digest signing must require on-device confirmation",
        re.compile(r"await_yesno_activity\s*\(.*?rsa_bip85_key_sign_digests\s*\(", re.S),
    ),
    (
        REPO_ROOT / "main" / "process" / "get_bip85_entropy.c",
        "BIP85 BIP39 entropy export must require on-device confirmation before derivation",
        re.compile(r"await_continueback_activity\s*\(.*?get_encrypted_bip85_bip39_entropy\s*\(", re.S),
    ),
    (
        REPO_ROOT / "main" / "process" / "get_bip85_entropy.c",
        "BIP85 RSA entropy export must require on-device confirmation before derivation",
        re.compile(r"await_continueback_activity\s*\(.*?get_encrypted_bip85_rsa_entropy\s*\(", re.S),
    ),
    (
        REPO_ROOT / "main" / "process" / "get_bip85_entropy.c",
        "BIP85 exported entropy must be encrypted with ECDH/AES before leaving the device",
        re.compile(
            r"get_encrypted_bip85_bip39_entropy\b.*?wally_aes_cbc_with_ecdh_key.*?"
            r"get_encrypted_bip85_rsa_entropy\b.*?wally_aes_cbc_with_ecdh_key",
            re.S,
        ),
    ),
)

TREZOR_SESSION_REQUIRED_PATTERNS = (
    (
        REPO_ROOT / "main" / "protocols" / "trezor" / "session.c",
        "pending Trezor calls must reject unrelated messages until the expected ACK/TxAck arrives",
        re.compile(
            r"trezor_session_pending_accepts\b.*?TREZOR_MSG_BUTTON_ACK.*?TREZOR_MSG_ETHEREUM_TX_ACK.*?"
            r"TREZOR_MSG_ETHEREUM_GNOSIS_SAFE_TX_ACK.*?TREZOR_MSG_TX_ACK.*?"
            r"Other call in progress",
            re.S,
        ),
    ),
    (
        REPO_ROOT / "main" / "protocols" / "trezor" / "session.c",
        "GetEntropy must be a local-confirmed two-step flow, not immediate USB output",
        re.compile(
            r"request_type\s*==\s*TREZOR_MSG_GET_ENTROPY.*?has_pending_get_entropy\s*=\s*true.*?"
            r"trezor_session_button_request_payload",
            re.S,
        ),
    ),
)

WALLET_CORE_LOCK_REQUIRED_PATTERNS = (
    (
        REPO_ROOT / "main" / "wallet_core" / "wallet_core.c",
        "wallet_core must initialize and use the keychain serialization lock",
        re.compile(r"void\s+wallet_core_init\b.*?keychain_lock\s*\(\s*\).*?keychain_unlock\s*\(\s*\)", re.S),
    ),
    (
        REPO_ROOT / "main" / "wallet_core" / "wallet_core.c",
        "recoverable digest signing must run inside the wallet_core/keychain lock",
        re.compile(
            r"wallet_core_sign_digest_ecdsa_recoverable\b.*?wallet_core_lock\s*\(\s*\).*?"
            r"wally_ec_sig_from_bytes.*?wallet_core_unlock\s*\(\s*\)",
            re.S,
        ),
    ),
    (
        REPO_ROOT / "main" / "keychain.c",
        "keychain load/store/clear/set must use the shared keychain lock",
        re.compile(
            r"void\s+keychain_set\b.*?keychain_lock\s*\(\s*\).*?keychain_unlock\s*\(\s*\).*?"
            r"void\s+keychain_clear\b.*?keychain_lock\s*\(\s*\).*?keychain_unlock\s*\(\s*\).*?"
            r"bool\s+keychain_store\b.*?keychain_lock\s*\(\s*\).*?keychain_unlock\s*\(\s*\).*?"
            r"bool\s+keychain_load\b.*?keychain_lock\s*\(\s*\).*?keychain_unlock\s*\(\s*\)",
            re.S,
        ),
    ),
)

SIGNING_CONFIRMATION_REQUIRED_PATTERNS = (
    (
        REPO_ROOT / "main" / "chains" / "ethereum" / "sign.c",
        "ETH transaction signing must authorize/display the normalized request before wallet_core signing",
        re.compile(
            r"ethereum_sign_tx_ex\b.*?ethereum_authorize_tx_ex\s*\(.*?"
            r"ethereum_tx_build_authorized_digest\s*\(.*?"
            r"wallet_core_sign_digest_ecdsa_recoverable\s*\(",
            re.S,
        ),
    ),
    (
        REPO_ROOT / "main" / "protocols" / "trezor" / "wallet_adapter.c",
        "Safe transaction signing must display and bind the structured SafeTx summary before wallet_core signing",
        re.compile(
            r"trezor_wallet_sign_eth_safe_tx\b.*?ethereum_safe_tx_confirm_summary_from_preflight\s*\(.*?"
            r"show_chain_confirm_summary_activity_ex\s*\(.*?"
            r"ethereum_safe_tx_confirm_summary_matches_preflight\s*\(.*?"
            r"wallet_core_sign_digest_ecdsa_recoverable\s*\(",
            re.S,
        ),
    ),
    (
        REPO_ROOT / "main" / "protocols" / "trezor" / "session.c",
        "BTC signing must build and bind the confirm request before sign_btc_digest",
        re.compile(
            r"trezor_bitcoin_signing_to_confirm_request\s*\(.*?"
            r"session->confirm_btc_tx\s*\(.*?"
            r"trezor_bitcoin_confirm_request_matches_state\s*\(.*?"
            r"session->sign_btc_digest\s*\(",
            re.S,
        ),
    ),
    (
        REPO_ROOT / "main" / "protocols" / "trezor" / "session.c",
        "BTC multisig signing must build and bind the multisig confirm request before sign_btc_digest",
        re.compile(
            r"trezor_bitcoin_signing_to_multisig_confirm_request\s*\(.*?"
            r"session->confirm_btc_tx\s*\(.*?"
            r"trezor_bitcoin_multisig_confirm_request_matches_state\s*\(.*?"
            r"session->sign_btc_digest\s*\(",
            re.S,
        ),
    ),
)

HOST_UI_REQUIRED_PATTERNS = (
    (
        REPO_ROOT / "main" / "chains" / "ethereum" / "sign.c",
        "host-triggered ETH signing must pass managed-activity cleanup through the authorization flow",
        re.compile(
            r"ethereum_sign_tx_ex\b.*?ethereum_authorize_tx_ex\s*\(\s*&trusted_request\s*,\s*&authorization\s*,"
            r"\s*free_managed_activities\s*\)",
            re.S,
        ),
    ),
    (
        REPO_ROOT / "main" / "protocols" / "trezor" / "wallet_adapter.c",
        "Trezor ETH signing must enable managed-activity cleanup for confirmation UI",
        re.compile(r"ethereum_sign_tx_ex\s*\(\s*request\s*,\s*signature\s*,\s*true\s*\)", re.S),
    ),
    (
        REPO_ROOT / "main" / "protocols" / "trezor" / "wallet_adapter.c",
        "Trezor SafeTx signing must enable managed-activity cleanup for confirmation UI",
        re.compile(r"trezor_wallet_sign_eth_safe_tx\b.*?show_chain_confirm_summary_activity_ex\s*\(\s*&summary\s*,\s*true\s*\)", re.S),
    ),
    (
        REPO_ROOT / "main" / "protocols" / "trezor" / "wallet_adapter.c",
        "Trezor BTC signing must enable managed-activity cleanup for confirmation UI",
        re.compile(r"trezor_wallet_confirm_btc_tx\b.*?show_chain_confirm_summary_activity_ex\s*\(\s*&summary\s*,\s*true\s*\)", re.S),
    ),
    (
        REPO_ROOT / "main" / "protocols" / "trezor" / "wallet_adapter.c",
        "Trezor GetEntropy must require managed local confirmation and use the hardware RNG helper",
        re.compile(
            r"trezor_wallet_get_entropy\b.*?await_yesno_activity_ex\s*\(.*?,\s*true\s*\).*?"
            r"get_hardware_random\s*\(\s*entropy\s*,\s*size\s*\)",
            re.S,
        ),
    ),
)

DEBUG_SURFACE_REQUIRED_PATTERNS = (
    (
        REPO_ROOT / "main" / "CMakeLists.txt",
        "Trezor USB HID builds must not allow debug RPC handlers",
        re.compile(r"CONFIG_TREZOR_USB_HID\s+AND\s+CONFIG_DEBUG_MODE.*?FATAL_ERROR", re.S),
    ),
    (
        REPO_ROOT / "main" / "process" / "dashboard.c",
        "debug RPC dispatch must be compiled only in CONFIG_DEBUG_MODE",
        re.compile(
            r"#ifdef\s+CONFIG_DEBUG_MODE.*?IS_METHOD\s*\(\s*\"debug_set_mnemonic\"\s*\).*?"
            r"IS_METHOD\s*\(\s*\"debug_handshake\"\s*\).*?#endif\s*//\s*CONFIG_DEBUG_MODE",
            re.S,
        ),
    ),
    (
        REPO_ROOT / "main" / "process" / "debug_set_mnemonic.c",
        "debug_set_mnemonic must not compile outside CONFIG_DEBUG_MODE",
        re.compile(r"#ifdef\s+CONFIG_DEBUG_MODE.*?void\s+debug_set_mnemonic_process\b", re.S),
    ),
    (
        REPO_ROOT / "main" / "process" / "debug_handshake.c",
        "debug_handshake must not compile outside CONFIG_DEBUG_MODE",
        re.compile(r"#ifdef\s+CONFIG_DEBUG_MODE.*?void\s+debug_handshake\b", re.S),
    ),
    (
        REPO_ROOT / "configs" / "sdkconfig_display_ttgo_tdisplays3_hardened.defaults",
        "T-Display-S3 hardened defaults must keep debug mode disabled",
        re.compile(r"#\s*CONFIG_DEBUG_MODE\s+is\s+not\s+set"),
    ),
    (
        REPO_ROOT / "configs" / "sdkconfig_display_ttgo_tdisplays3_hardened.defaults",
        "T-Display-S3 hardened defaults must keep Bluetooth disabled",
        re.compile(r"#\s*CONFIG_BT_ENABLED\s+is\s+not\s+set"),
    ),
    (
        REPO_ROOT / "main" / "process" / "dashboard.c",
        "raw BIP85 entropy RPC dispatch must stay debug-only",
        re.compile(
            r"#ifdef\s+CONFIG_DEBUG_MODE.*?IS_METHOD\s*\(\s*\"get_bip85_bip39_entropy\"\s*\).*?"
            r"IS_METHOD\s*\(\s*\"get_bip85_rsa_entropy\"\s*\).*?#endif\s*//\s*CONFIG_DEBUG_MODE",
            re.S,
        ),
    ),
)

CAPABILITY_REQUIRED_PATTERNS = (
    (
        REPO_ROOT / "main" / "protocols" / "trezor" / "wallet_adapter.c",
        "Trezor Features must not advertise TRON until the USB signing flow has parser/UI/signature binding gates",
        re.compile(
            r"\.capabilities\s*=\s*\{\s*TREZOR_CAPABILITY_BITCOIN\s*,\s*"
            r"TREZOR_CAPABILITY_BITCOIN_LIKE\s*,\s*TREZOR_CAPABILITY_ETHEREUM\s*\}\s*,\s*"
            r"\.capabilities_len\s*=\s*3\s*,",
            re.S,
        ),
    ),
)

FORBIDDEN_FILE_PATTERNS = (
    (
        REPO_ROOT / "main" / "protocols" / "trezor" / "wallet_adapter.c",
        "Trezor Features must not expose unfinished TRON capability",
        re.compile(r"\bTREZOR_CAPABILITY_TRON\b"),
    ),
)

ALLOWED_WALLET_CORE_SIGN_CALLS = {
    REPO_ROOT / "main" / "chains" / "ethereum" / "sign.c",
    REPO_ROOT / "main" / "protocols" / "trezor" / "wallet_adapter.c",
}

FORBIDDEN_LARGE_STACK_PATTERNS = (
    (
        REPO_ROOT / "main" / "protocols" / "trezor",
        "large Trezor signing state must live in session/static storage, not the HID/session task stack",
        re.compile(
            r"^(?!\s*(?:static|typedef)\b)\s*"
            r"(?:trezor_bitcoin_signed_tx_t|trezor_bitcoin_signing_state_t|"
            r"trezor_ethereum_signing_state_t)\s+\w+\s*(?:=|;|\[)",
            re.M,
        ),
    ),
)


def iter_source_files() -> list[Path]:
    files: list[Path] = []
    for root in SCAN_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.suffix in {".c", ".h"}:
                files.append(path)
    return sorted(files)


def main() -> int:
    violations: list[str] = []
    for path in iter_source_files():
        rel_path = path.relative_to(REPO_ROOT)
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            violations.append(f"{rel_path}: failed to read: {exc}")
            continue

        for line_no, line in enumerate(lines, 1):
            for label, pattern in FORBIDDEN_PATTERNS:
                if pattern.search(line):
                    violations.append(f"{rel_path}:{line_no}: {label}: {line.strip()}")

    for path, label, pattern in (
        STRONG_RANDOM_REQUIRED_PATTERNS + WALLET_ENTROPY_REQUIRED_PATTERNS + RPC_CONFIRMATION_REQUIRED_PATTERNS
        + TREZOR_SESSION_REQUIRED_PATTERNS + WALLET_CORE_LOCK_REQUIRED_PATTERNS
        + SIGNING_CONFIRMATION_REQUIRED_PATTERNS + HOST_UI_REQUIRED_PATTERNS + DEBUG_SURFACE_REQUIRED_PATTERNS
        + CAPABILITY_REQUIRED_PATTERNS
    ):
        rel_path = path.relative_to(REPO_ROOT)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            violations.append(f"{rel_path}: failed to read: {exc}")
            continue
        if not pattern.search(text):
            violations.append(f"{rel_path}: sensitive boundary gate: {label}")

    for path, label, pattern in FORBIDDEN_FILE_PATTERNS:
        rel_path = path.relative_to(REPO_ROOT)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            violations.append(f"{rel_path}: failed to read: {exc}")
            continue
        if pattern.search(text):
            violations.append(f"{rel_path}: sensitive boundary gate: {label}")

    for path in iter_source_files():
        if path in ALLOWED_WALLET_CORE_SIGN_CALLS:
            continue
        rel_path = path.relative_to(REPO_ROOT)
        text = path.read_text(encoding="utf-8", errors="replace")
        if re.search(r"\bwallet_core_sign_digest_ecdsa_recoverable\s*\(", text):
            violations.append(f"{rel_path}: wallet_core signer call is not in the explicit confirmation allowlist")

    for root, label, pattern in FORBIDDEN_LARGE_STACK_PATTERNS:
        if not root.exists():
            violations.append(f"{root.relative_to(REPO_ROOT)}: sensitive boundary gate: {label}")
            continue
        for path in sorted(root.rglob("*")):
            if path.suffix != ".c":
                continue
            rel_path = path.relative_to(REPO_ROOT)
            text = path.read_text(encoding="utf-8", errors="replace")
            for match in pattern.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                violations.append(f"{rel_path}:{line_no}: {label}: {match.group(0).strip()}")

    if violations:
        print("FAIL sensitive key boundary gate")
        print()
        print("Chain/protocol code must not access raw key material directly.")
        print("Use wallet_core public-key helpers or wallet_core_sign_digest_ecdsa_recoverable()")
        print("after chain parsing and on-device confirmation.")
        print()
        print("\n".join(violations))
        return 1

    print("PASS sensitive key boundary gate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
