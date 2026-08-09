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
