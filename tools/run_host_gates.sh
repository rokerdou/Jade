#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${1:-build-tdisplays3-hardened-ok}"
oracle_venv="${repo_root}/.host-oracle-venv"

cd "$repo_root"

run_external_oracle_gates() {
    local requirements="${repo_root}/tools/host_oracle_requirements.txt"
    local requirements_stamp="${oracle_venv}/.requirements.sha256"
    local requirements_hash
    requirements_hash="$(shasum -a 256 "$requirements" | awk '{print $1}')"

    if [[ ! -x "${oracle_venv}/bin/python" ]]; then
        python3 -m venv "$oracle_venv"
        "${oracle_venv}/bin/python" -m pip install --upgrade pip >/dev/null
    fi
    if [[ ! -f "$requirements_stamp" ]] || [[ "$(cat "$requirements_stamp")" != "$requirements_hash" ]]; then
        "${oracle_venv}/bin/python" -m pip install -r "$requirements"
        printf '%s' "$requirements_hash" >"$requirements_stamp"
    fi
    "${oracle_venv}/bin/python" tools/run_external_oracle_gates.py --build-dir "$build_dir"
}

if [[ "${2:-}" == "--no-build" ]]; then
    "./${build_dir}/eth_tron_address_gate"
    echo "PASS eth_tron_address_gate"
    "./${build_dir}/wallet_core_public_node_gate"
    echo "PASS wallet_core_public_node_gate"
    run_external_oracle_gates
    exit 0
fi

if [[ -f "${HOME}/esp/esp-idf/export.sh" ]]; then
    # shellcheck source=/dev/null
    . "${HOME}/esp/esp-idf/export.sh" >/dev/null
fi

idf.py \
    -B "$build_dir" \
    -D "SDKCONFIG=${build_dir}/sdkconfig" \
    -D SDKCONFIG_DEFAULTS=configs/sdkconfig_display_ttgo_tdisplays3_hardened.defaults \
    eth_tron_address_gate wallet_core_public_node_gate

"./${build_dir}/eth_tron_address_gate"
echo "PASS eth_tron_address_gate"
"./${build_dir}/wallet_core_public_node_gate"
echo "PASS wallet_core_public_node_gate"
run_external_oracle_gates
