#!/bin/bash
set -uo pipefail

check_status() {
    local rc=$1
    local msg=$2
    if [ "$rc" -ne 0 ]; then
        echo "Error: $msg"
        exit 1
    fi
}

if [[ -z "${1:-}" ]]; then
    echo "Error: cpu_model parameter is required."
    echo "Usage: $0 <cpu_model> [vmpl] [expected_measurement_hex]"
    echo "  vmpl: optional, request a report at this VMPL via"
    echo "        'snpguest report --vmpl <vmpl>'."
    echo "  expected_measurement_hex: optional, 96 hex chars (48 bytes)"
    echo "        of the expected SNP launch measurement."
    exit 1
fi

cpu_model="$1"
vmpl="${2:-}"
expected_measurement="${3:-}"

case "$cpu_model" in
    milan|genoa|bergamo|siena|turin) ;;
    *)
        echo "Error: unsupported cpu_model '$cpu_model'."
        echo "       Allowed: milan, genoa, bergamo, siena, turin."
        exit 1 ;;
esac

report_extra_args=()
if [[ -n "$vmpl" ]]; then
    if [[ ! "$vmpl" =~ ^[0-9]+$ ]]; then
        echo "Error: vmpl must be a non-negative integer (got: '$vmpl')."
        echo "       Allowed values: 0, 1, 2, or 3."
        exit 1
    fi
    if (( 10#$vmpl > 3 )); then
        echo "Error: vmpl out of range (got: $vmpl)."
        echo "       SNP defines only VMPL0..VMPL3."
        exit 1
    fi
    report_extra_args=(--vmpl "$vmpl")
fi

if [[ -n "$expected_measurement" ]]; then
    expected_measurement="$(echo -n "$expected_measurement" \
        | tr -d '[:space:]' | tr 'A-F' 'a-f')"
    if [[ ! "$expected_measurement" =~ ^[0-9a-f]{96}$ ]]; then
        echo "Error: expected_measurement must be exactly 96 hex chars"
        echo "       (48 bytes / SHA-384). Got ${#expected_measurement} chars."
        exit 1
    fi
fi

fetch_retry() {
    local max_retries=3
    local retry_count=0

    while (( retry_count < max_retries )); do
        "$@" && return 0
        retry_count=$((retry_count + 1))
        echo "Command '$*' failed. Retry $retry_count/$max_retries in 20s..." >&2
        sleep 20
    done
    echo "Command '$*' failed after $max_retries attempts." >&2
    return 1
}

# Verify regular attestation workflow on snp guest
snpguest report attestation-report.bin request-data.txt --random "${report_extra_args[@]}"
check_status "$?" "snpguest report failed."
if [[ ! -f attestation-report.bin ]]; then
    echo "attestation-report.bin not created."
    exit 1
fi
snpguest display report attestation-report.bin
check_status "$?" "Failed display attestation-report."

# Fetch cert
fetch_retry snpguest fetch ca -e vcek pem ./ "$cpu_model"
check_status "$?" "Failed to fetch CA certificate."

fetch_retry snpguest fetch vcek -p "$cpu_model" pem ./ attestation-report.bin
check_status "$?" "Failed to fetch VCEK certificate."

# Verify certs
snpguest verify certs ./
check_status "$?" "Failed to verify certificates."
snpguest verify attestation -p "$cpu_model" ./ attestation-report.bin
check_status "$?" "Failed to verify attestation."

if [[ -n "$expected_measurement" ]]; then
    if ! command -v xxd >/dev/null 2>&1; then
        echo "Error: 'xxd' is required to extract MEASUREMENT from"
        echo "       attestation-report.bin but was not found on PATH."
        exit 1
    fi
    actual_measurement="$(xxd -s 0x90 -l 48 -p attestation-report.bin \
        | tr -d '[:space:]' | tr 'A-F' 'a-f')"
    if [[ ! "$actual_measurement" =~ ^[0-9a-f]{96}$ ]]; then
        echo "Error: could not extract a 96-hex-char MEASUREMENT from"
        echo "       attestation-report.bin (offset 0x90, 48 bytes)."
        echo "       Got: '${actual_measurement}'"
        exit 1
    fi
    if [[ "$actual_measurement" != "$expected_measurement" ]]; then
        echo "Error: SNP MEASUREMENT mismatch."
        echo "       expected: $expected_measurement"
        echo "       actual:   $actual_measurement"
        echo "       The report came from a genuine AMD SNP CPU, but the"
        echo "       launch measurement does not match the firmware"
        echo "       build this test was configured for."
        exit 1
    fi
    echo "SNP MEASUREMENT matches the expected launch digest:"
    echo "       $actual_measurement"
fi
