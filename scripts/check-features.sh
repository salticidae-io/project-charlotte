#!/usr/bin/env bash
# Checks that every combination of the optional Cargo features compiles
# without warnings: first the server alone, which shows that a feature does
# not lean on something only the tests enable, then the tests with it.
#
# Usage: scripts/check-features.sh [extra cargo arguments, e.g. --locked]
set -euo pipefail

cd "$(dirname "$0")/.."

features=(acme hosting http3 proxy)
export RUSTFLAGS="${RUSTFLAGS:-} -D warnings"

failed=()
for mask in $(seq 0 $(((1 << ${#features[@]}) - 1))); do
    selected=()
    for index in "${!features[@]}"; do
        if (((mask >> index) & 1)); then
            selected+=("${features[index]}")
        fi
    done
    list=$(
        IFS=,
        echo "${selected[*]:-}"
    )
    echo "==> features: ${list:-(none)}"
    if ! cargo check --quiet --no-default-features --features "$list" "$@" ||
        ! cargo check --quiet --all-targets --no-default-features --features "$list" "$@"; then
        failed+=("${list:-(none)}")
    fi
done

if ((${#failed[@]})); then
    echo "feature combinations that failed:" >&2
    printf '  %s\n' "${failed[@]}" >&2
    exit 1
fi
echo "all $((1 << ${#features[@]})) feature combinations compile without warnings"
