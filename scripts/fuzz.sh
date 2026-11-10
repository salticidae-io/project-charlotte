#!/usr/bin/env bash
# Fuzz every test-fuzz target for a bounded time and keep what was learned.
#
#   scripts/fuzz.sh [SECONDS_PER_TARGET] [TARGET_SUBSTRING]
#
# Inputs AFL discovers are saved under fuzz/corpus/ and fed back into the next
# run, so coverage accumulates across runs and survives `cargo clean`. Crashes
# and hangs are copied to fuzz/findings/ and make the script exit non-zero.
set -euo pipefail
cd "$(dirname "$0")/.."

seconds="${1:-300}"
filter="${2:-}"
store=fuzz/corpus
findings=fuzz/findings
target_dir="${CARGO_TARGET_DIR:-target}"
crate=project_charlotte

# The seed tests record each target's starting corpus under target/corpus.
cargo test --bin project-charlotte --quiet

# Add the inputs saved by earlier runs.
mkdir -p "$store" "$target_dir/corpus"
cp -R "$store"/. "$target_dir/corpus"/

mapfile -t targets < <(
    cargo test-fuzz --list 2>&1 | grep -o '"[a-z0-9_:]*::tests::[a-z0-9_]*"' | tr -d '"'
)
if [[ ${#targets[@]} -eq 0 ]]; then
    echo "no fuzz targets found; is cargo-test-fuzz installed?" >&2
    exit 2
fi

failed=()
for target in "${targets[@]}"; do
    if [[ -n $filter && $target != *"$filter"* ]]; then
        continue
    fi
    echo "==> $target (${seconds}s)"
    # Start from the corpus rather than a previous session's AFL state.
    cargo test-fuzz --exact "$target" --reset >/dev/null 2>&1 || true
    if ! cargo test-fuzz --exact "$target" --max-total-time "$seconds" --no-ui --exit-code \
        >"$target_dir/fuzz-$target.log" 2>&1; then
        echo "    fuzzer failed; see $target_dir/fuzz-$target.log" >&2
        failed+=("$target (fuzzer error)")
        continue
    fi

    output="$target_dir/afl/output/${crate}::$target/default"
    for kind in crashes hangs; do
        if compgen -G "$output/$kind/id*" >/dev/null; then
            mkdir -p "$findings/$target/$kind"
            cp "$output/$kind"/id* "$findings/$target/$kind"/
            failed+=("$target ($kind)")
        fi
    done

    # Keep the inputs that reached new coverage. They are named by content so
    # that repeated runs do not accumulate duplicates.
    saved=0
    mkdir -p "$store/${crate}::$target"
    for input in "$output"/queue/id*; do
        [[ -f $input ]] || continue
        name=$(sha256sum "$input" | cut -c1-40)
        if [[ ! -e "$store/${crate}::$target/$name" ]]; then
            cp "$input" "$store/${crate}::$target/$name"
            saved=$((saved + 1))
        fi
    done
    execs=$(sed -n 's/^execs_done *: //p' "$output/fuzzer_stats" 2>/dev/null || true)
    echo "    ${execs:-?} execs, $saved new corpus entries"
done

if [[ ${#failed[@]} -gt 0 ]]; then
    echo
    echo "Findings (inputs under $findings/):" >&2
    printf '  %s\n' "${failed[@]}" >&2
    exit 1
fi
echo
echo "No crashes or hangs."
