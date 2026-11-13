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
cargo test --lib --quiet

# Rust target names use `::`, which is not supported in artifact paths on all
# platforms. The corpus store uses dots; test-fuzz still needs the original
# names under target/corpus.
safe() { printf '%s\n' "${1//::/.}"; }
restore() { printf '%s\n' "${1//./::}"; }

mkdir -p "$store" "$target_dir/corpus"

# Migrate corpora saved by older versions of this script, merging any existing
# entries before removing the legacy directory.
for legacy in "$store"/*; do
    [[ -d $legacy ]] || continue
    name=${legacy##*/}
    safe_name=$(safe "$name")
    [[ $safe_name != "$name" ]] || continue
    destination="$store/$safe_name"
    mkdir -p "$destination"
    cp -R "$legacy"/. "$destination"/
    rm -r -- "$legacy"
done

# Restore test-fuzz's expected `::` directory names when seeding its corpus.
for corpus in "$store"/*; do
    [[ -d $corpus ]] || continue
    name=${corpus##*/}
    target_name=$(restore "$name")
    target_corpus="$target_dir/corpus/$target_name"
    mkdir -p "$target_corpus"
    cp -R "$corpus"/. "$target_corpus"/
done

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
    safe_target=$(safe "$target")
    # Start from the corpus rather than a previous session's AFL state.
    cargo test-fuzz --exact "$target" --reset >/dev/null 2>&1 || true
    if ! cargo test-fuzz --exact "$target" --max-total-time "$seconds" --no-ui --exit-code \
        >"$target_dir/fuzz-$safe_target.log" 2>&1; then
        echo "    fuzzer failed; see $target_dir/fuzz-$safe_target.log" >&2
        failed+=("$target (fuzzer error)")
        continue
    fi

    output="$target_dir/afl/output/${crate}::$target/default"
    for kind in crashes hangs; do
        if compgen -G "$output/$kind/id*" >/dev/null; then
            mkdir -p "$findings/$safe_target/$kind"
            # AFL names inputs like `id:000000,sig:06,...`; drop the colons
            # so the findings can be uploaded as an artifact.
            for input in "$output/$kind"/id*; do
                base=${input##*/}
                cp "$input" "$findings/$safe_target/$kind/${base//:/_}"
            done
            failed+=("$target ($kind)")
        fi
    done

    # Keep the inputs that reached new coverage. They are named by content so
    # that repeated runs do not accumulate duplicates.
    saved=0
    safe_corpus=$(safe "$crate::$target")
    mkdir -p "$store/$safe_corpus"
    for input in "$output"/queue/id*; do
        [[ -f $input ]] || continue
        name=$(sha256sum "$input" | cut -c1-40)
        if [[ ! -e "$store/$safe_corpus/$name" ]]; then
            cp "$input" "$store/$safe_corpus/$name"
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
