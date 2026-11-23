#!/usr/bin/env bash
# Build Debian packages for Ubuntu 22.04 (jammy) inside an ubuntu:22.04
# container, so the binaries link against jammy's glibc and libmodsecurity3.
#
# Usage: scripts/build-deb-jammy.sh [cargo-deb args...]
#   e.g. scripts/build-deb-jammy.sh --variant proxy
#
# Output: target/jammy/debian/*.deb
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
engine="${CONTAINER_ENGINE:-docker}"
image="${JAMMY_IMAGE:-ubuntu:22.04}"
cache="${root}/target/jammy-cache"
mkdir -p "${cache}/cargo" "${cache}/rustup"

"${engine}" run --rm \
    -v "${root}:/src" \
    -v "${cache}/cargo:/cargo" \
    -v "${cache}/rustup:/rustup" \
    -e CARGO_HOME=/cargo \
    -e RUSTUP_HOME=/rustup \
    -e CARGO_TARGET_DIR=/src/target/jammy \
    -e DEBIAN_FRONTEND=noninteractive \
    -e HOST_UID="$(id -u)" \
    -e HOST_GID="$(id -g)" \
    -w /src \
    "${image}" \
    bash -euo pipefail -c '
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends \
            ca-certificates curl build-essential pkg-config \
            libmodsecurity-dev dpkg-dev >/dev/null
        export PATH=/cargo/bin:$PATH
        if ! command -v rustup >/dev/null; then
            curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path
        fi
        rustup toolchain install stable --profile minimal >/dev/null
        rustup default stable >/dev/null
        command -v cargo-deb >/dev/null || cargo install --locked cargo-deb
        cargo deb --locked "$@"
        chown -R "$HOST_UID:$HOST_GID" /src/target/jammy /cargo /rustup
    ' build-deb-jammy "$@"

ls -1 "${root}"/target/jammy/debian/*.deb
