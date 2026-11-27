#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 deps|test" >&2
    exit 2
}

install_dependencies() {
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            build-essential \
            ca-certificates \
            curl \
            dpkg-dev \
            git \
            libmodsecurity-dev \
            modsecurity-crs \
            php-cgi \
            pkg-config \
            passwd \
            python3 \
            sudo \
            util-linux
    elif command -v dnf >/dev/null 2>&1; then
        dnf -y install epel-release dnf-plugins-core
        dnf config-manager --set-enabled crb
        dnf -y install \
            ca-certificates \
            gcc \
            gcc-c++ \
            git \
            libmodsecurity-devel \
            make \
            mod_security_crs \
            php-cli \
            php-opcache \
            pkgconf-pkg-config \
            python3 \
            rpm-build \
            shadow-utils \
            sudo \
            util-linux
    else
        echo "Unsupported package manager; expected apt-get or dnf" >&2
        exit 1
    fi
}

run_tests() {
    local user=charlotte-ci
    local home=/home/$user
    local repo
    local test_workspace
    local test_repo
    local target_dir
    repo="$(pwd -P)"

    if [ "$(id -u)" -ne 0 ]; then
        echo "The test command must run as root so it can create the unprivileged test user" >&2
        exit 1
    fi

    if ! id "$user" >/dev/null 2>&1; then
        useradd --create-home --shell /bin/bash "$user"
    fi

    test_workspace="$(mktemp -d "$home/workspace.XXXXXX")"
    test_repo="$test_workspace/project-charlotte"
    mkdir -p "$test_repo"
    tar --exclude=target -C "$repo" -cf - . | tar -C "$test_repo" -xf -
    if [ -d "$repo/../modsecurity-rs" ]; then
        mkdir -p "$test_workspace/modsecurity-rs"
        tar --exclude=target -C "$repo/../modsecurity-rs" -cf - . | tar -C "$test_workspace/modsecurity-rs" -xf -
    fi
    chown -R "$user:$user" "$test_workspace"

    target_dir="${CARGO_TARGET_DIR:-$test_repo/target}"
    mkdir -p "$target_dir"
    chown -R "$user:$user" "$target_dir"

    local user_path="$home/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
        runuser -u "$user" -- env HOME="$home" CARGO_HOME="$home/.cargo" RUSTUP_HOME="$home/.rustup" PATH="$user_path" \
            sh -s -- -y --profile minimal --default-toolchain stable

    runuser -u "$user" -- env HOME="$home" CARGO_HOME="$home/.cargo" RUSTUP_HOME="$home/.rustup" PATH="$user_path" \
        "$home/.cargo/bin/cargo" install cargo-nextest --locked
    runuser -u "$user" -- env HOME="$home" CARGO_HOME="$home/.cargo" RUSTUP_HOME="$home/.rustup" PATH="$user_path" \
        CARGO_TARGET_DIR="$target_dir" "$home/.cargo/bin/cargo" nextest run --locked --profile ci --manifest-path "$test_repo/Cargo.toml"
}

case "${1:-}" in
    deps)
        install_dependencies
        ;;
    test)
        run_tests
        ;;
    *)
        usage
        ;;
esac