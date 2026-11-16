# syntax=docker/dockerfile:1.7
#
# Starter VM template for `/demo`. The base image already ships Chromium,
# Node.js, xterm, a window manager, and an ffmpeg recorder configured for
# the demo agent. The project root is mounted at /workspace inside the
# running VM.
#
# Add extra language runtimes or system packages as your app needs.
#
# Full docs: https://junie.jetbrains.com/docs/junie-cli-demo.html
FROM registry.jetbrains.team/p/junie-cli/containers/demo-base:2

USER root
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ca-certificates clang cmake curl git \
      libmodsecurity-dev libnss3-tools pebble pkg-config php-cgi \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.cargo/bin:${PATH}"
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain stable

WORKDIR /build
COPY . /build
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release \
    && install -D target/release/project-charlotte /usr/local/bin/project-charlotte \
    && install -D target/release/charlotte-ctl /usr/local/bin/charlotte-ctl \
    && install -D target/release/apache2charlotte /usr/local/bin/apache2charlotte \
    && install -D target/release/nginx2charlotte /usr/local/bin/nginx2charlotte

WORKDIR /workspace
