# shellcheck shell=sh
# CI and image tool pins. Contributors keep rust-toolchain.toml's stable channel.
RUST_VERSION=$(sed -nE 's/^FROM --platform=\$BUILDPLATFORM rust:([0-9]+\.[0-9]+\.[0-9]+)-[^ @]+@sha256:[0-9a-f]{64} AS build$/\1/p' Dockerfile)
DOCKERHUB_USERNAME=postkeep
BUILDKIT_IMAGE=moby/buildkit:v0.35.0@sha256:aa632b921ef07411d2cb77292cd34213d4f7b384001d6fceef1e1f25bf9752bb
NEXTEST_VERSION=0.9.148
NEXTEST_SHA256=223ba936714cc861a9cdedad5a8eb664dfdd69d6fbdf6cea6aa8184f523290dc
CARGO_DENY_VERSION=0.20.2
CARGO_DENY_SHA256=9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f
SITE_NODE_IMAGE=node:22-bookworm@sha256:7c400d78797d8cbe3f6bb21d2227b86af4cd24b0014cc9f62ff989cc16de988e
BUN_VERSION=$(sed -nE 's/^[[:space:]]*"packageManager": "bun@([0-9]+\.[0-9]+\.[0-9]+)",?$/\1/p' site/package.json)
BUN_SHA256_X64=36368faef7527875d5ffa52e53cd48021741f2a83eb6208a8dd64068d422a913
BUN_SHA256_AARCH64=54328bbc2d9c8e0c9f892c544d66c57a83b84139e34909e5ee81758f1ac8fda7
case $RUST_VERSION in ''|*[!0-9.]*) echo 'Expected one digest-pinned Rust build image in Dockerfile' >&2; return 1 ;; esac
case $BUN_VERSION in ''|*[!0-9.]*) echo 'Expected one Bun packageManager version in site/package.json' >&2; return 1 ;; esac
export DOCKERHUB_USERNAME BUILDKIT_IMAGE RUST_VERSION NEXTEST_VERSION NEXTEST_SHA256 CARGO_DENY_VERSION CARGO_DENY_SHA256 SITE_NODE_IMAGE BUN_VERSION BUN_SHA256_X64 BUN_SHA256_AARCH64
