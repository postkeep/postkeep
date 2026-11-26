# syntax=docker/dockerfile:1.7
#
# Multi-architecture image for postkeep (linux/amd64, linux/arm64).
# The build stage runs on the build machine's architecture and
# cross-compiles, so no emulation is needed:
#
#   docker buildx build --platform linux/amd64,linux/arm64 -t postkeep .
#
# The runtime image is distroless (glibc, no shell) and runs as a non-root
# user. Configure it entirely through POSTKEEP_* environment variables; see
# docs/configuration.md.

# CI also reads its Rust version from this pin.
FROM --platform=$BUILDPLATFORM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS build
ARG TARGETARCH
ARG BUILDARCH
WORKDIR /src

# Cross linkers and C compilers (ring and SQLite contain C code).
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc \
    AR_x86_64_unknown_linux_gnu=x86_64-linux-gnu-ar \
    CARGO_NET_GIT_FETCH_WITH_CLI=true

RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-gnu; cross=gcc-x86-64-linux-gnu; libc=libc6-dev-amd64-cross ;; \
      arm64) target=aarch64-unknown-linux-gnu; cross=gcc-aarch64-linux-gnu; libc=libc6-dev-arm64-cross ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
      apt-get update; \
      apt-get install -y --no-install-recommends "$cross" "$libc"; \
      rm -rf /var/lib/apt/lists/*; \
    fi; \
    rustup target add "$target"; \
    echo "$target" > /rust-target

COPY . .

# Empty for a local build and for a main-branch image, which keep the
# workspace version in Cargo.toml. A release tag sets X.Y.Z or
# X.Y.Z-prerelease so `postkeep --version` prints that version.
ARG POSTKEEP_VERSION=

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,id=target-${TARGETARCH},sharing=locked \
    set -eux; \
    if [ -n "${POSTKEEP_VERSION:-}" ]; then \
      sh tools/stamp-workspace-version.sh "$POSTKEEP_VERSION"; \
    fi; \
    target="$(cat /rust-target)"; \
    cargo build --release --locked --target "$target" -p postkeep; \
    install -D -m 0755 "target/$target/release/postkeep" /out/postkeep; \
    mkdir -p /out/data

# Pinned by digest; bump the digest by hand when the base image updates.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

# Redeclared after the last FROM so a publish can stamp the image it pushes.
ARG IMAGE_SOURCE
ARG IMAGE_REVISION=unknown
ARG IMAGE_CREATED=unknown
ARG IMAGE_VERSION=unknown
ARG IMAGE_LICENSES=MIT

LABEL org.opencontainers.image.title="postkeep" \
      org.opencontainers.image.description="Open-source MCP server that lets your agent read and answer your mail, from a server you run" \
      org.opencontainers.image.url="https://postkeep.dev" \
      org.opencontainers.image.documentation="https://postkeep.dev/docs/" \
      org.opencontainers.image.source="${IMAGE_SOURCE}" \
      org.opencontainers.image.revision="${IMAGE_REVISION}" \
      org.opencontainers.image.created="${IMAGE_CREATED}" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.vendor="postkeep" \
      org.opencontainers.image.licenses="${IMAGE_LICENSES}" \
      io.modelcontextprotocol.server.name="io.github.postkeep/postkeep"

COPY --from=build /out/postkeep /usr/local/bin/postkeep
COPY --from=build --chown=65532:65532 /out/data /data

# The built-in defaults listen on 0.0.0.0:8080 and use ./postkeep.db.
# This working directory makes that file /data/postkeep.db.
WORKDIR /data

VOLUME ["/data"]
EXPOSE 8080
USER 65532:65532

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/postkeep", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/postkeep"]
CMD ["serve"]
