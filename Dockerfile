# syntax=docker/dockerfile:1.6
#
# twigpine-node — production image for operators.
# Multi-arch (linux/amd64, linux/arm64), non-root runtime, HEALTHCHECK.

# ── Build stage ─────────────────────────────────────────────────────────────
FROM rust:1.91-bookworm AS builder

WORKDIR /build

# Cache dependencies first for faster rebuilds.
# EVERY workspace member's manifest must be copied here, not just the ones this
# image ships: cargo loads the whole workspace before it resolves anything, so a
# missing member's Cargo.toml (or a path dependency pointing at one) aborts the
# layer before a single crate is fetched.
COPY Cargo.toml Cargo.lock ./
COPY crates/twigpine-core/Cargo.toml crates/twigpine-core/
COPY crates/twigpine-node/Cargo.toml crates/twigpine-node/
COPY crates/twigpine-cli/Cargo.toml crates/twigpine-cli/
COPY crates/git-remote-twigpine/Cargo.toml crates/git-remote-twigpine/
COPY crates/twigpine-attest/Cargo.toml crates/twigpine-attest/
COPY crates/icaptcha-client/Cargo.toml crates/icaptcha-client/

# Fetch deps (this layer caches until Cargo.{toml,lock} change).
# No `|| true`: this layer is expected to succeed, and swallowing its exit code
# is what let it sit dead from the moment twigpine gained a path dependency on
# icaptcha-client. A failure here should stop the build, not silently turn every
# image build into a cold one.
# twigpine-node declares BOTH a [[bin]] and a [lib], so it needs both stubs:
# cargo resolves every declared target before it fetches anything, and a
# missing src/lib.rs aborts the layer with a target resolution error.
RUN mkdir -p crates/twigpine-core/src crates/twigpine-node/src crates/twigpine-cli/src \
        crates/git-remote-twigpine/src crates/twigpine-attest/src crates/icaptcha-client/src && \
    echo 'fn main() {}' > crates/twigpine-node/src/main.rs && \
    echo 'fn main() {}' > crates/twigpine-cli/src/main.rs && \
    echo 'fn main() {}' > crates/git-remote-twigpine/src/main.rs && \
    echo '' > crates/twigpine-node/src/lib.rs && \
    echo '' > crates/twigpine-core/src/lib.rs && \
    echo '' > crates/twigpine-attest/src/lib.rs && \
    echo '' > crates/icaptcha-client/src/lib.rs && \
    cargo build --release --locked -p twigpine-node -p twigpine-cli -p git-remote-twigpine

# Now copy real sources and build for real.
# Force-bump mtimes so cargo's fingerprint check rebuilds — without this,
# cargo can keep the dummy `fn main() {}` binaries from the cache layer above
# and the runtime container exits immediately with code 0.
COPY crates/ crates/
COPY bootstrap-peers.json ./
RUN find crates -name "*.rs" -exec touch {} + && \
    rm -f target/release/twigpine-node target/release/twigpine target/release/git-remote-twigpine \
          target/release/git-remote-gitlawb && \
    rm -rf target/release/.fingerprint/twigpine-node-* \
           target/release/.fingerprint/twigpine-cli-* \
           target/release/.fingerprint/git-remote-twigpine-* && \
    cargo build --release --locked -p twigpine-node -p twigpine-cli -p git-remote-twigpine && \
    strip target/release/twigpine-node target/release/twigpine target/release/git-remote-twigpine

# ── Runtime stage ───────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        curl \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for runtime
RUN groupadd -r gitlawb --gid=1000 \
    && useradd -r -g gitlawb --uid=1000 --home-dir=/data --shell=/sbin/nologin gitlawb \
    && mkdir -p /data/repos /data/keys \
    && chown -R gitlawb:gitlawb /data

COPY --from=builder /build/target/release/twigpine-node /usr/local/bin/
COPY --from=builder /build/target/release/twigpine /usr/local/bin/
COPY --from=builder /build/target/release/git-remote-twigpine /usr/local/bin/
# Other names for the same binaries: the short form of the command, and the
# names used before the rename. Git picks its remote helper by URL scheme, so
# existing remotes still run the old helper name, and a compose file or unit
# that overrides the command may still call the old daemon name.
RUN ln -s twigpine /usr/local/bin/twig \
    && ln -s twigpine /usr/local/bin/gl \
    && ln -s git-remote-twigpine /usr/local/bin/git-remote-gitlawb \
    && ln -s twigpine-node /usr/local/bin/gitlawb-node

USER gitlawb
WORKDIR /data

# Image defaults, kept under the settings' names from before the rename on
# purpose. A value the operator gives under either name must override them:
# TWIGPINE_* wins over GITLAWB_* when both are set, so defaults under the new
# names would silently beat an existing deployment's GITLAWB_PORT or
# GITLAWB_KEY. Under the old names, GITLAWB_* replaces them and TWIGPINE_*
# outranks them. They move to the new names when the old ones are dropped.
ENV GITLAWB_REPOS_DIR=/data/repos \
    GITLAWB_KEY=/data/keys/identity.pem \
    GITLAWB_P2P_KEY=/data/keys/p2p.key \
    GITLAWB_HOST=0.0.0.0 \
    GITLAWB_PORT=7545 \
    GITLAWB_P2P_PORT=7546

EXPOSE 7545 7546/udp

VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:${TWIGPINE_PORT:-${GITLAWB_PORT}}/health || exit 1

# Run under tini so the node is never PID 1. As PID 1 a process must reap
# reparented orphans itself; the node does not, so git's reparented grandchildren
# (e.g. pack-objects orphaned when a served upload-pack dies on a client
# disconnect) would accumulate as zombies until fork() fails with EAGAIN (#53).
# tini reaps them and forwards SIGTERM/SIGINT to the node, which runs its own
# graceful shutdown. (No `-g`: the node manages its own children, so group-wide
# signalling would only disturb in-flight git helpers during shutdown.)
ENTRYPOINT ["tini", "--", "twigpine-node"]
