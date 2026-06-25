# Pinned, reproducible build image for Kontor contracts.
#
# Contract wasm bytes are a function of the build environment (CPU arch + build
# path + tool versions), not just the source, so byte-identical output is only
# guaranteed inside a FIXED environment: this image, at the fixed WORKDIR /build,
# on a fixed arch. There is no single "canonical" arch — each committed set records
# the arch that built it in binaries/build.json (NEP-330 style), and CI verifies on
# a matching runner. The image is published multi-arch so any arch can be
# reproduced natively (different arches yield different bytes — cargo bakes the arch
# into crate metadata).
#
# Published on push to main as docker.io/kontorprotocol/kontor-build:<rustc>.
# Use (workspaces are passed as arguments to the in-image build script):
#   docker run --rm -v "$PWD:/build" -w /build \
#     kontorprotocol/kontor-build:1.96.0 \
#     bash tools/build-in-image.sh native-contracts test-contracts
# Locally, tools/build-contracts.sh builds this image and runs the above for you.
#
# Every wasm-affecting input is pinned: rustc by the base image digest, wasm-opt
# by the binaryen version + sha below, brotli by an exact apt version. The base is
# pinned by @sha256 (the multi-arch manifest-list digest, so it still resolves to
# the right per-arch image) — CI rebuilds this image every run, so a tag alone
# would silently drift the toolchain if Docker Hub re-tagged it. The tag is kept
# alongside the digest for human readability; bump both together.
FROM rust:1.96.0-slim-bookworm@sha256:4732ca96fd086cb9be682050c3f0176288eebaac2b80aa2bcefccfaf198e1950

# Pinned binaryen release providing wasm-opt. Both the cargo toolchain and the
# wasm-opt binary are part of the wasm's identity, so the wasm-opt version is
# pinned here exactly like rustc is pinned by the base tag. Bump together.
ARG BINARYEN_VERSION=version_130
ARG BINARYEN_SHA256_X86_64=0a18362361ad05465118cd8eeb72edaeec89de6894bc283576ef4e07aa3babcc
ARG BINARYEN_SHA256_AARCH64=e6ae6e09ac40f4e14bc5be6f687c58e2995c84170013975fa641809dd3b480a0

# brotli pinned to an exact apt version — compression output can change between
# brotli releases, and CI rebuilds this image every run, so an unpinned package
# would silently drift the committed bytes. curl + ca-certificates only fetch the
# wasm-opt tarball; no C/C++ toolchain — nothing is compiled. (If apt ever drops
# this exact version, bump it here and regenerate.)
RUN apt-get update \
 && apt-get install -y --no-install-recommends brotli=1.0.9-2+b6 curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Install the prebuilt wasm-opt for the build platform's native arch. `uname -m`
# is correct under buildx: each per-arch image is assembled on (or emulated as)
# its target arch, so this resolves to the matching binaryen tarball + sha.
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
      x86_64)  sha="$BINARYEN_SHA256_X86_64" ;; \
      aarch64) sha="$BINARYEN_SHA256_AARCH64" ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/WebAssembly/binaryen/releases/download/${BINARYEN_VERSION}/binaryen-${BINARYEN_VERSION}-${arch}-linux.tar.gz"; \
    curl -fsSL "$url" -o /tmp/binaryen.tar.gz; \
    echo "${sha}  /tmp/binaryen.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/binaryen.tar.gz -C /tmp; \
    cp "/tmp/binaryen-${BINARYEN_VERSION}/bin/wasm-opt" /usr/local/bin/wasm-opt; \
    cp -a "/tmp/binaryen-${BINARYEN_VERSION}/lib/." /usr/local/lib/; \
    rm -rf /tmp/binaryen.tar.gz "/tmp/binaryen-${BINARYEN_VERSION}"; \
    ldconfig; \
    wasm-opt --version

RUN rustup target add wasm32-unknown-unknown

# Marker the contract build script checks for: it refuses to run outside this
# image (where host tool versions would make the output non-reproducible). The
# blessed entrypoint is tools/build-contracts.sh, which runs it in here.
ENV KONTOR_BUILD_IMAGE=1

# Fixed WORKDIR: the build path is part of the wasm's identity (cargo bakes it into
# the metadata/StableCrateId), so every build must happen here for reproducibility.
WORKDIR /build
