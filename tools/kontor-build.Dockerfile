# Publish this image, then pin its digest in tools/build.json. Builds use that
# published image, not a locally rebuilt substitute. SDK tool archives are
# separately checksum-pinned in tools/build.json.
FROM rust:1.96.0-slim-bookworm@sha256:4732ca96fd086cb9be682050c3f0176288eebaac2b80aa2bcefccfaf198e1950

# Pinned binaryen release providing wasm-opt. Both the cargo toolchain and the
# wasm-opt binary are part of the wasm's identity, so the wasm-opt version is
# pinned here exactly like rustc is pinned by the base tag. Bump together.
ARG BINARYEN_VERSION=version_130
ARG BINARYEN_SHA256_X86_64=0a18362361ad05465118cd8eeb72edaeec89de6894bc283576ef4e07aa3babcc
ARG BINARYEN_SHA256_AARCH64=e6ae6e09ac40f4e14bc5be6f687c58e2995c84170013975fa641809dd3b480a0

# Compression output depends on brotli's exact version. Republish and regenerate
# if Debian drops this package version.
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

# Fixed WORKDIR: the build path is part of the wasm's identity (cargo bakes it into
# the metadata/StableCrateId), so every build must happen here for reproducibility.
WORKDIR /build
