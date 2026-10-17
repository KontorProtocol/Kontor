# Publish this image, then pin its digest in tools/build.json. Builds use that
# published image, not a locally rebuilt substitute. SDK tool archives are
# separately checksum-pinned in tools/build.json.
FROM rust:1.99.1-slim-bookworm@sha256:a24e292b4af7bdee351a31d3a6379972a5652f0ea22a1b6d6883324ac4f5097c

# Pinned binaryen release providing wasm-opt. Both the cargo toolchain and the
# wasm-opt binary are part of the wasm's identity, so the wasm-opt version is
# pinned here exactly like rustc is pinned by the base tag. Regenerate outputs
# whenever either version changes.
ARG BINARYEN_VERSION=version_133
ARG BINARYEN_SHA256_X86_64=2dc9c7813f5375db93d96ead4b78222fcc3e2677bbb832297af4797782a37489
ARG BINARYEN_SHA256_AARCH64=89c07ea56faf38d0fbecf36ca8ec0721756716185f265b568e133d427f299bf8

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
