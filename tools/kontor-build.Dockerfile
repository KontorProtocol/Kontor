# Publish this image, then pin its digest in tools/build.json. Builds use that
# published image, not a locally rebuilt substitute. SDK tool archives are
# separately checksum-pinned in tools/build.json.
FROM rust:1.99.1-slim-trixie@sha256:4df2ae8cfdfebdfc13a65da7f253b73d68983dc0339f2719bc17a279c913b13d

# Pinned binaryen release providing wasm-opt. Both the cargo toolchain and the
# wasm-opt binary are part of the wasm's identity, so the wasm-opt version is
# pinned here exactly like rustc is pinned by the base tag. Regenerate outputs
# whenever either version changes.
ARG BINARYEN_VERSION=version_133
ARG BINARYEN_SHA256_X86_64=2dc9c7813f5375db93d96ead4b78222fcc3e2677bbb832297af4797782a37489
ARG BINARYEN_SHA256_AARCH64=89c07ea56faf38d0fbecf36ca8ec0721756716185f265b568e133d427f299bf8

# Compression output is part of the committed binaries' identity.
ARG BROTLI_VERSION=1.2.1
ARG BROTLI_SHA256=98d35d11a78dc453aebb7d10c3748f3f73ff78c8267c0dc697b8631f67bf7e8f
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates cmake gcc make \
 && curl -fsSL "https://github.com/google/brotli/archive/refs/tags/v${BROTLI_VERSION}.tar.gz" -o /tmp/brotli.tar.gz \
 && echo "${BROTLI_SHA256}  /tmp/brotli.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/brotli.tar.gz -C /tmp \
 && cmake -S "/tmp/brotli-${BROTLI_VERSION}" -B /tmp/brotli-build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBROTLI_DISABLE_TESTS=ON \
 && cmake --build /tmp/brotli-build --target brotli --parallel 2 \
 && install /tmp/brotli-build/brotli /usr/local/bin/brotli \
 && brotli --version \
 && apt-get purge -y --auto-remove cmake make \
 && rm -rf /var/lib/apt/lists/* /tmp/brotli*

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
