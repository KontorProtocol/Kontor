#!/usr/bin/env bash
# Build the committed contract binaries by running the pinned build image against
# each contracts workspace. This just launches the container; the actual build
# (and reproducibility) lives in tools/build-in-image.sh, which runs inside it.
#
# With no args, builds both contract workspaces; pass dirs to build a subset:
#   tools/build-contracts.sh                          # native + test
#   tools/build-contracts.sh native-contracts         # just one
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKERFILE="$REPO_ROOT/tools/kontor-build.Dockerfile"

WORKSPACES=("$@")
[ ${#WORKSPACES[@]} -eq 0 ] && WORKSPACES=(native-contracts test-contracts)

if command -v docker >/dev/null 2>&1; then
  RUNTIME=docker
  RUN_OPTS=()
elif command -v podman >/dev/null 2>&1; then
  RUNTIME=podman
  # Rootless podman + SELinux: a plain bind mount is unreadable in-container.
  # label=disable avoids relabeling the whole working tree.
  RUN_OPTS=(--security-opt label=disable)
else
  echo "error: need docker or podman on PATH" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64) PLATFORM=linux/amd64 ;;
  aarch64 | arm64) PLATFORM=linux/arm64 ;;
  *) echo "error: unsupported arch $(uname -m)" >&2; exit 1 ;;
esac

# Tag the image by Dockerfile content + arch, and build ONLY when that exact
# image is missing — so an unchanged Dockerfile skips the build entirely (even a
# warm layer-cache walk costs a second or two) and goes straight to run. A
# Dockerfile edit changes the hash → new tag → rebuild. git hash-object is used
# (not sha256sum) so this works on macOS too. localhost/ qualifies the name so
# podman treats it as local and never searches remote registries.
IMAGE_TAG="localhost/kontor-build:$(git hash-object "$DOCKERFILE" | cut -c1-12)-$(uname -m)"

if ! "$RUNTIME" image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
  # Pipe the Dockerfile in on stdin (context "-") so the build has NO context at
  # all: no COPY means no files needed, and this avoids the runtime walking the
  # repo root (100s of GB of target/ dirs) to assemble a context it never uses.
  echo "==> Building image $IMAGE_TAG"
  "$RUNTIME" build --platform "$PLATFORM" -t "$IMAGE_TAG" - <"$DOCKERFILE"
fi

# build-in-image.sh pins CARGO_HOME under the mounted repo (/build/.build-cache),
# so the crate registry persists across runs here too — cargo doesn't re-download
# or recompile every time. CARGO_BUILD_JOBS is a local-machine guard (avoids OOM)
# and doesn't affect output, so it stays here rather than in the reproducible env.
"$RUNTIME" run --rm --platform "$PLATFORM" "${RUN_OPTS[@]+"${RUN_OPTS[@]}"}" \
  -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" \
  -v "$REPO_ROOT:/build" -w /build \
  "$IMAGE_TAG" bash tools/build-in-image.sh "${WORKSPACES[@]}"
