#!/usr/bin/env bash
set -euo pipefail
: "${GITHUB_OUTPUT:?}"
: "${MAX_CACHE_KIB:?}"
[[ "$MAX_CACHE_KIB" =~ ^[1-9][0-9]*$ ]]
size=0
for path in "$@"; do
    if [[ -d "$path" ]]; then
        # Cache paths name directories, so tar can include descendants even when
        # the action's glob excludes them. Prune disposable outputs explicitly.
        find "$path" -type d -name incremental -prune -exec rm -rf {} +
        # The final node link must regenerate compiler/linker audit records that
        # live outside target. Cached dependencies remain usable independently.
        find "$path" -type d -path '*/.fingerprint/kontor-node-*' -prune -exec rm -rf {} +
        if [[ "${PRUNE_TEST_EXECUTABLES:-false}" == true ]]; then
            # Keep proc-macro libraries; test programs are relinked from the
            # current checkout and need not occupy the shared cache quota.
            find "$path" -type f -path '*/deps/*' ! -path '*/build/*' -perm -u+x ! -name '*.so' ! -name '*.dylib' -delete
        fi
        kib=$(du -sk "$path" | cut -f1)
        size=$((size + kib))
    fi
done
printf 'size_kib=%s\nsave=%s\n' "$size" "$([[ "$size" -gt 0 && "$size" -le "$MAX_CACHE_KIB" ]] && echo true || echo false)" >> "$GITHUB_OUTPUT"
printf 'Compilation cache: %s KiB, upload limit: %s KiB\n' "$size" "$MAX_CACHE_KIB"
