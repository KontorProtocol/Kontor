#!/usr/bin/env bash
set -euo pipefail
: "${GITHUB_OUTPUT:?}"
: "${RUST_TESTS:?}"
: "${STACK_TESTS:?}"
[[ "$RUST_TESTS" == true || "$RUST_TESTS" == false ]]
[[ "$STACK_TESTS" == true || "$STACK_TESTS" == false ]]
matrix=$(jq -cn --argjson ordinary "$RUST_TESTS" --argjson stack "$STACK_TESTS" '
  {include: [
    {os:"ubuntu-24.04",arch:"X64"},
    {os:"ubuntu-24.04-arm",arch:"ARM64"},
    {os:"macos-15",arch:"ARM64"}
  ] | map(. as $platform | ["release","dev"][] |
    . as $profile | ($ordinary and $profile == "release" and $platform.os != "ubuntu-24.04-arm") as $workspace |
    select($stack or $workspace) | $platform + {profile:$profile,workspace:$workspace})}')
printf 'matrix=%s\n' "$matrix" >> "$GITHUB_OUTPUT"
printf 'required=%s\n' "$(jq '.include | length > 0' <<<"$matrix")" >> "$GITHUB_OUTPUT"
