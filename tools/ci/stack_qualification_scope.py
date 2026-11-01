"""Select full stack qualification from execution and build input changes."""

import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess


PREFIXES = (
    "core/indexer/proto/",
    "core/indexer/src/runtime/", "core/indexer/src/protocol/",
    "core/indexer/src/database/", "core/indexer/src/reactor/",
    "core/indexer/src/bls/", "core/indexer/src/test_utils/",
    "core/built-in-types/", "core/indexer-types/", "core/macros/",
    "core/numerics/", "core/stdlib/", "core/wit-validator/",
    "core/bls-crypto/", "core/testlib/", "core/kontor-build/", "core/vendor/",
    "native-contracts/", "test-contracts/", "protocol-bundles/",
    "tools/native-stack/", "tools/protocol-bundles/", "tools/native-crypto/",
)
FILES = {
    "core/indexer/src/block.rs", "core/indexer/src/config.rs",
    "core/indexer/src/main.rs", "core/indexer/src/lib.rs",
    "core/indexer/src/built_info.rs", "core/indexer/src/stopper.rs",
    "core/indexer/src/test_utils.rs", "core/indexer/src/testlib_exports.rs",
    "core/indexer/src/legacy_test_utils.rs", "core/indexer/src/multi_psbt_test_utils.rs",
    "core/indexer/src/api/env.rs", "core/indexer/src/api/mod.rs", "core/indexer/src/api/router.rs",
    "core/indexer/src/api/handlers/contracts.rs",
    "core/indexer/src/api/handlers/signers.rs", "core/indexer/src/api/handlers/tests/ownership.rs",
    "tools/kontor", "tools/build.json", "tools/kontor-build.Dockerfile",
    "Dockerfile", ".dockerignore",
    ".github/workflows/native-stack.yml", ".github/workflows/native-stack-s2.yml",
    ".github/workflows/protocol-bundles.yml", ".github/workflows/publish-build-image.yml",
    "tools/ci/stack_qualification_scope.py", "tools/ci/test_stack_qualification_scope.py",
}
BUILD_NAMES = {"Cargo.toml", "Cargo.lock", "build.rs", "rust-toolchain", "rust-toolchain.toml"}
SHA = re.compile(r"[0-9a-f]{40}\Z")


def relevant(path):
    if evidence_only(path):
        return False
    parts = PurePosixPath(path).parts
    return (
        path in FILES or path.startswith(PREFIXES)
        or PurePosixPath(path).name in BUILD_NAMES
        or (".cargo" in parts and PurePosixPath(path).name in {"config", "config.toml"})
    )


def evidence_only(path):
    name = PurePosixPath(path).name
    return path.startswith('tools/protocol-bundles/') and (
        name == 'compare_node.py' or (name.startswith('test_') and name.endswith('.py'))
    )


def changed_paths(event_name, event, root):
    if event_name == "pull_request":
        base = event["pull_request"]["base"]["sha"]
        head = event["pull_request"]["head"]["sha"]
        # Compare the whole PR, excluding unrelated advancement on its base branch.
        three_dot = True
    elif event_name == "push":
        base, head = event["before"], event["after"]
        three_dot = False
    else:
        raise ValueError(f"unsupported event: {event_name}")
    if not all(isinstance(sha, str) and SHA.fullmatch(sha) and sha != "0" * 40 for sha in (base, head)):
        raise ValueError("missing or invalid comparison commits")
    revision = f"{base}...{head}" if three_dot else f"{base}..{head}"
    # Disable rename detection so both the removed and added paths participate.
    result = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames", "-z", revision, "--"],
        cwd=root, check=True, capture_output=True,
    )
    return [os.fsdecode(path) for path in result.stdout.split(b"\0") if path]


def select(event_name, event, root):
    if event_name == "workflow_dispatch":
        return {"required": True, "reason": "manual qualification", "paths": []}
    try:
        paths = changed_paths(event_name, event, root)
    except (KeyError, TypeError, ValueError, OSError, subprocess.CalledProcessError) as error:
        # Missing history must never silently omit qualification.
        return {"required": True, "reason": f"cannot establish change scope: {type(error).__name__}", "paths": []}
    selected = sorted(path for path in paths if relevant(path))
    return {
        "required": bool(selected),
        "reason": "execution or build inputs changed" if selected else "no stack qualification inputs changed",
        "paths": selected,
    }


def main():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    result = select(os.environ["GITHUB_EVENT_NAME"], event, Path.cwd())
    result["profile_policy"] = profile_policy(os.environ["GITHUB_EVENT_NAME"], event)
    print(json.dumps(result, indent=2))
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write(f"required={str(result['required']).lower()}\n")
        output.write(f"profile_policy={result['profile_policy']}\n")


def profile_policy(event_name, event):
    policy = event.get("inputs", {}).get("profiles", "release") if event_name == "workflow_dispatch" else "release"
    if policy not in {"release", "full"}:
        raise ValueError("unknown qualification profile policy")
    return policy


if __name__ == "__main__":
    main()
