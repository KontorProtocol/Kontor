use std::collections::BTreeSet;

use super::JOBS;

pub(super) const STACK_PREFIXES: &[&str] = &[
    "core/indexer/proto/",
    "core/indexer/src/runtime/",
    "core/indexer/src/protocol/",
    "core/indexer/src/database/",
    "core/indexer/src/reactor/",
    "core/indexer/src/bls/",
    "core/indexer/src/test_utils/",
    "core/built-in-types/",
    "core/indexer-types/",
    "core/macros/",
    "core/numerics/",
    "core/stdlib/",
    "core/wit-validator/",
    "core/bls-crypto/",
    "core/testlib/",
    "core/kontor-build/",
    "core/vendor/",
    "native-contracts/",
    "test-contracts/",
    "protocol-bundles/",
    "tools/native-stack/",
    "tools/protocol-bundles/",
    "tools/native-crypto/",
];

pub(super) const STACK_FILES: &[&str] = &[
    ".github/actions/setup-kontor-tools/action.yml",
    "core/indexer/src/block.rs",
    "core/indexer/src/config.rs",
    "core/indexer/src/main.rs",
    "core/indexer/src/lib.rs",
    "core/indexer/src/built_info.rs",
    "core/indexer/src/stopper.rs",
    "core/indexer/src/test_utils.rs",
    "core/indexer/src/testlib_exports.rs",
    "core/indexer/src/legacy_test_utils.rs",
    "core/indexer/src/multi_psbt_test_utils.rs",
    "core/indexer/src/api/env.rs",
    "core/indexer/src/api/mod.rs",
    "core/indexer/src/api/router.rs",
    "core/indexer/src/api/handlers/contracts.rs",
    "core/indexer/src/api/handlers/signers.rs",
    "core/indexer/src/api/handlers/tests/ownership.rs",
    "tools/kontor",
    "tools/build.json",
    "tools/kontor-build.Dockerfile",
    "Dockerfile",
    ".dockerignore",
    ".github/workflows/native-stack.yml",
    ".github/workflows/native-stack-s2.yml",
    ".github/workflows/protocol-bundles.yml",
    ".github/workflows/publish-build-image.yml",
    "tools/ci/stack_qualification_scope.py",
    "tools/ci/test_stack_qualification_scope.py",
];

pub(super) const BUILD_NAMES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "build.rs",
    "rust-toolchain",
    "rust-toolchain.toml",
];

pub(super) const REPRO_PREFIXES: &[&str] = &[
    "native-contracts/",
    "test-contracts/",
    "core/stdlib/",
    "core/macros/",
    "core/built-in-types/",
    "core/numerics/",
    "core/indexer-types/",
    "core/wit-validator/",
    "core/bls-crypto/",
    "core/kontor-sdk/",
    "core/kontor-sdk-wasm/",
    "core/kontor-build/",
    "core/vendor/",
    "core/indexer/src/runtime/wit/",
    "core/contract/wit/",
    "sdk/src/component/",
    "tools/native-crypto/",
];

pub(super) const REPRO_FILES: &[&str] = &[
    "sdk/src/bindings.d.ts",
    "sdk/package.json",
    "sdk/package-lock.json",
    "tools/kontor",
    "tools/build.json",
    "tools/kontor-build.Dockerfile",
    ".dockerignore",
];

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

pub(super) fn build_metadata(path: &str) -> bool {
    BUILD_NAMES.contains(&basename(path))
        || (path.split('/').any(|part| part == ".cargo")
            && ["config", "config.toml"].contains(&basename(path)))
}

pub(super) fn evidence_only(path: &str) -> bool {
    let name = basename(path);
    path.starts_with("tools/protocol-bundles/")
        && (name == "compare_node.py" || (name.starts_with("test_") && name.ends_with(".py")))
}

pub(super) fn stack_relevant(path: &str) -> bool {
    !evidence_only(path)
        && (STACK_FILES.contains(&path)
            || STACK_PREFIXES.iter().any(|prefix| path.starts_with(prefix))
            || build_metadata(path))
}

pub(super) fn classify(path: &str, docker_targets: &BTreeSet<String>) -> BTreeSet<&'static str> {
    if path.starts_with("docs/") || (!path.contains('/') && path.ends_with(".md")) {
        return BTreeSet::new();
    }
    if docker_targets.contains(path)
        || build_metadata(path)
        || path.starts_with("tools/ci/")
        || path == ".github/workflows/ci.yml"
        || [
            "Dockerfile",
            ".dockerignore",
            ".github/workflows/docker-cache.yml",
        ]
        .contains(&path)
        || path.starts_with(".github/actions/setup-docker/")
    {
        return JOBS.into_iter().collect();
    }
    if ["core/", "native-contracts/", "test-contracts/"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        let mut selected = BTreeSet::from(["rust", "sdk"]);
        if REPRO_PREFIXES.iter().any(|prefix| path.starts_with(prefix)) {
            selected.insert("reproducible");
        }
        if ["lib.rs", "main.rs"].contains(&basename(path))
            || path
                .split('/')
                .any(|part| ["bin", "examples", "tests", "benches"].contains(&part))
        {
            selected.insert("docker_cache");
        }
        return selected;
    }
    if path.starts_with("sdk/") {
        return if REPRO_FILES.contains(&path) || path.starts_with("sdk/src/component/") {
            BTreeSet::from(["sdk", "reproducible"])
        } else {
            BTreeSet::from(["sdk"])
        };
    }
    if path.starts_with("protocol-bundles/") {
        return BTreeSet::from(["rust", "sdk", "docker_cache"]);
    }
    JOBS.into_iter().collect()
}
