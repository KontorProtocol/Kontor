use std::collections::BTreeSet;

use super::JOBS;

const STACK_MODULES: &[&str] = &[
    "call",
    "component_cache",
    "component_policy",
    "conversion_probe",
    "fuel",
    "guest_memory",
    "host_context",
    "host_files",
    "host_numbers",
    "host_storage",
    "host_system",
    "invocation",
    "lowering",
    "ownership",
    "pool",
    "stack",
    "storage",
    "storage_host",
    "system",
    "types",
    "wit",
    "sequential_tests",
    "resource_diagnostics",
    "bundle_ownership",
    "bundle_session",
];

const STACK_PREFIXES: &[&str] = &[
    "core/vendor/",
    "core/bls-crypto/",
    "core/contract/wit/",
    "test-contracts/stack-probe/",
    "test-contracts/error-test/",
    "test-contracts/proxy/",
    "test-contracts/crypto/",
    "tools/native-stack/",
    ".github/actions/run-stack/",
    ".github/actions/run-workspace-tests/",
];

const STACK_FILES: &[&str] = &[
    "core/indexer/src/runtime/mod.rs",
    "core/indexer/src/config.rs",
    "core/indexer/src/api/env.rs",
    "core/indexer/src/api/handlers/contracts.rs",
    "core/indexer/src/api/handlers/tests/ownership.rs",
    "core/macros/src/contract.rs",
    "core/macros/src/import.rs",
    "core/macros/src/interface.rs",
    "core/macros/src/wavey.rs",
    "core/macros/src/lib.rs",
    "core/stdlib/src/lib.rs",
    "core/stdlib/src/wave_interfaces.rs",
    "test-contracts/binaries/stack_probe.wasm.br",
    "test-contracts/binaries/error_test.wasm.br",
    "test-contracts/binaries/proxy.wasm.br",
    "test-contracts/binaries/crypto.wasm.br",
    ".github/workflows/native-stack.yml",
    ".github/workflows/rust-tests.yml",
];

const BUNDLE_PREFIXES: &[&str] = &[
    "protocol-bundles/",
    "core/vendor/",
    "core/bls-crypto/",
    "core/indexer/proto/",
    "core/indexer/src/bls/",
    "core/indexer/src/protocol/coordinator/",
    "core/indexer/src/reactor/upgrade_qualification/",
    "tools/protocol-bundles/",
    "tools/native-crypto/",
];

const BUNDLE_FILES: &[&str] = &[
    "core/indexer/src/main.rs",
    "core/indexer/src/lib.rs",
    "core/indexer/src/stopper.rs",
    "core/indexer/src/runtime/mod.rs",
    "core/indexer/src/runtime/selected.rs",
    "core/indexer/src/database/init.rs",
    "core/indexer/src/database/migration_input.rs",
    "core/indexer/src/database/sql/upgrade_control.sql",
    "core/indexer/src/database/sql/canonical_history.sql",
    "core/indexer/src/database/sql/certified_history.sql",
    "core/indexer/src/protocol/v1/mod.rs",
    "core/indexer/src/protocol/v1/definition.rs",
    "core/indexer/src/protocol/v1/migration.rs",
    "core/indexer/src/protocol/v1/migration_definition.rs",
    "core/indexer/src/protocol/v2/mod.rs",
    "core/indexer/src/protocol/v2/fixture_migration.rs",
    "core/indexer/src/protocol/v2/migration_definition.rs",
    "core/indexer/src/reactor/mod.rs",
    "core/indexer/src/reactor/upgrade_qualification.rs",
    "core/indexer/src/reactor/upgrades.rs",
    "core/indexer/src/reactor/session.rs",
    "core/indexer/src/reactor/executor.rs",
    "core/indexer/src/reactor/execution.rs",
    "core/indexer/src/reactor/handoff.rs",
    ".github/workflows/protocol-bundles.yml",
];

const SHARED_BUILD_FILES: &[&str] = &[
    "tools/kontor",
    "tools/build.json",
    "tools/kontor-build.Dockerfile",
    "Dockerfile",
    ".dockerignore",
    ".github/workflows/publish-build-image.yml",
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

pub(super) fn tooling_only(path: &str) -> bool {
    path.starts_with("core/kontor-build/src/ci_scope/")
        || path == "core/kontor-build/src/ci_scope.rs"
        || path.starts_with("core/kontor-build/tests/")
        || path.starts_with("core/kontor-build/src/diagnostics/")
        || path == "core/kontor-build/src/diagnostics.rs"
        || path.starts_with("core/kontor-build/src/node_evidence/comparison/")
        || path.starts_with(".github/actions/setup-kontor-tools/")
        || path == ".github/workflows/ci-diagnostics.yml"
        || path == ".github/workflows/docker-image.yml"
}

fn module(path: &str, stem: &str) -> bool {
    path == format!("{stem}.rs") || path.starts_with(&format!("{stem}/"))
}

fn shared_build(path: &str) -> bool {
    SHARED_BUILD_FILES.contains(&path)
        || (build_metadata(path)
            && (!path.contains('/')
                || path.starts_with(".cargo/")
                || ["core/", "native-contracts/", "test-contracts/"]
                    .iter()
                    .any(|prefix| path.starts_with(prefix))))
}

pub(super) fn stack_relevant(path: &str) -> bool {
    if tooling_only(path) {
        return false;
    }
    shared_build(path)
        || STACK_FILES.contains(&path)
        || STACK_PREFIXES.iter().any(|prefix| path.starts_with(prefix))
        || STACK_MODULES
            .iter()
            .any(|name| module(path, &format!("core/indexer/src/runtime/{name}")))
        || module(path, "core/kontor-build/src/stack_evidence")
        || module(path, "core/kontor-build/src/toolchain")
}

pub(super) fn bundle_relevant(path: &str) -> bool {
    if tooling_only(path) {
        return false;
    }
    shared_build(path)
        || BUNDLE_FILES.contains(&path)
        || BUNDLE_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix))
        || path.starts_with("core/indexer/src/runtime/bundle_")
        || path
            .strip_prefix("core/indexer/src/protocol/")
            .is_some_and(|name| !name.contains('/') && name.ends_with(".rs"))
        || path.starts_with("core/indexer/src/database/storage_")
        || module(path, "core/indexer/src/database/canonical_history")
        || module(path, "core/indexer/src/database/certified_history")
        || module(path, "core/indexer/src/runtime/ownership")
        || module(path, "core/indexer/src/reactor/engine")
        || [
            "node_build",
            "graph_build",
            "compiler_wrapper",
            "linker_record",
            "shared_ownership",
            "symbol_audit",
            "native_crypto",
            "native_lock",
            "metadata_control",
            "execution_definition",
            "consensus_definition",
            "freeze_sources",
            "source_identity",
            "source_policy",
            "snapshot",
            "build_inputs",
            "build_artifacts",
            "provenance",
            "canonical_json",
            "outputs",
            "recipes",
            "toolchain",
            "container",
            "bundles",
            "interface",
            "node_evidence",
        ]
        .iter()
        .any(|name| module(path, &format!("core/kontor-build/src/{name}")))
        || path.starts_with("core/kontor-build/src/bin/kontor-")
}

pub(super) fn classify(path: &str, docker_targets: &BTreeSet<String>) -> BTreeSet<&'static str> {
    if tooling_only(path) {
        return BTreeSet::from(["tooling"]);
    }
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
