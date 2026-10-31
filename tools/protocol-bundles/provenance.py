"""Record source and common-toolchain inputs independently of Cargo's build cache."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tomllib

from source_identity import verify_sources
from symbol_tool import executable as symbol_tool


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_inputs(root, data):
    verified = verify_sources(data)
    packages = []
    trees = {}
    inherited = {}
    for package in data["packages"]:
        directory = Path(package["manifest_path"]).parent
        for parent in (directory, *directory.parents):
            for relative in ("Cargo.toml", ".cargo/config", ".cargo/config.toml"):
                path = parent / relative
                if path.is_file():
                    inherited[str(path)] = sha(path)
            if (parent / ".git").exists():
                if package.get("source", "") and package["source"].startswith("git+"):
                    trees[str(parent)] = parent
                break
        files = {}
        for path in sorted(directory.rglob("*")):
            relative = path.relative_to(directory)
            if {".git", "target", "__pycache__"} & set(relative.parts) or not path.is_file():
                continue
            files[str(relative)] = sha(path)
        identity = package["id"].replace(str(root), "<repository>")
        packages.append({"package": identity, "files": files})
    sources = {}
    for relative in ("core/indexer/src/runtime/mod.rs",
                     "core/indexer/src/protocol/v1/engine.rs",
                     "core/indexer/src/protocol/v1/resources.rs",
                     "core/indexer/src/protocol/v1/gas.rs",
                     "core/indexer/src/protocol/v1/native.rs",
                     "core/indexer/src/protocol/v1/errors.rs",
                     "core/indexer/src/protocol/v1/fuel.rs",
                     "core/indexer/src/protocol/v1/fees.rs",
                     "core/indexer/src/protocol/v1/deposit.rs"):
        sources[relative] = sha(root / relative)
    for directory in (root / "protocol-bundles/proof", root / "tools/protocol-bundles",
                      root / "tools/native-crypto/fixtures"):
        for path in sorted(directory.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                sources[str(path.relative_to(root))] = sha(path)
    git_sources = {}
    for identity, directory in sorted(trees.items()):
        git_sources[identity] = {
            str(path.relative_to(directory)): sha(path)
            for path in sorted(directory.rglob("*"))
            if path.is_file() and not {".git", "target", "__pycache__"} & set(path.relative_to(directory).parts)
        }
    for directory in (root, *root.parents, Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))):
        for relative in (".cargo/config", ".cargo/config.toml", "config", "config.toml"):
            path = directory / relative
            if path.is_file():
                inherited[str(path)] = sha(path)
    return {"verified_external_sources": verified, "packages": packages, "qualification_sources": sources,
            "inherited_manifests_and_configuration": inherited, "git_source_trees": git_sources}


def locked_packages(lock):
    return tomllib.loads(lock.read_text())["package"]


def tools(env, target):
    sysroot = Path(subprocess.check_output([env["RUSTC"], "--print", "sysroot"], env=env, text=True).strip())
    libraries = sysroot / "lib/rustlib" / target / "lib"
    common = {p.name: sha(p) for p in sorted(libraries.iterdir()) if p.suffix in (".rlib", ".rmeta")}
    if not common:
        raise RuntimeError("missing common sysroot libraries")
    compiler_libraries = {str(p.relative_to(sysroot)): sha(p) for p in sorted((sysroot / "lib").glob("*"))
                          if p.is_file() and (".so" in p.name or p.suffix == ".dylib")}
    build_environment = {key: value for key, value in env.items()
                         if key in ("CC", "CXX", "AR", "RANLIB", "CFLAGS", "CXXFLAGS", "LDFLAGS",
                                    "MACOSX_DEPLOYMENT_TARGET", "SDKROOT", "RUSTC", "RUSTUP_TOOLCHAIN")
                         or key.startswith(("CARGO_PROFILE_", "CARGO_TARGET_", "CC_", "CXX_", "CFLAGS_", "CXXFLAGS_", "AR_"))}
    return {"compiler": subprocess.check_output([env["RUSTC"], "-Vv"], env=env, text=True),
            "symbol_reader": {"path": str(symbol_tool()), "sha256": sha(symbol_tool()),
                              "version": subprocess.check_output([str(symbol_tool()), "--version"], text=True)},
            "rustc_sha256": sha(sysroot / "bin/rustc"), "common_sysroot": common,
            "compiler_libraries": compiler_libraries, "build_environment": build_environment,
            "cc": subprocess.check_output([env.get("CC", "cc"), "--version"], env=env, text=True),
            "platform": list(os.uname())}


def runtime_libraries(executable, env, graphs):
    if os.uname().sysname == "Darwin":
        command = ["otool", "-L", str(executable)]
    else:
        command = ["readelf", "-d", str(executable)]
    output = subprocess.check_output(command, env=env, text=True)
    compiler_libraries = {Path(item[field]).name for graph in graphs
                          for item in graph["compiler_proc_macros"] for field in ("path", "staged")}
    for line in output.splitlines():
        if "NEEDED" not in line and os.uname().sysname != "Darwin":
            continue
        if any(word in line for word in compiler_libraries):
            raise RuntimeError("compiler proc-macro library became a node runtime dependency")
    return output


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
