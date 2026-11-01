// SPDX-License-Identifier: CC0-1.0

//! # Build script

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

extern crate cc;

use std::env;
use std::error::Error;
use std::path::PathBuf;

use kontor_native_build::{preprocess_sources, Namespace};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(secp256k1_fuzz)");
    println!("cargo:rustc-check-cfg=cfg(rust_secp_no_symbol_renaming)");
    let namespace = Namespace::configured();
    let prefix = namespace
        .as_ref()
        .map(Namespace::prefix)
        .unwrap_or_default();
    println!("cargo:rustc-env=KONTOR_SECP_PREFIX={prefix}");
    let mut sources = Vec::new();
    // Actual build
    let mut base_config = cc::Build::new();
    base_config
        .include("depend/secp256k1/")
        .include("depend/secp256k1/include")
        .include("depend/secp256k1/src")
        .flag_if_supported("-Wno-unused-function") // some ecmult stuff is defined but not used upstream
        .flag_if_supported("-Wno-unused-parameter") // patching out printf causes this warning
        .define("SECP256K1_API", Some(""))
        .define("ENABLE_MODULE_ECDH", Some("1"))
        .define("ENABLE_MODULE_SCHNORRSIG", Some("1"))
        .define("ENABLE_MODULE_EXTRAKEYS", Some("1"))
        .define("ENABLE_MODULE_ELLSWIFT", Some("1"))
        // upstream sometimes introduces calls to printf, which we cannot compile
        // with WASM due to its lack of libc. printf is never necessary and we can
        // just #define it away.
        .define("printf(...)", Some(""));

    if cfg!(feature = "lowmemory") {
        base_config.define("ECMULT_WINDOW_SIZE", Some("4")); // A low-enough value to consume negligible memory
        base_config.define("ECMULT_GEN_PREC_BITS", Some("2"));
    } else {
        base_config.define("ECMULT_GEN_PREC_BITS", Some("4"));
        base_config.define("ECMULT_WINDOW_SIZE", Some("15")); // This is the default in the configure file (`auto`)
    }
    base_config.define("USE_EXTERNAL_DEFAULT_CALLBACKS", Some("1"));
    #[cfg(feature = "recovery")]
    base_config.define("ENABLE_MODULE_RECOVERY", Some("1"));

    // WASM headers and size/align defines.
    if env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "wasm32" {
        base_config.include("wasm/wasm-sysroot");
        sources.push(PathBuf::from("wasm/wasm.c"));
    }

    sources.extend(
        [
            "depend/secp256k1/contrib/lax_der_parsing.c",
            "depend/secp256k1/src/precomputed_ecmult_gen.c",
            "depend/secp256k1/src/precomputed_ecmult.c",
            "depend/secp256k1/src/secp256k1.c",
        ]
        .map(PathBuf::from),
    );

    if let Some(namespace) = namespace {
        namespace.require_preprocessable_target();
        if compile_namespaced(&base_config, &sources, &namespace).is_err() {
            base_config.include("wasm/wasm-sysroot");
            compile_namespaced(&base_config, &sources, &namespace).unwrap();
        }
    } else {
        base_config.files(&sources);
        if base_config.try_compile("libsecp256k1.a").is_err() {
            base_config.include("wasm/wasm-sysroot");
            base_config.compile("libsecp256k1.a");
        }
    }
}

fn compile_namespaced(
    config: &cc::Build,
    sources: &[PathBuf],
    namespace: &Namespace,
) -> Result<(), Box<dyn Error>> {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("namespaced");
    let generated = preprocess_sources(config, sources, &out_dir, |name| {
        name.starts_with("rustsecp256k1_v0_10_0_")
            .then(|| namespace.symbol(name))
    })?;
    config
        .clone()
        .files(generated)
        .try_compile("libsecp256k1.a")?;
    Ok(())
}
