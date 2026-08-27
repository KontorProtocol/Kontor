//! The single source of the built-in WIT data types.
//!
//! The `kontor:built-in` data interfaces are generated into Rust exactly ONCE,
//! here; every other consumer aliases this family instead of generating its
//! own — the host (wasmtime `bindgen!`) via an interface-level `with:` onto
//! [`host_facade`], and (in a later stage) contracts via wit-bindgen's `with:`.
//! Hand-written behavior on these types lives HERE as ordinary owned impls —
//! the replacement for the write-once-expand-twice `impls!()` pattern, which
//! existed only because two bindgens produced twin type families that no crate
//! owned.
//!
//! The `host` feature injects wasmtime's component-model derives (plus the
//! per-field/case `#[component(name = "...")]` mappings wasmtime's own
//! generated types carry) through wit-bindgen's targeted attributes, so the
//! one type family lifts/lowers on the host side too. wasmtime emits
//! compile-time layout assertions (`SIZE32`/`ALIGN32`) against remapped types,
//! so a divergence fails the build.

#![no_std]

extern crate alloc;

wit_bindgen::generate!({
    world: "shared",
    path: "wit",
    generate_all,
    generate_unused_types: true,
    additional_derives: [stdlib::Wavey],
    additional_type_attributes: {
        "kontor:built-in/context-types/out-point": [
            #[derive(stdlib::Storage)]
            #[cfg_attr(feature = "host", derive(wasmtime::component::ComponentType, wasmtime::component::Lift, wasmtime::component::Lower, serde::Deserialize))]
            #[cfg_attr(feature = "host", component(record))]
        ],
        "kontor:built-in/context-types/contract-address": [
            #[derive(stdlib::Storage)]
            #[cfg_attr(feature = "host", derive(wasmtime::component::ComponentType, wasmtime::component::Lift, wasmtime::component::Lower, serde::Deserialize))]
            #[cfg_attr(feature = "host", component(record))]
        ],
        "kontor:built-in/context-types/holder-ref": [
            #[derive(stdlib::Storage)]
            #[cfg_attr(feature = "host", derive(wasmtime::component::ComponentType, wasmtime::component::Lift, wasmtime::component::Lower, serde::Deserialize))]
            #[cfg_attr(feature = "host", component(variant))]
        ],
        "kontor:built-in/context-types/signer-ref": [
            #[derive(stdlib::Storage)]
            #[cfg_attr(feature = "host", derive(wasmtime::component::ComponentType, wasmtime::component::Lift, wasmtime::component::Lower, serde::Deserialize))]
            #[cfg_attr(feature = "host", component(variant))]
        ],
        "kontor:built-in/context-types/network": [
            #[derive(stdlib::Storage)]
            #[cfg_attr(feature = "host", derive(wasmtime::component::ComponentType, wasmtime::component::Lift, wasmtime::component::Lower, serde::Deserialize))]
            #[cfg_attr(feature = "host", component(enum))]
        ],
        "kontor:built-in/numbers-types/integer": [
            #[derive(stdlib::Storage)]
            #[cfg_attr(feature = "host", derive(wasmtime::component::ComponentType, wasmtime::component::Lift, wasmtime::component::Lower, serde::Deserialize))]
            #[cfg_attr(feature = "host", component(record))]
        ],
        "kontor:built-in/numbers-types/decimal": [
            #[derive(stdlib::Storage)]
            #[cfg_attr(feature = "host", derive(wasmtime::component::ComponentType, wasmtime::component::Lift, wasmtime::component::Lower, serde::Deserialize))]
            #[cfg_attr(feature = "host", component(record))]
        ],
        "kontor:built-in/numbers-types/sign": [
            #[derive(stdlib::Storage)]
            #[cfg_attr(feature = "host", derive(wasmtime::component::ComponentType, wasmtime::component::Lift, wasmtime::component::Lower, serde::Deserialize))]
            #[cfg_attr(feature = "host", component(enum))]
        ],
        "kontor:built-in/numbers-types/ordering": [
            #[derive(stdlib::Storage)]
            #[cfg_attr(feature = "host", derive(wasmtime::component::ComponentType, wasmtime::component::Lift, wasmtime::component::Lower, serde::Deserialize))]
            #[cfg_attr(feature = "host", component(enum))]
        ],
        "kontor:built-in/error/error": [
            #[derive(stdlib::Storage)]
            #[cfg_attr(feature = "host", derive(wasmtime::component::ComponentType, wasmtime::component::Lift, wasmtime::component::Lower, serde::Deserialize))]
            #[cfg_attr(feature = "host", component(variant))]
        ],
        "kontor:built-in/file-registry-types/raw-file-descriptor": [
            #[derive(stdlib::Storage)]
            #[cfg_attr(feature = "host", derive(wasmtime::component::ComponentType, wasmtime::component::Lift, wasmtime::component::Lower, serde::Deserialize))]
            #[cfg_attr(feature = "host", component(record))]
        ],
        "kontor:built-in/file-registry-types/challenge-input": [
            #[derive(stdlib::Storage)]
            #[cfg_attr(feature = "host", derive(wasmtime::component::ComponentType, wasmtime::component::Lift, wasmtime::component::Lower, serde::Deserialize))]
            #[cfg_attr(feature = "host", component(record))]
        ],
        "kontor:built-in/file-registry-types/verify-result": [
            #[derive(stdlib::Storage)]
            #[cfg_attr(feature = "host", derive(wasmtime::component::ComponentType, wasmtime::component::Lift, wasmtime::component::Lower, serde::Deserialize))]
            #[cfg_attr(feature = "host", component(enum))]
        ],
    },
    additional_member_attributes: {
        "kontor:built-in/context-types/out-point.txid": [ #[cfg_attr(feature = "host", component(name = "txid"))] ],
        "kontor:built-in/context-types/out-point.vout": [ #[cfg_attr(feature = "host", component(name = "vout"))] ],
        "kontor:built-in/context-types/contract-address.name": [ #[cfg_attr(feature = "host", component(name = "name"))] ],
        "kontor:built-in/context-types/contract-address.height": [ #[cfg_attr(feature = "host", component(name = "height"))] ],
        "kontor:built-in/context-types/contract-address.tx-index": [ #[cfg_attr(feature = "host", component(name = "tx-index"))] ],
        "kontor:built-in/context-types/holder-ref.x-only-pubkey": [ #[cfg_attr(feature = "host", component(name = "x-only-pubkey"))] ],
        "kontor:built-in/context-types/holder-ref.signer-id": [ #[cfg_attr(feature = "host", component(name = "signer-id"))] ],
        "kontor:built-in/context-types/holder-ref.core": [ #[cfg_attr(feature = "host", component(name = "core"))] ],
        "kontor:built-in/context-types/holder-ref.burner": [ #[cfg_attr(feature = "host", component(name = "burner"))] ],
        "kontor:built-in/context-types/holder-ref.utxo": [ #[cfg_attr(feature = "host", component(name = "utxo"))] ],
        "kontor:built-in/context-types/signer-ref.signer-id": [ #[cfg_attr(feature = "host", component(name = "signer-id"))] ],
        "kontor:built-in/context-types/signer-ref.x-only-pubkey": [ #[cfg_attr(feature = "host", component(name = "x-only-pubkey"))] ],
        "kontor:built-in/context-types/network.mainnet": [ #[cfg_attr(feature = "host", component(name = "mainnet"))] ],
        "kontor:built-in/context-types/network.signet": [ #[cfg_attr(feature = "host", component(name = "signet"))] ],
        "kontor:built-in/context-types/network.testnet": [ #[cfg_attr(feature = "host", component(name = "testnet"))] ],
        "kontor:built-in/context-types/network.regtest": [ #[cfg_attr(feature = "host", component(name = "regtest"))] ],
        "kontor:built-in/numbers-types/integer.r0": [ #[cfg_attr(feature = "host", component(name = "r0"))] ],
        "kontor:built-in/numbers-types/integer.r1": [ #[cfg_attr(feature = "host", component(name = "r1"))] ],
        "kontor:built-in/numbers-types/integer.r2": [ #[cfg_attr(feature = "host", component(name = "r2"))] ],
        "kontor:built-in/numbers-types/integer.r3": [ #[cfg_attr(feature = "host", component(name = "r3"))] ],
        "kontor:built-in/numbers-types/integer.sign": [ #[cfg_attr(feature = "host", component(name = "sign"))] ],
        "kontor:built-in/numbers-types/decimal.r0": [ #[cfg_attr(feature = "host", component(name = "r0"))] ],
        "kontor:built-in/numbers-types/decimal.r1": [ #[cfg_attr(feature = "host", component(name = "r1"))] ],
        "kontor:built-in/numbers-types/decimal.r2": [ #[cfg_attr(feature = "host", component(name = "r2"))] ],
        "kontor:built-in/numbers-types/decimal.r3": [ #[cfg_attr(feature = "host", component(name = "r3"))] ],
        "kontor:built-in/numbers-types/decimal.sign": [ #[cfg_attr(feature = "host", component(name = "sign"))] ],
        "kontor:built-in/numbers-types/sign.plus": [ #[cfg_attr(feature = "host", component(name = "plus"))] ],
        "kontor:built-in/numbers-types/sign.minus": [ #[cfg_attr(feature = "host", component(name = "minus"))] ],
        "kontor:built-in/numbers-types/ordering.less": [ #[cfg_attr(feature = "host", component(name = "less"))] ],
        "kontor:built-in/numbers-types/ordering.equal": [ #[cfg_attr(feature = "host", component(name = "equal"))] ],
        "kontor:built-in/numbers-types/ordering.greater": [ #[cfg_attr(feature = "host", component(name = "greater"))] ],
        "kontor:built-in/error/error.message": [ #[cfg_attr(feature = "host", component(name = "message"))] ],
        "kontor:built-in/error/error.overflow": [ #[cfg_attr(feature = "host", component(name = "overflow"))] ],
        "kontor:built-in/error/error.div-by-zero": [ #[cfg_attr(feature = "host", component(name = "div-by-zero"))] ],
        "kontor:built-in/error/error.syntax": [ #[cfg_attr(feature = "host", component(name = "syntax"))] ],
        "kontor:built-in/error/error.validation": [ #[cfg_attr(feature = "host", component(name = "validation"))] ],
        "kontor:built-in/file-registry-types/raw-file-descriptor.file-id": [ #[cfg_attr(feature = "host", component(name = "file-id"))] ],
        "kontor:built-in/file-registry-types/raw-file-descriptor.object-id": [ #[cfg_attr(feature = "host", component(name = "object-id"))] ],
        "kontor:built-in/file-registry-types/raw-file-descriptor.nonce": [ #[cfg_attr(feature = "host", component(name = "nonce"))] ],
        "kontor:built-in/file-registry-types/raw-file-descriptor.root": [ #[cfg_attr(feature = "host", component(name = "root"))] ],
        "kontor:built-in/file-registry-types/raw-file-descriptor.padded-len": [ #[cfg_attr(feature = "host", component(name = "padded-len"))] ],
        "kontor:built-in/file-registry-types/raw-file-descriptor.original-size": [ #[cfg_attr(feature = "host", component(name = "original-size"))] ],
        "kontor:built-in/file-registry-types/raw-file-descriptor.filename": [ #[cfg_attr(feature = "host", component(name = "filename"))] ],
        "kontor:built-in/file-registry-types/challenge-input.challenge-id": [ #[cfg_attr(feature = "host", component(name = "challenge-id"))] ],
        "kontor:built-in/file-registry-types/challenge-input.file": [ #[cfg_attr(feature = "host", component(name = "file"))] ],
        "kontor:built-in/file-registry-types/challenge-input.block-height": [ #[cfg_attr(feature = "host", component(name = "block-height"))] ],
        "kontor:built-in/file-registry-types/challenge-input.num-challenges": [ #[cfg_attr(feature = "host", component(name = "num-challenges"))] ],
        "kontor:built-in/file-registry-types/challenge-input.seed": [ #[cfg_attr(feature = "host", component(name = "seed"))] ],
        "kontor:built-in/file-registry-types/challenge-input.prover-id": [ #[cfg_attr(feature = "host", component(name = "prover-id"))] ],
        "kontor:built-in/file-registry-types/verify-result.verified": [ #[cfg_attr(feature = "host", component(name = "verified"))] ],
        "kontor:built-in/file-registry-types/verify-result.rejected": [ #[cfg_attr(feature = "host", component(name = "rejected"))] ],
        "kontor:built-in/file-registry-types/verify-result.invalid": [ #[cfg_attr(feature = "host", component(name = "invalid"))] ],
    },
    runtime_path: "stdlib::wit_bindgen::rt",
    async: false,
});

pub use kontor::built_in::file_registry_types;
// The generated models' `try_update_*` path names `crate::error::Error`.
pub use kontor::built_in::context;
pub use kontor::built_in::context_types;
pub use kontor::built_in::error;
pub use kontor::built_in::numbers;
pub use kontor::built_in::numbers_types;

// This crate OWNS the guest context wrappers, so it is exempt from the
// workspace `disallowed-types` fence that keeps host code (which reaches these
// types transitively, but for which they are unreachable-stub decoys) off them.
#[allow(clippy::disallowed_types)]
mod impls;

// Owned behavior on the shared types — written once here, where the types
// live, instead of expanded per bindgen family (the old impls.rs pattern).
impl PartialEq for file_registry_types::RawFileDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.file_id == other.file_id
            && self.object_id == other.object_id
            && self.nonce == other.nonce
            && self.root == other.root
            && self.padded_len == other.padded_len
            && self.original_size == other.original_size
            && self.filename == other.filename
    }
}

impl Eq for file_registry_types::RawFileDescriptor {}

/// The modules the host `bindgen!`'s interface-level `with:` points at, one per
/// types-only interface. wasmtime expects the module shape of a previously
/// generated interface — for a types-only interface that is the types plus an
/// empty `Host`, a `HostWithStore<T>`, and an `add_to_linker` that registers
/// the instance name and links nothing. The trait/function shapes are copied
/// from wasmtime 48's own generated output (verified identical under the
/// `async | store | trappable` import options the runtime uses); any drift in
/// a future wasmtime is a compile error at the world's `add_to_linker` call
/// site, not a runtime surprise.
#[cfg(feature = "host")]
macro_rules! types_only_host_facade {
    ($name:ident, $instance:literal, { $($reexport:tt)* }) => {
        pub mod $name {
            $($reexport)*

            pub trait HostWithStore<T>: wasmtime::component::HasData {}
            impl<H: ?Sized, T> HostWithStore<T> for H where H: wasmtime::component::HasData {}
            pub trait Host {}
            impl<_T: Host + ?Sized> Host for &mut _T {}

            pub fn add_to_linker_instance<T, D>(
                _inst: &mut wasmtime::component::LinkerInstance<'_, T>,
                _host_getter: fn(&mut T) -> D::Data<'_>,
            ) -> wasmtime::Result<()>
            where
                D: HostWithStore<T>,
                for<'a> D::Data<'a>: Host,
                T: 'static,
            {
                Ok(())
            }

            pub fn add_to_linker<T, D>(
                linker: &mut wasmtime::component::Linker<T>,
                host_getter: fn(&mut T) -> D::Data<'_>,
            ) -> wasmtime::Result<()>
            where
                D: HostWithStore<T>,
                for<'a> D::Data<'a>: Host,
                T: 'static,
            {
                let mut inst = linker.instance($instance)?;
                add_to_linker_instance::<T, D>(&mut inst, host_getter)
            }
        }
    };
}

#[cfg(feature = "host")]
types_only_host_facade!(host_facade, "kontor:built-in/file-registry-types", {
    pub use crate::file_registry_types::{ChallengeInput, RawFileDescriptor, VerifyResult};
});

#[cfg(feature = "host")]
types_only_host_facade!(
    host_facade_numbers_types,
    "kontor:built-in/numbers-types",
    {
        pub use crate::numbers_types::{Decimal, Integer, Ordering, Sign};
    }
);

#[cfg(feature = "host")]
types_only_host_facade!(host_facade_error, "kontor:built-in/error", {
    pub use crate::error::Error;
});

#[cfg(feature = "host")]
types_only_host_facade!(
    host_facade_context_types,
    "kontor:built-in/context-types",
    {
        pub use crate::context_types::{ContractAddress, HolderRef, Network, OutPoint, SignerRef};
    }
);
