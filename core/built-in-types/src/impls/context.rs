//! The context family: stdlib traits + grammars on the shared data types
//! (ContractAddress, HolderRef, Network, …) and the guest-side plumbing on the
//! context resource wrappers (storage traits, Holder/Signer identity impls).

use alloc::string::String;

use crate::kontor;
use crate::kontor::built_in::context;

// --- context data types (moved from the retired `impls!` macro and the
// per-contract glue; stdlib traits + grammars on types this crate owns) ---

// The grammar macros expand bare identifiers (`Vec`, `OutPoint`, `format!`,
// `ToString`) — the same scope `contract!`'s preamble provided is recreated in
// this module (the trait impls they emit are globally visible regardless).
mod grammar {
    #[allow(unused_imports)]
    use alloc::{
        format,
        string::{String, ToString},
        vec::Vec,
    };

    use crate::kontor;
    #[allow(unused_imports)]
    use crate::kontor::built_in::context_types::OutPoint;

    stdlib::contract_address!(kontor::built_in::context_types::ContractAddress);
    stdlib::holder_ref!(kontor::built_in::context_types::HolderRef);
}

impl kontor::built_in::context_types::Network {
    /// True on the production Bitcoin mainnet chain.
    pub fn is_mainnet(&self) -> bool {
        matches!(self, kontor::built_in::context_types::Network::Mainnet)
    }
    /// True on the local regtest chain (dev/test).
    pub fn is_regtest(&self) -> bool {
        matches!(self, kontor::built_in::context_types::Network::Regtest)
    }
}

// `SignerRef` is the two real-account arms of `HolderRef`; widening it is
// total. Lets `detach` turn an op-return recipient into a `HolderRef` (then a
// `Holder`) directly.
impl From<kontor::built_in::context_types::SignerRef>
    for kontor::built_in::context_types::HolderRef
{
    fn from(signer_ref: kontor::built_in::context_types::SignerRef) -> Self {
        match signer_ref {
            kontor::built_in::context_types::SignerRef::SignerId(id) => Self::SignerId(id),
            kontor::built_in::context_types::SignerRef::XOnlyPubkey(pk) => Self::XOnlyPubkey(pk),
        }
    }
}

/// `#[index]` on a ContractAddress field buckets by its canonical string.
impl stdlib::IndexKey for kontor::built_in::context_types::ContractAddress {
    fn index_key(&self) -> alloc::vec::Vec<u8> {
        stdlib::KeyElement::encode(&alloc::string::ToString::to_string(self))
    }
}

impl<__S: stdlib::ReadStorage + 'static> stdlib::Retrieve<__S>
    for kontor::built_in::context_types::ContractAddress
{
    fn __get(ctx: &alloc::rc::Rc<__S>, path: stdlib::KeyPath) -> Option<Self> {
        stdlib::ReadStorage::__exists(ctx, &path).then(|| {
            kontor::built_in::context_types::ContractAddressModel::new(ctx.clone(), path).load()
        })
    }
}

impl<__S: stdlib::ReadStorage> stdlib::Retrieve<__S>
    for kontor::built_in::context_types::HolderRef
{
    fn __get(ctx: &alloc::rc::Rc<__S>, path: stdlib::KeyPath) -> Option<Self> {
        let s: String = stdlib::ReadStorage::__get(ctx, path)?;
        s.parse().ok()
    }
}

// ─── Guest-side context plumbing, written once ──────────────────────────────
// Everything below was expanded verbatim into every contract crate while the
// `context` interface was generated per-crate; the `with:` remap makes this
// crate the owner. On native targets the resource methods are wit-bindgen's
// unreachable stubs — the host never touches these wrappers (its context
// resources are Runtime-backed host objects); they compile natively only so
// this crate builds in the indexer's dependency graph.

impl stdlib::HasNext for context::Keys {
    fn next(&self) -> Option<alloc::vec::Vec<u8>> {
        // Resolves to the inherent resource method (inherent wins over trait).
        self.next()
    }
}

impl stdlib::HasNextRow for context::IndexRows {
    fn next(&self) -> Option<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>)> {
        self.next()
    }
}

impl stdlib::ReadStorage for context::ViewStorage {
    fn __get_str(self: &alloc::rc::Rc<Self>, path: &[u8]) -> Option<String> {
        self.get_str(path)
    }

    fn __get_u64(self: &alloc::rc::Rc<Self>, path: &[u8]) -> Option<u64> {
        self.get_u64(path)
    }

    fn __get_s64(self: &alloc::rc::Rc<Self>, path: &[u8]) -> Option<i64> {
        self.get_s64(path)
    }

    fn __get_bool(self: &alloc::rc::Rc<Self>, path: &[u8]) -> Option<bool> {
        self.get_bool(path)
    }

    fn __get_list_u8(self: &alloc::rc::Rc<Self>, path: &[u8]) -> Option<alloc::vec::Vec<u8>> {
        self.get_list_u8(path)
    }

    fn __get_keys_range<T: stdlib::KeyElement + Clone>(
        self: &alloc::rc::Rc<Self>,
        path: &[u8],
        lo: Option<&[u8]>,
        hi: Option<&[u8]>,
        descending: bool,
    ) -> impl Iterator<Item = T> + use<T> {
        stdlib::make_keys_iterator(self.get_keys(path, lo, hi, descending))
    }

    fn __get_index_rows_range(
        self: &alloc::rc::Rc<Self>,
        path: &[u8],
        lo: Option<&[u8]>,
        hi: Option<&[u8]>,
        descending: bool,
    ) -> impl Iterator<Item = (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>)> + use<> {
        stdlib::make_index_rows_iterator(self.get_index_rows(path, lo, hi, descending))
    }

    fn __exists(self: &alloc::rc::Rc<Self>, path: &[u8]) -> bool {
        self.exists(path)
    }

    fn __extend_path_with_match(
        self: &alloc::rc::Rc<Self>,
        path: &[u8],
        candidates: &[alloc::vec::Vec<u8>],
    ) -> Option<u32> {
        self.extend_path_with_match(path, candidates)
    }

    fn __get<T: stdlib::Retrieve<Self>>(
        self: &alloc::rc::Rc<Self>,
        path: stdlib::KeyPath,
    ) -> Option<T> {
        T::__get(self, path)
    }
}

impl stdlib::ReadStorage for context::ProcStorage {
    fn __get_str(self: &alloc::rc::Rc<Self>, path: &[u8]) -> Option<String> {
        self.get_str(path)
    }

    fn __get_u64(self: &alloc::rc::Rc<Self>, path: &[u8]) -> Option<u64> {
        self.get_u64(path)
    }

    fn __get_s64(self: &alloc::rc::Rc<Self>, path: &[u8]) -> Option<i64> {
        self.get_s64(path)
    }

    fn __get_bool(self: &alloc::rc::Rc<Self>, path: &[u8]) -> Option<bool> {
        self.get_bool(path)
    }

    fn __get_list_u8(self: &alloc::rc::Rc<Self>, path: &[u8]) -> Option<alloc::vec::Vec<u8>> {
        self.get_list_u8(path)
    }

    fn __get_keys_range<T: stdlib::KeyElement + Clone>(
        self: &alloc::rc::Rc<Self>,
        path: &[u8],
        lo: Option<&[u8]>,
        hi: Option<&[u8]>,
        descending: bool,
    ) -> impl Iterator<Item = T> + use<T> {
        stdlib::make_keys_iterator(self.get_keys(path, lo, hi, descending))
    }

    fn __get_index_rows_range(
        self: &alloc::rc::Rc<Self>,
        path: &[u8],
        lo: Option<&[u8]>,
        hi: Option<&[u8]>,
        descending: bool,
    ) -> impl Iterator<Item = (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>)> + use<> {
        stdlib::make_index_rows_iterator(self.get_index_rows(path, lo, hi, descending))
    }

    fn __exists(self: &alloc::rc::Rc<Self>, path: &[u8]) -> bool {
        self.exists(path)
    }

    fn __extend_path_with_match(
        self: &alloc::rc::Rc<Self>,
        path: &[u8],
        candidates: &[alloc::vec::Vec<u8>],
    ) -> Option<u32> {
        self.extend_path_with_match(path, candidates)
    }

    fn __get<T: stdlib::Retrieve<Self>>(
        self: &alloc::rc::Rc<Self>,
        path: stdlib::KeyPath,
    ) -> Option<T> {
        T::__get(self, path)
    }
}

impl stdlib::WriteStorage for context::ProcStorage {
    fn __set_str(self: &alloc::rc::Rc<Self>, path: &[u8], value: &str) {
        self.set_str(path, value)
    }

    fn __set_u64(self: &alloc::rc::Rc<Self>, path: &[u8], value: u64) {
        self.set_u64(path, value)
    }

    fn __set_s64(self: &alloc::rc::Rc<Self>, path: &[u8], value: i64) {
        self.set_s64(path, value)
    }

    fn __set_bool(self: &alloc::rc::Rc<Self>, path: &[u8], value: bool) {
        self.set_bool(path, value)
    }

    fn __set_list_u8(self: &alloc::rc::Rc<Self>, path: &[u8], value: alloc::vec::Vec<u8>) {
        self.set_list_u8(path, &value)
    }

    fn __set_void(self: &alloc::rc::Rc<Self>, path: &[u8]) {
        self.set_void(path)
    }

    fn __set<T: stdlib::Store<Self>>(self: &alloc::rc::Rc<Self>, path: stdlib::KeyPath, value: T) {
        T::__set(self, path, value)
    }

    fn __delete(self: &alloc::rc::Rc<Self>, path: &[u8]) -> bool {
        self.delete(path)
    }

    fn __delete_matching_paths(
        self: &alloc::rc::Rc<Self>,
        base_path: &[u8],
        candidates: &[alloc::vec::Vec<u8>],
    ) -> u64 {
        self.delete_matching_paths(base_path, candidates)
    }
}

// The write-model side of every generated model reads through the proc
// storage's derived VIEW handle; this trait link is what keeps the generated
// models generic over the storage handle.
impl stdlib::HasViewStorage for context::ProcStorage {
    type View = context::ViewStorage;
    fn view_storage(&self) -> Self::View {
        context::ProcStorage::view_storage(self)
    }
}

// Holder is serialized via its canonical key string (same as the
// `Map<Holder, _>` key pattern). Reads parse via `FromStr` and return `None`
// on a missing entry. Holder is a WIT resource, so wit-bindgen doesn't
// auto-apply `#[derive(Storage)]` the way it does for HolderRef — its
// Retrieve/Store are defined directly here.
impl<__S: stdlib::ReadStorage> stdlib::Retrieve<__S> for context::Holder {
    fn __get(ctx: &alloc::rc::Rc<__S>, path: stdlib::KeyPath) -> Option<Self> {
        let s: String = stdlib::ReadStorage::__get(ctx, path)?;
        s.parse().ok()
    }
}

impl<__S: stdlib::WriteStorage + ?Sized> stdlib::Store<__S> for context::Holder {
    fn __set(ctx: &alloc::rc::Rc<__S>, path: stdlib::KeyPath, value: Self) {
        stdlib::WriteStorage::__set_str(ctx, &path, &alloc::string::ToString::to_string(&value));
    }
}

// A `Map<Holder, _>` keys on the Holder's canonical string identity: it
// encodes as a string element (`Display`) and decodes via `FromStr`.
stdlib::key_element_via_display!(context::Holder);

/// `#[index]` on a Holder field buckets by its canonical string.
impl stdlib::IndexKey for context::Holder {
    fn index_key(&self) -> alloc::vec::Vec<u8> {
        stdlib::KeyElement::encode(&alloc::string::ToString::to_string(self))
    }
}

// Identity behavior on the Signer/Holder handle wrappers: Holder round-trips
// through its canonical HolderRef, Signer projects to one.
impl core::fmt::Display for context::Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.key())
    }
}

impl core::fmt::Display for context::Holder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.key())
    }
}

impl Clone for context::Holder {
    fn clone(&self) -> Self {
        context::Holder::from_ref(&self.as_ref()).expect("clone of valid Holder failed")
    }
}

impl PartialEq for context::Holder {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}

impl Eq for context::Holder {}

impl core::str::FromStr for context::Holder {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let holder_ref: kontor::built_in::context_types::HolderRef = s.parse()?;
        context::Holder::from_ref(&holder_ref).map_err(|e| alloc::format!("{:?}", e))
    }
}

impl TryFrom<kontor::built_in::context_types::HolderRef> for context::Holder {
    type Error = kontor::built_in::error::Error;

    fn try_from(
        holder_ref: kontor::built_in::context_types::HolderRef,
    ) -> Result<Self, Self::Error> {
        context::Holder::from_ref(&holder_ref)
    }
}

impl TryFrom<&kontor::built_in::context_types::HolderRef> for context::Holder {
    type Error = kontor::built_in::error::Error;

    fn try_from(
        holder_ref: &kontor::built_in::context_types::HolderRef,
    ) -> Result<Self, Self::Error> {
        context::Holder::from_ref(holder_ref)
    }
}

impl From<&context::Signer> for context::Holder {
    fn from(signer: &context::Signer) -> Self {
        signer.as_holder()
    }
}

impl From<context::Signer> for context::Holder {
    fn from(signer: context::Signer) -> Self {
        signer.as_holder()
    }
}

impl From<&context::Signer> for kontor::built_in::context_types::HolderRef {
    fn from(signer: &context::Signer) -> Self {
        signer.as_ref()
    }
}

impl From<context::Signer> for kontor::built_in::context_types::HolderRef {
    fn from(signer: context::Signer) -> Self {
        signer.as_ref()
    }
}

impl From<&context::Holder> for kontor::built_in::context_types::HolderRef {
    fn from(holder: &context::Holder) -> Self {
        holder.as_ref()
    }
}

impl From<context::Holder> for kontor::built_in::context_types::HolderRef {
    fn from(holder: context::Holder) -> Self {
        holder.as_ref()
    }
}
