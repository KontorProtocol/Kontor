use darling::FromMeta;
use heck::{ToPascalCase, ToSnakeCase};
use proc_macro2::TokenStream;
use quote::quote;
use std::collections::BTreeMap;
use std::path::Path;
use syn::Ident;
use wit_parser::Resolve;
use wit_validator::Validator;

#[derive(FromMeta)]
pub struct Config {
    name: String,
    path: Option<String>,
    /// Secondary-index declarations on WIT records stored in an `IndexedMap`.
    /// Semicolon-separated entries, each `record: name [by field] [sort field]`
    /// (kebab-case, as in the WIT); `record: field` is sugar for a single-field
    /// index. E.g.
    /// ```text
    /// indexed = "
    ///   agreement-data: active;
    ///   challenge-data: status;
    ///   challenge-data: due by status sort deadline-height;
    /// "
    /// ```
    /// `contract!` injects the matching struct-level `#[index(...)]` plus
    /// `#[derive(stdlib::Indexed)]` on each record (via the forked wit-bindgen) so
    /// the generated model maintains the index. `by`/`sort` fields are mapped to
    /// the generated snake_case Rust field names.
    indexed: Option<String>,
}

/// Translate one `name [by field…] [sort field]` entry (the part after `record:`)
/// into the Rust struct-level attribute string `#[index(name, by = …, sort = …)]`.
/// `by` takes one or more fields (a composite bucket), consuming tokens up to the
/// next `sort` or the end. kebab names map to the generated snake_case Rust idents.
fn index_attr(spec: &str) -> String {
    let mut tokens = spec.split_whitespace().peekable();
    let name = tokens
        .next()
        .unwrap_or_else(|| panic!("`indexed` entry is missing an index name: {spec:?}"))
        .to_snake_case();
    let mut by: Vec<String> = Vec::new();
    let mut sort: Option<String> = None;
    while let Some(keyword) = tokens.next() {
        match keyword {
            "by" => {
                while let Some(field) = tokens.next_if(|t| *t != "sort") {
                    by.push(field.to_snake_case());
                }
                if by.is_empty() {
                    panic!("`by` needs at least one field in indexed entry: {spec:?}");
                }
            }
            "sort" => {
                let field = tokens
                    .next()
                    .unwrap_or_else(|| panic!("`sort` needs a field in indexed entry: {spec:?}"));
                sort = Some(field.to_snake_case());
            }
            other => {
                panic!("unexpected `{other}` in indexed entry (expected `by`/`sort`): {spec:?}")
            }
        }
    }
    let mut args = name;
    match by.as_slice() {
        [] => {}
        [one] => args.push_str(&format!(", by = {one}")),
        many => args.push_str(&format!(", by = ({})", many.join(", "))),
    }
    if let Some(sort) = sort {
        args.push_str(&format!(", sort = {sort}"));
    }
    format!("#[index({args})]")
}

/// Build the `additional_type_attributes` option tokens for the wit-bindgen
/// `generate!` from the `indexed` spec: `#[derive(stdlib::Indexed)]` once per
/// record plus one `#[index(...)]` per declared index. The fork emits each as its
/// own attribute line on the (owned) record, and the `Indexed`/`Model` derives
/// parse them via the shared index-declaration grammar. (Storage enums are NOT
/// injected here — the fork applies type attributes only to records, not
/// enums/variants — they're generated directly from the WIT, see
/// [`storage_enum_impls`].)
fn index_attr_options(indexed: Option<&str>) -> TokenStream {
    let Some(spec) = indexed else {
        return quote! {};
    };
    // record (kebab wit name) -> its `#[index(...)]` lines, in declared order.
    // BTreeMap keeps the emitted output deterministic across runs.
    let mut by_record: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in spec.split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (record, rest) = entry.split_once(':').unwrap_or_else(|| {
            panic!("`indexed` entry must be `record: name [by field] [sort field]`: {entry:?}")
        });
        by_record
            .entry(record.trim().to_string())
            .or_default()
            .push(index_attr(rest.trim()));
    }
    if by_record.is_empty() {
        return quote! {};
    }
    let mut type_pairs = Vec::new();
    for (record, attrs) in by_record {
        type_pairs.push(quote! { #record: "#[derive(stdlib::Indexed)]", });
        for attr in attrs {
            type_pairs.push(quote! { #record: #attr, });
        }
    }
    quote! { additional_type_attributes: { #(#type_pairs)* }, }
}

pub fn generate(config: Config) -> TokenStream {
    let name = Ident::from_string(&config.name.to_pascal_case()).unwrap();
    let abs_path = Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .canonicalize()
        .expect("Failed to canonicalize manifest directory")
        .join(config.path.unwrap_or("wit".to_string()));
    if !abs_path.exists() {
        panic!("Path does not exist: {}", abs_path.display());
    }

    let mut resolve = Resolve::new();
    resolve
        .push_dir(&abs_path)
        .unwrap_or_else(|e| panic!("Failed to parse WIT at {}: {}", abs_path.display(), e));

    let result = Validator::validate_resolve(&resolve);
    if result.has_errors() {
        let error_messages: Vec<String> =
            result.errors.iter().map(|e| format!("  - {}", e)).collect();
        panic!(
            "WIT validation failed for {}:\n{}",
            abs_path.display(),
            error_messages.join("\n")
        );
    }

    let path = abs_path.to_string_lossy().to_string();
    let type_attrs = index_attr_options(config.indexed.as_deref());
    quote! {
        extern crate alloc;

        use alloc::{
            format,
            string::{String, ToString},
            vec::Vec,
        };

        wit_bindgen::generate!({
            world: "root",
            path: #path,
            generate_all,
            generate_unused_types: true,
            additional_derives: [stdlib::Storage, stdlib::Wavey],
            #type_attrs
            export_macro_name: "__export__",
            runtime_path: "stdlib::wit_bindgen::rt",
            async: false,
        });

        use kontor::built_in::*;
        use kontor::built_in::context::{Holder, OutPoint};
        use kontor::built_in::context::{ContractAddressModel, ContractAddressWriteModel};
        use kontor::built_in::numbers::{IntegerModel, IntegerWriteModel, DecimalModel, DecimalWriteModel};

        type Map<K, V> = stdlib::StorageMap<K, V, context::ProcStorage>;
        type IndexedMap<K, V> = stdlib::StorageIndexedMap<K, V, context::ProcStorage>;

        fn BURNER() -> Holder {
            Holder::from_ref(&context::HolderRef::Burner).unwrap()
        }

        fn CORE() -> Holder {
            Holder::from_ref(&context::HolderRef::Core).unwrap()
        }

        impl stdlib::HasNext for context::Keys {
            fn next(&self) -> Option<Vec<u8>> {
                self.next()
            }
        }

        #[automatically_derived]
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

            fn __get_list_u8(self: &alloc::rc::Rc<Self>, path: &[u8]) -> Option<Vec<u8>> {
                self.get_list_u8(path)
            }

            fn __get_keys<T: stdlib::KeyElement + Clone>(self: &alloc::rc::Rc<Self>, path: &[u8]) -> impl Iterator<Item = T> + use<T> {
                stdlib::make_keys_iterator(self.get_keys(path, None))
            }

            fn __exists(self: &alloc::rc::Rc<Self>, path: &[u8]) -> bool {
                self.exists(path)
            }

            fn __extend_path_with_match(self: &alloc::rc::Rc<Self>, path: &[u8], variants: &[&str]) -> Option<String> {
                self.extend_path_with_match(path, &variants.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            }

            fn __get<T: Retrieve<Self>>(self: &alloc::rc::Rc<Self>, path: KeyPath) -> Option<T> {
                T::__get(self, path)
            }
        }

        #[automatically_derived]
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

            fn __get_list_u8(self: &alloc::rc::Rc<Self>, path: &[u8]) -> Option<Vec<u8>> {
                self.get_list_u8(path)
            }

            fn __get_keys<T: stdlib::KeyElement + Clone>(self: &alloc::rc::Rc<Self>, path: &[u8]) -> impl Iterator<Item = T> + use<T> {
                stdlib::make_keys_iterator(self.get_keys(path, None))
            }

            fn __exists(self: &alloc::rc::Rc<Self>, path: &[u8]) -> bool {
                self.exists(path)
            }

            fn __extend_path_with_match(self: &alloc::rc::Rc<Self>, path: &[u8], variants: &[&str]) -> Option<String> {
                self.extend_path_with_match(path, &variants.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            }

            fn __get<T: Retrieve<Self>>(self: &alloc::rc::Rc<Self>, path: KeyPath) -> Option<T> {
                T::__get(self, path)
            }
        }

        #[automatically_derived]
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

            fn __set_list_u8(self: &alloc::rc::Rc<Self>, path: &[u8], value: Vec<u8>) {
                self.set_list_u8(path, &value)
            }

            fn __set_void(self: &alloc::rc::Rc<Self>, path: &[u8]) {
                self.set_void(path)
            }

            fn __set<T: stdlib::Store<Self>>(self: &alloc::rc::Rc<Self>, path: KeyPath, value: T) {
                T::__set(self, path, value)
            }

            fn __delete(self: &alloc::rc::Rc<Self>, path: &[u8]) -> bool {
                self.delete(path)
            }

            fn __delete_matching_paths(self: &alloc::rc::Rc<Self>, base_path: &[u8], variants: &[&str]) -> u64 {
                self.delete_matching_paths(base_path, &variants.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            }
        }

        impl Retrieve<crate::context::ViewStorage> for context::ContractAddress {
            fn __get(ctx: &alloc::rc::Rc<crate::context::ViewStorage>, path: stdlib::KeyPath) -> Option<Self> {
                stdlib::ReadStorage::__exists(ctx, &path).then(|| context::ContractAddressModel::new(ctx.clone(), path).load())
            }
        }

        impl Retrieve<crate::context::ProcStorage> for context::ContractAddress {
            fn __get(ctx: &alloc::rc::Rc<crate::context::ProcStorage>, path: stdlib::KeyPath) -> Option<Self> {
                stdlib::ReadStorage::__exists(ctx, &path).then(|| context::ContractAddressWriteModel::new(ctx.clone(), path).load())
            }
        }

        impl Retrieve<crate::context::ViewStorage> for context::HolderRef {
            fn __get(ctx: &alloc::rc::Rc<crate::context::ViewStorage>, path: stdlib::KeyPath) -> Option<Self> {
                let s: String = stdlib::ReadStorage::__get(ctx, path)?;
                s.parse().ok()
            }
        }

        impl Retrieve<crate::context::ProcStorage> for context::HolderRef {
            fn __get(ctx: &alloc::rc::Rc<crate::context::ProcStorage>, path: stdlib::KeyPath) -> Option<Self> {
                let s: String = stdlib::ReadStorage::__get(ctx, path)?;
                s.parse().ok()
            }
        }

        // Holder is serialized via its canonical key string (same as the
        // `Map<Holder, _>` key pattern). Reads parse via `FromStr` and
        // return `None` on a missing entry; the macro-generated getter's
        // `.unwrap()` surfaces storage corruption as a panic — same
        // behavior as every other primitive field. Holder is a WIT
        // resource, so wit-bindgen doesn't auto-apply `#[derive(Storage)]`
        // the way it does for HolderRef — we define Retrieve/Store
        // directly here.
        impl Retrieve<crate::context::ViewStorage> for context::Holder {
            fn __get(ctx: &alloc::rc::Rc<crate::context::ViewStorage>, path: stdlib::KeyPath) -> Option<Self> {
                let s: String = stdlib::ReadStorage::__get(ctx, path)?;
                s.parse().ok()
            }
        }

        impl Retrieve<crate::context::ProcStorage> for context::Holder {
            fn __get(ctx: &alloc::rc::Rc<crate::context::ProcStorage>, path: stdlib::KeyPath) -> Option<Self> {
                let s: String = stdlib::ReadStorage::__get(ctx, path)?;
                s.parse().ok()
            }
        }

        impl stdlib::Store<crate::context::ProcStorage> for context::Holder {
            fn __set(ctx: &alloc::rc::Rc<crate::context::ProcStorage>, path: stdlib::KeyPath, value: Self) {
                stdlib::WriteStorage::__set_str(ctx, &path, &value.to_string());
            }
        }

        // A `Map<Holder, _>` keys on the Holder's canonical string identity: it
        // encodes as a string element (`Display`) and decodes via `FromStr`.
        stdlib::key_element_via_display!(context::Holder);

        // `#[index]` on an identity/number field buckets by its canonical string,
        // encoded as a string codec element (equality partition — order irrelevant).
        // `is_primitive_type` routes all of these through the by-value `IndexKey`
        // path, so providing the impls here is what lets them be `#[index]`ed at all
        // (otherwise `#[index]` on, say, a `Decimal` field is a cryptic trait error).
        macro_rules! __index_key_via_display {
            ($($ty:ty),*) => {$(
                impl stdlib::IndexKey for $ty {
                    fn index_key(&self) -> alloc::vec::Vec<u8> {
                        stdlib::KeyElement::encode(&alloc::string::ToString::to_string(self))
                    }
                }
            )*};
        }
        // (HolderRef is a storage enum and already gets a discriminant `IndexKey`.)
        __index_key_via_display!(
            context::Holder,
            context::ContractAddress,
            numbers::Integer,
            numbers::Decimal
        );

        // `numbers::Integer`/`Decimal` are 256-bit sign-magnitude; encode them as
        // order-preserving codec elements so they can be `Map`/`IndexedMap` KEYS or
        // index SORT fields (e.g. ordering by a monetary amount). `Decimal` reuses
        // the integer encoding on its raw scaled limbs (fixed scale ⇒ raw-magnitude
        // order == value order). Distinct from the `IndexKey` (bucket) impl above.
        macro_rules! __key_element_num256 {
            ($($ty:path),*) => {$(
                impl stdlib::KeyElement for $ty {
                    fn encode_to(&self, out: &mut alloc::vec::Vec<u8>) {
                        stdlib::encode_int256(
                            out,
                            matches!(self.sign, numbers::Sign::Minus),
                            [self.r0, self.r1, self.r2, self.r3],
                        );
                    }
                    fn decode_from(bytes: &[u8]) -> Result<(Self, &[u8]), stdlib::CodecError> {
                        let (negative, limbs, rest) = stdlib::decode_int256(bytes)?;
                        Ok((
                            Self {
                                r0: limbs[0],
                                r1: limbs[1],
                                r2: limbs[2],
                                r3: limbs[3],
                                sign: if negative {
                                    numbers::Sign::Minus
                                } else {
                                    numbers::Sign::Plus
                                },
                            },
                            rest,
                        ))
                    }
                }
            )*};
        }
        __key_element_num256!(numbers::Integer, numbers::Decimal);

        impl Retrieve<crate::context::ViewStorage> for numbers::Integer {
            fn __get(ctx: &alloc::rc::Rc<crate::context::ViewStorage>, path: stdlib::KeyPath) -> Option<Self> {
                stdlib::ReadStorage::__exists(ctx, &path).then(|| numbers::IntegerModel::new(ctx.clone(), path).load())
            }
        }

        impl Retrieve<crate::context::ProcStorage> for numbers::Integer {
            fn __get(ctx: &alloc::rc::Rc<crate::context::ProcStorage>, path: stdlib::KeyPath) -> Option<Self> {
                stdlib::ReadStorage::__exists(ctx, &path).then(|| numbers::IntegerWriteModel::new(ctx.clone(), path).load())
            }
        }

        impl Retrieve<crate::context::ViewStorage> for numbers::Decimal {
            fn __get(ctx: &alloc::rc::Rc<crate::context::ViewStorage>, path: stdlib::KeyPath) -> Option<Self> {
                stdlib::ReadStorage::__exists(ctx, &path).then(|| numbers::DecimalModel::new(ctx.clone(), path).load())
            }
        }

        impl Retrieve<crate::context::ProcStorage> for numbers::Decimal {
            fn __get(ctx: &alloc::rc::Rc<crate::context::ProcStorage>, path: stdlib::KeyPath) -> Option<Self> {
                stdlib::ReadStorage::__exists(ctx, &path).then(|| numbers::DecimalWriteModel::new(ctx.clone(), path).load())
            }
        }

        impls!();

        struct #name;

        __export__!(#name);
    }
}
