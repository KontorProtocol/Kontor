use darling::FromMeta;
use heck::{ToPascalCase, ToSnakeCase};
use proc_macro2::TokenStream;
use quote::quote;
use std::collections::BTreeMap;
use std::path::Path;
use syn::Ident;
use wit_parser::{Resolve, Type, TypeDefKind, TypeId, TypeOwner, WorldId};
use wit_validator::Validator;

/// The world every contract's WIT declares. Also the prefix of a fully-qualified
/// wit-bindgen selector for a type declared directly in that world.
const WORLD: &str = "root";

#[derive(FromMeta)]
pub struct Config {
    name: String,
    path: Option<String>,
    /// Secondary-index declarations on WIT records used as `Map` values.
    /// Semicolon-separated entries, each
    /// `record: name [by field…] [sort field] [include field…]` (kebab-case, as in the
    /// WIT); `record: field` is sugar for a single-field index. `include` marks a
    /// covering index (those fields are projected into the index leaf). E.g.
    /// ```text
    /// indexed = "
    ///   agreement-data: active;
    ///   challenge-data: status;
    ///   challenge-data: due by status sort deadline-height;
    /// "
    /// ```
    /// `contract!` injects the matching struct-level `#[index(...)]` on each record
    /// (via wit-bindgen's `additional_type_attributes`); the index machinery is folded
    /// into `#[derive(Storage)]`, which every indexed record receives (indexed ⊂
    /// storage). `by`/`sort` fields are mapped to the generated snake_case Rust
    /// field names.
    indexed: Option<String>,
}

/// Translate one `name [by field…] [sort field] [include field…]` entry (the part
/// after `record:`), parsed with each field's role preserved (validation treats
/// them differently: `by`/`sort` must be scalar; `include` only needs a
/// projectable `KeyElement`, so e.g. `list<u8>` is fine there). Field names are
/// held snake_case, as the generated Rust idents the rendered attribute uses.
struct IndexDeclSpec {
    /// The index name; for the single-token sugar (`record: field`) this IS the
    /// bucket field.
    name: String,
    by: Vec<String>,
    sort: Option<String>,
    include: Vec<String>,
}

impl IndexDeclSpec {
    /// True when the sugar form was used and `name` doubles as the bucket field.
    fn name_is_field(&self) -> bool {
        self.by.is_empty() && self.sort.is_none() && self.include.is_empty()
    }

    /// Render as the Rust struct-level attribute string
    /// `#[index(name, by = …, sort = …, include = (…))]`.
    fn render(&self) -> String {
        let mut args = self.name.clone();
        match self.by.as_slice() {
            [] => {}
            [one] => args.push_str(&format!(", by = {one}")),
            many => args.push_str(&format!(", by = ({})", many.join(", "))),
        }
        if let Some(sort) = &self.sort {
            args.push_str(&format!(", sort = {sort}"));
        }
        if !self.include.is_empty() {
            args.push_str(&format!(", include = ({})", self.include.join(", ")));
        }
        format!("#[index({args})]")
    }
}

fn index_attr(spec: &str) -> IndexDeclSpec {
    const KEYWORDS: &[&str] = &["by", "sort", "include"];
    let mut tokens = spec.split_whitespace().peekable();
    let name = tokens
        .next()
        .unwrap_or_else(|| panic!("`indexed` entry is missing an index name: {spec:?}"))
        .to_snake_case();
    let mut by: Vec<String> = Vec::new();
    let mut sort: Option<String> = None;
    let mut include: Vec<String> = Vec::new();
    while let Some(keyword) = tokens.next() {
        match keyword {
            "by" => {
                while let Some(field) = tokens.next_if(|t| !KEYWORDS.contains(t)) {
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
            "include" => {
                while let Some(field) = tokens.next_if(|t| !KEYWORDS.contains(t)) {
                    include.push(field.to_snake_case());
                }
                if include.is_empty() {
                    panic!("`include` needs at least one field in indexed entry: {spec:?}");
                }
            }
            other => {
                panic!(
                    "unexpected `{other}` in indexed entry (expected `by`/`sort`/`include`): {spec:?}"
                )
            }
        }
    }
    IndexDeclSpec {
        name,
        by,
        sort,
        include,
    }
}

/// Parse the `indexed` spec into record (kebab wit name) -> its parsed index
/// declarations, in declared order. BTreeMap keeps everything downstream
/// deterministic across runs.
fn parse_indexed(indexed: Option<&str>) -> BTreeMap<String, Vec<IndexDeclSpec>> {
    let mut by_record: BTreeMap<String, Vec<IndexDeclSpec>> = BTreeMap::new();
    for entry in indexed.unwrap_or_default().split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (record, rest) = entry.split_once(':').unwrap_or_else(|| {
            panic!(
                "`indexed` entry must be `record: name [by field] [sort field] [include field…]`: {entry:?}"
            )
        });
        by_record
            .entry(record.trim().to_string())
            .or_default()
            .push(index_attr(rest.trim()));
    }
    by_record
}

/// The contract's own world in the resolve.
fn root_world(resolve: &Resolve) -> WorldId {
    resolve
        .worlds
        .iter()
        .find(|(_, w)| w.name == WORLD)
        .map(|(id, _)| id)
        .unwrap_or_else(|| panic!("WIT does not declare a `{WORLD}` world"))
}

/// Named types declared directly in the contract's world (aliases created by
/// `use` included — callers discriminate on kind).
fn world_types(resolve: &Resolve, world: WorldId) -> BTreeMap<String, TypeId> {
    resolve
        .types
        .iter()
        .filter(|(_, td)| td.owner == TypeOwner::World(world))
        .filter_map(|(id, td)| td.name.clone().map(|n| (n, id)))
        .collect()
}

/// The kebab name of the definition a field/payload type resolves to (through
/// alias links), for validation messages; None for unnamed shapes.
fn resolved_kind<'a>(resolve: &'a Resolve, ty: &Type) -> Option<&'a TypeDefKind> {
    let mut ty = *ty;
    loop {
        match ty {
            Type::Id(id) => match &resolve.types[id].kind {
                TypeDefKind::Type(inner) => ty = *inner,
                other => return Some(other),
            },
            _ => return None,
        }
    }
}

/// Validate one `indexed` record's declarations against the WIT: the record
/// exists in the world, is a record, and every referenced field exists with a
/// shape its role supports — `by`/`sort` (and the single-token sugar's name)
/// must be scalar; `include` fields only need to be projectable (`KeyElement`),
/// so lists like `list<u8>` are fine there. This is what turns the old "cryptic
/// trait error"/unresolvable-`<ty>Kind` failures into real messages.
fn validate_indexed_record(
    resolve: &Resolve,
    world: &BTreeMap<String, TypeId>,
    record: &str,
    specs: &[IndexDeclSpec],
) {
    let id = *world.get(record).unwrap_or_else(|| {
        panic!("`indexed` names `{record}`, but the world declares no type with that name")
    });
    let TypeDefKind::Record(rec) = &resolve.types[id].kind else {
        panic!("`indexed` target `{record}` is not a record")
    };
    // Fields in WIT are kebab; the parsed specs hold the generated snake names —
    // compare through the same conversion the DSL applied.
    let fields: BTreeMap<String, &Type> = rec
        .fields
        .iter()
        .map(|f| (f.name.to_snake_case(), &f.ty))
        .collect();

    let lookup = |field: &str| -> &Type {
        fields.get(field).unwrap_or_else(|| {
            panic!(
                "`indexed` on `{record}` references field `{field}`, but the record's \
                 fields are: {:?}",
                fields.keys().collect::<Vec<_>>()
            )
        })
    };
    // Composite/container shapes can't be index keys — reject with the
    // record/field named instead of letting the derive produce an opaque trait
    // error. `include` permits lists (projected as `KeyElement` bytes).
    let check = |field: &str, allow_list: bool| {
        if let Some(kind) = resolved_kind(resolve, lookup(field)) {
            let bad = match kind {
                TypeDefKind::Record(_) => Some("a record"),
                TypeDefKind::List(_) if !allow_list => Some("a list"),
                TypeDefKind::Tuple(_) => Some("a tuple"),
                TypeDefKind::Option(_) => Some("an option"),
                TypeDefKind::Result(_) => Some("a result"),
                TypeDefKind::Flags(_) => Some("flags"),
                _ => None,
            };
            if let Some(shape) = bad {
                panic!(
                    "`indexed` on `{record}` uses field `{field}`, which is {shape} — \
                     index key fields must be scalar (numbers, strings, bools, enums, or \
                     built-in identity types)"
                );
            }
        }
    };

    for spec in specs {
        if spec.name_is_field() {
            check(&spec.name, false);
        }
        for field in &spec.by {
            check(field, false);
        }
        if let Some(sort) = &spec.sort {
            check(sort, false);
        }
        for field in &spec.include {
            check(field, true);
        }
    }
}

/// Build the `additional_type_attributes` option tokens for the wit-bindgen
/// `generate!` from the `indexed` spec, validated against the parsed WIT: one
/// `#[index(...)]` per declared index. wit-bindgen emits each as its own
/// attribute line on the (owned) record, and the `Storage` derive (applied to
/// every record via `additional_derives`, where the index machinery lives)
/// parses them via the shared index-declaration grammar.
fn type_attr_options(resolve: &Resolve, indexed: Option<&str>) -> TokenStream {
    let by_record = parse_indexed(indexed);
    if by_record.is_empty() {
        return quote! {};
    }
    let world_named = world_types(resolve, root_world(resolve));
    for (record, specs) in &by_record {
        validate_indexed_record(resolve, &world_named, record, specs);
    }

    // The index machinery is folded into `#[derive(Storage)]` (applied to every
    // record via the contract's `additional_derives`), so we inject only the
    // `#[index(...)]` attributes here; non-derive attributes are emitted
    // verbatim so `#[index(...)]` passes through untouched. Selectors are fully
    // qualified, and these records are declared directly in the world, so the
    // qualified name is the world name and then the record's kebab wit name.
    let mut type_pairs = Vec::new();
    for (record, decls) in by_record {
        let selector = format!("{WORLD}/{record}");
        let attrs = decls.iter().map(IndexDeclSpec::render).collect::<Vec<_>>();
        let attrs = attrs.iter().map(|attr| {
            attr.parse::<TokenStream>()
                .unwrap_or_else(|e| panic!("generated a malformed index attribute {attr:?}: {e}"))
        });
        type_pairs.push(quote! { #selector: [ #(#attrs)* ], });
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
    let type_attrs = type_attr_options(&resolve, config.indexed.as_deref());
    quote! {
        extern crate alloc;

        use alloc::{
            format,
            string::{String, ToString},
            vec::Vec,
        };

        wit_bindgen::generate!({
            world: #WORLD,
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
        type Deque<V> = stdlib::StorageDeque<V, context::ProcStorage>;

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

        impl stdlib::HasNextRow for context::IndexRows {
            fn next(&self) -> Option<(Vec<u8>, Vec<u8>)> {
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

            fn __get_keys_range<T: stdlib::KeyElement + Clone>(self: &alloc::rc::Rc<Self>, path: &[u8], lo: Option<&[u8]>, hi: Option<&[u8]>, descending: bool) -> impl Iterator<Item = T> + use<T> {
                stdlib::make_keys_iterator(self.get_keys(path, lo, hi, descending))
            }

            fn __get_index_rows_range(self: &alloc::rc::Rc<Self>, path: &[u8], lo: Option<&[u8]>, hi: Option<&[u8]>, descending: bool) -> impl Iterator<Item = (Vec<u8>, Vec<u8>)> + use<> {
                stdlib::make_index_rows_iterator(self.get_index_rows(path, lo, hi, descending))
            }

            fn __exists(self: &alloc::rc::Rc<Self>, path: &[u8]) -> bool {
                self.exists(path)
            }

            fn __extend_path_with_match(self: &alloc::rc::Rc<Self>, path: &[u8], candidates: &[alloc::vec::Vec<u8>]) -> Option<u32> {
                self.extend_path_with_match(path, candidates)
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

            fn __get_keys_range<T: stdlib::KeyElement + Clone>(self: &alloc::rc::Rc<Self>, path: &[u8], lo: Option<&[u8]>, hi: Option<&[u8]>, descending: bool) -> impl Iterator<Item = T> + use<T> {
                stdlib::make_keys_iterator(self.get_keys(path, lo, hi, descending))
            }

            fn __get_index_rows_range(self: &alloc::rc::Rc<Self>, path: &[u8], lo: Option<&[u8]>, hi: Option<&[u8]>, descending: bool) -> impl Iterator<Item = (Vec<u8>, Vec<u8>)> + use<> {
                stdlib::make_index_rows_iterator(self.get_index_rows(path, lo, hi, descending))
            }

            fn __exists(self: &alloc::rc::Rc<Self>, path: &[u8]) -> bool {
                self.exists(path)
            }

            fn __extend_path_with_match(self: &alloc::rc::Rc<Self>, path: &[u8], candidates: &[alloc::vec::Vec<u8>]) -> Option<u32> {
                self.extend_path_with_match(path, candidates)
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

            fn __delete_matching_paths(self: &alloc::rc::Rc<Self>, base_path: &[u8], candidates: &[alloc::vec::Vec<u8>]) -> u64 {
                self.delete_matching_paths(base_path, candidates)
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
        // order-preserving codec elements so they can be `Map` KEYS or
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
