use proc_macro2::TokenStream;
use quote::quote;
use syn::{DataStruct, Error, Fields, Ident, Result};

use crate::utils;

/// Body of `Indexed::index_entries` for a struct: one `(field_name, index key)`
/// entry per `#[index]`-tagged field. The key is `IndexKey::index_key` — the one
/// source every index path stringifies through, so each indexed field must be
/// `IndexKey` (primitives are; storage enums get it from `#[derive(StorageEnum)]`).
pub fn generate_index_entries(data_struct: &DataStruct, type_name: &Ident) -> Result<TokenStream> {
    let Fields::Named(fields) = &data_struct.fields else {
        return Err(Error::new(
            type_name.span(),
            "Indexed derive only supports structs with named fields",
        ));
    };

    let pushes: Vec<TokenStream> = fields
        .named
        .iter()
        .filter(|f| f.attrs.iter().any(|a| a.path().is_ident("index")))
        .map(|field| {
            let field_name = field.ident.as_ref().unwrap();
            let name_str = field_name.to_string();
            quote! {
                entries.push((#name_str, stdlib::IndexKey::index_key(&self.#field_name)));
            }
        })
        .collect();

    Ok(quote! {
        let mut entries = alloc::vec::Vec::new();
        #(#pushes)*
        entries
    })
}

/// The `<E>Kind` discriminant-marker type for an enum index field, named from
/// the field type's last path segment (matching `#[derive(StorageEnum)]`). A
/// non-path type falls back to `<ty>Kind` tokens, which simply won't resolve —
/// surfacing as "no such type" if a non-enum, non-primitive field is `#[index]`ed.
fn enum_kind_ident(ty: &syn::Type) -> TokenStream {
    if let syn::Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
    {
        let kind = Ident::new(&format!("{}Kind", segment.ident), segment.ident.span());
        return quote! { #kind };
    }
    quote! { #ty Kind }
}

/// The per-value typed index-lookup trait. For each `#[index]` field it adds a
/// `where_<field>(value)` method taking the field's real type, so a contract
/// queries an index by value (`where_status(Status::Active)`) instead of a
/// stringly-typed name + hand-built key. Generated here (the value derive sees
/// its own `#[index]` fields); the `Model` derive can't, since it only sees the
/// `IndexedMap<K, V>` field, not `V`'s fields — so the field model implements
/// the one required primitive (`by_index`) and inherits the typed wrappers. The
/// wrappers stringify with the same `ToString` the index rows are written with,
/// so a lookup and its stored bucket can't drift.
pub fn generate_lookup_trait(data_struct: &DataStruct, type_name: &Ident) -> Result<TokenStream> {
    let Fields::Named(fields) = &data_struct.fields else {
        return Err(Error::new(
            type_name.span(),
            "Indexed derive only supports structs with named fields",
        ));
    };

    let trait_name = Ident::new(&format!("{type_name}Index"), type_name.span());

    let methods: Vec<TokenStream> = fields
        .named
        .iter()
        .filter(|f| f.attrs.iter().any(|a| a.path().is_ident("index")))
        .map(|field| {
            let field_name = field.ident.as_ref().unwrap();
            let field_ty = &field.ty;
            let name_str = field_name.to_string();
            let method = Ident::new(&format!("where_{field_name}"), field_name.span());
            // A primitive field's lookup takes the value directly. A storage
            // enum's takes `impl Into<<E>Kind>` — so a unit enum's full value
            // (`Status::Active`) AND a payload-carrying case's marker
            // (`StatusKind::Failed`) both work, and the bucket is keyed by the
            // discriminant via `IndexKey`. Both stringify through `IndexKey`, the
            // same source `index_entries` uses, so lookup and stored bucket agree.
            if utils::is_primitive_type(field_ty) {
                quote! {
                    fn #method(&self, #field_name: #field_ty) -> impl Iterator<Item = K> {
                        self.by_index(#name_str, &stdlib::IndexKey::index_key(&#field_name))
                    }
                }
            } else {
                let kind_ty = enum_kind_ident(field_ty);
                quote! {
                    fn #method(&self, #field_name: impl core::convert::Into<#kind_ty>) -> impl Iterator<Item = K> {
                        let kind: #kind_ty = #field_name.into();
                        self.by_index(#name_str, &stdlib::IndexKey::index_key(&kind))
                    }
                }
            }
        })
        .collect();

    Ok(quote! {
        pub trait #trait_name<K>
        where
            K: alloc::string::ToString + core::str::FromStr + Clone,
            <K as core::str::FromStr>::Err: core::fmt::Debug,
        {
            /// Raw bucket scan — the single primitive the field model supplies;
            /// the typed `where_*` methods wrap it. Kept public as an escape
            /// hatch for index keys built at runtime. The returned iterator owns
            /// its source (`use<Self, K>`, no lifetime capture), so the typed
            /// wrappers can hand it a borrow of a temporary key string.
            fn by_index(&self, index_name: &str, index_key: &str) -> impl Iterator<Item = K> + use<Self, K>;

            #(#methods)*
        }
    })
}
