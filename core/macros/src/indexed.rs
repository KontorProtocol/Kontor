use proc_macro2::TokenStream;
use quote::quote;
use syn::{FieldsNamed, Ident};

use crate::index_decl::{self, IndexDecl};
use crate::utils;

/// Body of `Indexed::index_entries` for a struct: one `IndexEntry` per declared
/// index. Operates on the real value, so each field's value is `self.<field>`.
/// The bucket/sort encoding goes through [`index_decl::index_entry`], the one
/// source every index path stringifies through — so a write and a later diff
/// can't disagree.
pub fn generate_index_entries(decls: &[IndexDecl]) -> TokenStream {
    let pushes = decls.iter().map(|decl| {
        let entry = index_decl::index_entry(decl, &|field| quote! { self.#field });
        quote! { entries.push(#entry); }
    });

    quote! {
        let mut entries = alloc::vec::Vec::new();
        #(#pushes)*
        entries
    }
}

/// The `<E>Kind` discriminant-marker type for an enum index field, named from
/// the field type's last path segment (matching the `Storage` derive's `<E>Kind`). A
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

/// The per-value typed index-lookup trait. For each declared index it adds a
/// `where_<index>(bucket)` method taking the bucket field's real type, so a
/// contract queries by value (`where_status(Status::Active)`) instead of a
/// stringly-typed name + hand-built key. A *sorted* index's `where_` returns a
/// [`stdlib::SortedScan`], adding `.up_to(bound)` / `.range(lo..=hi)`; an unsorted
/// one returns a plain iterator (today's behavior).
///
/// Generated here (the value derive sees its own index declarations); the `Model`
/// derive can't, since it only sees the `IndexedMap<K, V>` field, not `V` — so the
/// field model implements the required primitives (`by_index`, `by_index_sorted`,
/// `bucket_count`) and inherits the typed wrappers. The wrappers stringify with
/// the same `IndexKey` the index rows are written with, so a lookup and its stored
/// bucket can't drift.
pub fn generate_lookup_trait(
    decls: &[IndexDecl],
    fields: &FieldsNamed,
    type_name: &Ident,
) -> TokenStream {
    let trait_name = Ident::new(&format!("{type_name}Index"), type_name.span());

    let methods: Vec<TokenStream> = decls
        .iter()
        .map(|decl| {
            let name = &decl.name;
            let by = &decl.by[0];
            let by_ty = index_decl::field_type(fields, by);
            let where_method = Ident::new(&format!("where_{name}"), type_name.span());
            let count_method = Ident::new(&format!("count_{name}"), type_name.span());

            // The bucket field's value → its `IndexKey`. A primitive is taken by
            // value; a storage enum by `impl Into<<E>Kind>`, so a unit enum's full
            // value AND a payload-carrying case's marker both work and key by the
            // discriminant. `key_stmt` binds the temporary the key borrows; both
            // stringify through `IndexKey`, the same source `index_entries` uses.
            let (param, key_stmt, key_ref) = if utils::is_primitive_type(by_ty) {
                (
                    quote! { #by: #by_ty },
                    quote! {},
                    quote! { stdlib::IndexKey::index_key(&#by) },
                )
            } else {
                let kind_ty = enum_kind_ident(by_ty);
                (
                    quote! { #by: impl core::convert::Into<#kind_ty> },
                    quote! { let kind: #kind_ty = #by.into(); },
                    quote! { stdlib::IndexKey::index_key(&kind) },
                )
            };

            let where_body = match &decl.sort {
                Some(sort_field) => {
                    let sort_ty = index_decl::field_type(fields, sort_field);
                    quote! {
                        fn #where_method(&self, #param) -> stdlib::SortedScan<K> {
                            #key_stmt
                            self.by_index_sorted(#name, &#key_ref, <#sort_ty as stdlib::SortKey>::WIDTH)
                        }
                    }
                }
                None => quote! {
                    fn #where_method(&self, #param) -> impl Iterator<Item = K> {
                        #key_stmt
                        self.by_index(#name, &#key_ref)
                    }
                },
            };

            quote! {
                #where_body

                fn #count_method(&self, #param) -> u64 {
                    #key_stmt
                    self.bucket_count(#name, &#key_ref)
                }
            }
        })
        .collect();

    quote! {
        pub trait #trait_name<K>
        where
            K: alloc::string::ToString + core::str::FromStr + Clone,
            <K as core::str::FromStr>::Err: core::fmt::Debug,
        {
            /// Raw bucket scan — yields the primary keys of an unsorted index
            /// bucket. The returned iterator owns its source (`use<Self, K>`, no
            /// lifetime capture), so the typed wrappers can hand it a borrow of a
            /// temporary key string.
            fn by_index(&self, index_name: &str, index_key: &str) -> impl Iterator<Item = K> + use<Self, K>;

            /// Ordered bucket scan for a *sorted* index: the bucket's `<sort‖pk>`
            /// child segments, wrapped so `SortedScan` strips the `sort_width`-char
            /// prefix to yield `K` and `up_to`/`range` can bound on the encoded
            /// prefix.
            fn by_index_sorted(&self, index_name: &str, index_key: &str, sort_width: usize) -> stdlib::SortedScan<K>;

            /// O(1) member count of a `(index_name, index_key)` bucket, the
            /// framework-maintained size of what the scans would walk.
            fn bucket_count(&self, index_name: &str, index_key: &str) -> u64;

            #(#methods)*
        }
    }
}
