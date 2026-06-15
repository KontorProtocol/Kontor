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
            let index_id = decl.id; // interned `<index>` segment
            let where_method = Ident::new(&format!("where_{name}"), type_name.span());
            let count_method = Ident::new(&format!("count_{name}"), type_name.span());

            // One parameter per `by` field (in declared order), each typed for how
            // it buckets: a primitive by value; a storage enum by `impl Into<<E>Kind>`
            // (so a unit enum's full value AND a payload case's marker both work);
            // an `Option` by `impl Into<Presence>` (its none/some discriminant). Each
            // field's key is bound to a `__b<i>` local, and the bucket is the slice of
            // those — so a single-field index is just the one-segment case. Every key
            // stringifies through `IndexKey`, the same source `index_entries` writes.
            let parts: Vec<(TokenStream, TokenStream, Ident)> = decl
                .by
                .iter()
                .enumerate()
                .map(|(i, field)| {
                    let ty = index_decl::field_type(fields, field);
                    let binding = Ident::new(&format!("__b{i}"), type_name.span());
                    let (param, key_expr) = if utils::is_primitive_type(ty) {
                        (
                            quote! { #field: #ty },
                            quote! { stdlib::IndexKey::index_key(&#field) },
                        )
                    } else if utils::is_option_type(ty) {
                        (
                            quote! { #field: impl core::convert::Into<stdlib::Presence> },
                            quote! {{ let __p: stdlib::Presence = #field.into(); stdlib::IndexKey::index_key(&__p) }},
                        )
                    } else {
                        let kind_ty = enum_kind_ident(ty);
                        (
                            quote! { #field: impl core::convert::Into<#kind_ty> },
                            quote! {{ let __k: #kind_ty = #field.into(); stdlib::IndexKey::index_key(&__k) }},
                        )
                    };
                    (param, quote! { let #binding = #key_expr; }, binding)
                })
                .collect();

            let params = parts.iter().map(|(p, _, _)| p);
            let bindings = parts.iter().map(|(_, b, _)| b).collect::<Vec<_>>();
            // Each `__b<i>` is a pre-encoded `IndexKey` element (`Vec<u8>`); the
            // bucket is the slice of their byte-slices.
            let bucket_refs = parts.iter().map(|(_, _, b)| quote! { #b.as_slice() });
            let bucket = quote! { &[#(#bucket_refs),*] };

            // `params`/`bindings`/`bucket` are each consumed once per use below;
            // re-collect so `where_` and `count_` can both expand them.
            let params: Vec<_> = params.collect();

            let where_body = match &decl.sort {
                Some(sort_field) => {
                    let sort_ty = index_decl::field_type(fields, sort_field);
                    quote! {
                        fn #where_method(&self, #(#params),*) -> stdlib::SortedScan<K, #sort_ty> {
                            #(#bindings)*
                            self.by_index_sorted::<#sort_ty>(#index_id, #bucket)
                        }
                    }
                }
                None => quote! {
                    fn #where_method(&self, #(#params),*) -> impl Iterator<Item = K> {
                        #(#bindings)*
                        self.by_index(#index_id, #bucket)
                    }
                },
            };

            quote! {
                #where_body

                fn #count_method(&self, #(#params),*) -> u64 {
                    #(#bindings)*
                    self.bucket_count(#index_id, #bucket)
                }
            }
        })
        .collect();

    quote! {
        pub trait #trait_name<K>
        where
            K: stdlib::KeyElement + Clone,
        {
            /// Raw bucket scan — yields the primary keys of an unsorted index
            /// bucket, identified by the index's interned id and its bucket segments
            /// `<bucket…>` (one per `by` field). The returned iterator owns its
            /// source (`use<Self, K>`, no lifetime capture), so the typed wrappers
            /// can hand it borrows of temporary key strings.
            fn by_index(&self, index_id: u8, bucket: &[&[u8]]) -> impl Iterator<Item = K> + use<Self, K>;

            /// Ordered bucket scan for a *sorted* index: the bucket's `(sort, pk)`
            /// tuple child members, wrapped in a `SortedScan` that yields `K` in sort
            /// order and bounds `up_to`/`range` on the decoded sort value. `S` is the
            /// index's sort field type, so the wrong bound type is a compile error.
            fn by_index_sorted<S: stdlib::KeyElement + Clone + 'static>(&self, index_id: u8, bucket: &[&[u8]]) -> stdlib::SortedScan<K, S>;

            /// O(1) member count of an `(index_id, bucket…)` bucket, the
            /// framework-maintained size of what the scans would walk.
            fn bucket_count(&self, index_id: u8, bucket: &[&[u8]]) -> u64;

            #(#methods)*
        }
    }
}
