use heck::ToPascalCase;
use proc_macro2::TokenStream;
use quote::quote;
use syn::{FieldsNamed, Ident};

use crate::index_decl::{self, IndexDecl};
use crate::utils;

/// The generated flat covering-value struct name for a covering index — e.g. index
/// `cheapest` on `Listing` → `ListingCheapestValue`. Holds the sort field (if any) plus
/// the `include=` fields; what `.values()`/`.iter()` yield.
fn covering_value_ident(type_name: &Ident, decl: &IndexDecl) -> Ident {
    Ident::new(
        &format!("{type_name}{}Value", decl.name.to_pascal_case()),
        type_name.span(),
    )
}

/// The flat covering-value struct + its `__from_covering` decoder for each COVERING
/// index (`include = …`). The struct carries the sort field (free from the member) and
/// the covered `include` fields; `__from_covering` rebuilds it from a leaf's raw
/// projection bytes (decoded field-by-field, in `include` order — the concatenation
/// [`index_decl::index_entry`] writes) plus, for a sorted index, the sort value passed
/// separately. Passed to `CoveringQuery`/`SortedCoveringQuery` as the `build` fn.
pub fn generate_covering_value_structs(
    decls: &[IndexDecl],
    fields: &FieldsNamed,
    type_name: &Ident,
) -> TokenStream {
    let structs = decls
        .iter()
        .filter(|decl| !decl.include.is_empty())
        .map(|decl| {
            let value_ident = covering_value_ident(type_name, decl);

            let mut field_defs = Vec::new();
            let mut ctor_fields = Vec::new();
            let mut decode_stmts = Vec::new();

            // The sort field leads the struct and comes from the member (not the
            // projection), so it's a `&S` parameter, not decoded.
            let sort_param = match &decl.sort {
                Some(sort) => {
                    let sort_ty = index_decl::field_type(fields, sort);
                    field_defs.push(quote! { pub #sort: #sort_ty });
                    ctor_fields.push(quote! { #sort: sort.clone() });
                    quote! { sort: &#sort_ty, }
                }
                None => quote! {},
            };

            // Each include field is decoded in order from the concatenated projection;
            // `decode_from` returns `(value, rest)`, and shadowing `__proj` threads the
            // remaining bytes to the next field. A non-`KeyElement` include field is a
            // compile error right here (the read side of the same guarantee the write
            // side gives).
            for inc in &decl.include {
                let inc_ty = index_decl::field_type(fields, inc);
                field_defs.push(quote! { pub #inc: #inc_ty });
                decode_stmts.push(quote! {
                    let (#inc, __proj) = <#inc_ty as stdlib::KeyElement>::decode_from(__proj)
                        .expect("covering projection decodes into its declared field types");
                });
                ctor_fields.push(quote! { #inc });
            }

            quote! {
                #[derive(Clone, Debug, PartialEq)]
                pub struct #value_ident {
                    #(#field_defs),*
                }

                impl #value_ident {
                    /// Rebuild the covered value from a leaf's raw projection bytes (and,
                    /// for a sorted index, the member's sort value). The `build` fn the
                    /// covering query calls per row — generated, not called directly.
                    #[doc(hidden)]
                    pub fn __from_covering(#sort_param __proj: &[u8]) -> Self {
                        #(#decode_stmts)*
                        let _ = __proj; // last field consumes it; silence unused
                        Self { #(#ctor_fields),* }
                    }
                }
            }
        });

    quote! { #(#structs)* }
}

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
/// `<index>(bucket)` method taking the bucket field's real type, so a contract
/// queries by value (`status(Status::Active)`) instead of a stringly-typed name +
/// hand-built key. A plain index returns a set-like [`stdlib::IndexQuery`]
/// (`keys()`/`len()`); a *sorted* index returns a map-like
/// [`stdlib::SortedIndexQuery`] (`keys()`/`values()`/`iter()`/`range(..)`, plus the
/// O(1) `len()`).
///
/// Generated here (the value derive sees its own index declarations); the `Model`
/// derive can't, since it only sees the `Map<K, V>` field, not `V` — so the field
/// model implements the [`stdlib::IndexScan`] primitives (`by_index`,
/// `by_index_sorted`, `bucket_count`) those queries back onto, and inherits the
/// typed methods here. The methods stringify with the same `IndexKey` the index
/// rows are written with, so a lookup and its stored bucket can't drift.
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
            // The name is a method on the field model; `index_decl::parse` has already
            // rejected any that would shadow the map surface or a query finisher.
            let method = Ident::new(name, type_name.span());

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

            let params: Vec<_> = parts.iter().map(|(p, _, _)| p).collect();
            let bindings = parts.iter().map(|(_, b, _)| b);
            // Each `__b<i>` is a pre-encoded `IndexKey` element (`Vec<u8>`); the query
            // owns the bucket as an `alloc::vec!` of those, and reads its member count
            // / member scan through the `IndexScan` primitives on demand.
            let bucket_idents = parts.iter().map(|(_, _, b)| b);
            // `Vec::from([__b0, …])` (not `vec![…]`) so the expansion snapshot renders
            // cleanly — every index has ≥1 `by` field, so the array is never empty.
            let bucket = quote! { alloc::vec::Vec::from([#(#bucket_idents),*]) };

            // The typed lookup returns a lazy query borrowing the field model; which one
            // depends on whether the index sorts (`sort = …`) and/or covers
            // (`include = …`). `count`/`len` and the `keys`/`values`/`iter`/`range`
            // (+ `with_scores` for sorted-covering) finishers live on the query, so one
            // method per index replaces `where_`/`count_`:
            //   plain             → `IndexQuery` (BTreeSet-like)
            //   sort              → `SortedIndexQuery` (BTreeMap<K, S>-like)
            //   include           → `CoveringQuery` (covered values from the leaf)
            //   sort + include    → `SortedCoveringQuery` (Redis ZSET + covered columns)
            let covering = !decl.include.is_empty();
            match (&decl.sort, covering) {
                (Some(sort_field), false) => {
                    let sort_ty = index_decl::field_type(fields, sort_field);
                    quote! {
                        fn #method(&self, #(#params),*) -> stdlib::SortedIndexQuery<'_, K, #sort_ty, Self> {
                            #(#bindings)*
                            stdlib::SortedIndexQuery::new(self, #index_id, #bucket)
                        }
                    }
                }
                (None, false) => quote! {
                    fn #method(&self, #(#params),*) -> stdlib::IndexQuery<'_, K, Self> {
                        #(#bindings)*
                        stdlib::IndexQuery::new(self, #index_id, #bucket)
                    }
                },
                (Some(sort_field), true) => {
                    let sort_ty = index_decl::field_type(fields, sort_field);
                    let value_ident = covering_value_ident(type_name, decl);
                    quote! {
                        fn #method(&self, #(#params),*) -> stdlib::SortedCoveringQuery<'_, K, #sort_ty, #value_ident, Self> {
                            #(#bindings)*
                            stdlib::SortedCoveringQuery::new(self, #index_id, #bucket, #value_ident::__from_covering)
                        }
                    }
                }
                (None, true) => {
                    let value_ident = covering_value_ident(type_name, decl);
                    quote! {
                        fn #method(&self, #(#params),*) -> stdlib::CoveringQuery<'_, K, #value_ident, Self> {
                            #(#bindings)*
                            stdlib::CoveringQuery::new(self, #index_id, #bucket, #value_ident::__from_covering)
                        }
                    }
                }
            }
        })
        .collect();

    quote! {
        // Each index adds a typed `<name>(bucket…)` lookup returning a lazy
        // `IndexQuery` / `SortedIndexQuery`. The `stdlib::IndexScan` supertrait
        // supplies the `by_index` / `by_index_sorted` / `bucket_count` primitives
        // (implemented by the field model), which those queries back onto.
        pub trait #trait_name<K>: stdlib::IndexScan<K> + Sized
        where
            K: stdlib::KeyElement + Clone + 'static,
        {
            #(#methods)*
        }
    }
}
