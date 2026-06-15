use heck::ToPascalCase;
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{
    Attribute, DataEnum, DataStruct, Error, Fields, GenericArgument, Ident, PathArguments, Result,
    Type, spanned::Spanned,
};

use crate::index_decl::{self, IndexDecl};
use crate::utils;

/// The local an index-participating field is read into once, so building entries
/// (and a setter's old + new sides) never re-reads the same storage slot.
fn idx_local(field: &Ident) -> Ident {
    Ident::new(&format!("__idx_{field}"), field.span())
}

pub fn generate_struct(
    data_struct: &DataStruct,
    struct_attrs: &[Attribute],
    type_name: &Ident,
    write: bool,
) -> Result<TokenStream> {
    match &data_struct.fields {
        Fields::Named(fields) => {
            utils::check_struct_field_count(fields, type_name.span())?;
            // The struct's declared secondary indexes (field-level `#[index]` +
            // struct-level `#[index(...)]`). The single source the in-place
            // setters reconcile against and the read model reads back for diffs.
            let decls = index_decl::parse(struct_attrs, fields)?;
            let has_indexed = !decls.is_empty();
            let write_prefix = if write { "Write" } else { "" };
            let read_only_model_name = Ident::new(&format!("{}Model", type_name), type_name.span());
            let model_name = Ident::new(
                &format!("{}{}Model", type_name, write_prefix),
                type_name.span(),
            );
            let context_param = if write {
                quote! { crate::context::ProcStorage }
            } else {
                quote! { crate::context::ViewStorage }
            };

            let mut special_models = vec![];

            let getters = fields.named.iter().enumerate().map(|(field_idx, field)| {
                let field_name = field.ident.as_ref().unwrap();
                // Per-type interned path id for this field's structural name: its
                // declaration index. Emitted as a `push_interned` dict-ref instead
                // of the full field-name string (see `keycodec` TAG_DICT). The id
                // is private to this type and stable for the life of the contract
                // (no in-place upgrades), so declaration order is a fine, dense key.
                let field_id = field_idx as u8;
                let field_ty = &field.ty;

                if utils::is_map_type(field_ty) {
                    let (k_ty, v_ty) = get_map_types(field_ty)?;
                    let field_model_name = Ident::new(&format!("{}{}{}Model", type_name, &field_name.to_string().to_pascal_case(), write_prefix), field.span());

                    let vi = value_item(write, &v_ty, field.span())?;
                    let item_ty = &vi.item_ty;
                    let get_return = quote! { Option<#item_ty> };
                    let get_body = if vi.is_primitive {
                        quote! { stdlib::ReadStorage::__get(&self.ctx, base_path) }
                    } else {
                        let v_model_ty = vi.model_ty.as_ref().unwrap();
                        quote! { stdlib::ReadStorage::__exists(&self.ctx, &base_path).then(|| #v_model_ty::new(self.ctx.clone(), base_path)) }
                    };

                    let setter = if write {
                        quote! {
                            pub fn set(&self, key: &#k_ty, value: #v_ty) {
                                stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_element(key), value)
                            }

                            /// Remove a single entry (tombstone). Returns true if a live value existed.
                            pub fn remove(&self, key: &#k_ty) -> bool {
                                stdlib::WriteStorage::__delete(&self.ctx, &self.base_path.push_element(key))
                            }
                        }
                    } else {
                        quote!{}
                    };

                    special_models.push(quote! {
                        #[derive(Clone)]
                        pub struct #field_model_name {
                            pub base_path: stdlib::KeyPath,
                            ctx: alloc::rc::Rc<#context_param>,
                        }

                        impl #field_model_name {
                            pub fn get(&self, key: &#k_ty) -> #get_return {
                                let base_path = self.base_path.push_element(key);
                                #get_body
                            }

                            #setter

                            pub fn load(&self) -> Map<#k_ty, #v_ty> {
                                Map::new(&[])
                            }

                            pub fn keys(&self) -> impl Iterator<Item = #k_ty> {
                                stdlib::ReadStorage::__get_keys(&self.ctx, &self.base_path)
                            }
                        }
                    });

                    Ok(quote! {
                        pub fn #field_name(&self) -> #field_model_name {
                            #field_model_name { base_path: self.base_path.push_interned(#field_id), ctx: self.ctx.clone() }
                        }
                    })
                } else if utils::is_indexed_map_type(field_ty) {
                    let (k_ty, v_ty) = get_indexed_map_types(field_ty)?;
                    let field_model_name = Ident::new(&format!("{}{}{}Model", type_name, &field_name.to_string().to_pascal_case(), write_prefix), field.span());
                    // Index rows live in a SIBLING root (not under the map) so they
                    // never show up in the primary's `keys()`. Its interned id is the
                    // field's id with the high bit set (`id | 0x80`) — a pure-byte
                    // rule so the generic wholesale `IndexedMap` write can rebuild it
                    // from the map's path without the contract's name dictionary (see
                    // `KeyPath::interned_index_sibling`). Field ids are < 128, so the
                    // marker space (128..=255) never collides with a field id.
                    let idx_marker_id: u8 = field_id | 0x80;

                    // IndexedMap values are always structs deriving `Indexed` +
                    // `Storage`, so `get` returns the value model (like a nested
                    // struct field), never a bare primitive.
                    let v_model_ty = get_model_ident(write, &v_ty, field.span())?;

                    // The value's `Indexed` derive generates `<Value>Index`, a
                    // trait carrying the typed `where_<field>` lookups; the field
                    // model implements its one required primitive (`by_index`) and
                    // inherits the wrappers. Generated there, not here, because this
                    // site only sees `IndexedMap<K, V>` — never `V`'s `#[index]`
                    // fields.
                    let index_trait = index_trait_ident(&v_ty, field.span())?;

                    // On the write model, bind the returned value model to this
                    // index so its indexed-field setters reconcile in place.
                    let with_index_call = if write {
                        quote! { .with_index(self.index_path.clone(), stdlib::KeyElement::encode(key)) }
                    } else {
                        quote! {}
                    };

                    // Mutators only on the write model. They maintain the index
                    // through the shared diff helper: new entries from the value's
                    // `Indexed` impl, old entries from the prior value's model via
                    // `__index_entries` — which reads only the `#[index]` columns,
                    // not the whole struct.
                    let mutators = if write {
                        quote! {
                            pub fn set(&self, key: &#k_ty, value: #v_ty) {
                                let key_bytes = stdlib::KeyElement::encode(key);
                                let new_entries = stdlib::Indexed::index_entries(&value);
                                let old_entries = self.get(key).map(|m| m.__index_entries()).unwrap_or_default();
                                stdlib::apply_index_diff(&self.ctx, &self.index_path, &key_bytes, &old_entries, &new_entries);
                                stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_element(key), value);
                            }

                            /// Remove the entry and its index rows. Returns true if a live value existed.
                            pub fn remove(&self, key: &#k_ty) -> bool {
                                let key_bytes = stdlib::KeyElement::encode(key);
                                let old_entries = self.get(key).map(|m| m.__index_entries()).unwrap_or_default();
                                stdlib::apply_index_diff(&self.ctx, &self.index_path, &key_bytes, &old_entries, &[]);
                                stdlib::WriteStorage::__delete(&self.ctx, &self.base_path.push_element(key))
                            }
                        }
                    } else {
                        quote!{}
                    };

                    special_models.push(quote! {
                        #[derive(Clone)]
                        pub struct #field_model_name {
                            pub base_path: stdlib::KeyPath,
                            index_path: stdlib::KeyPath,
                            ctx: alloc::rc::Rc<#context_param>,
                        }

                        impl #field_model_name {
                            pub fn get(&self, key: &#k_ty) -> Option<#v_model_ty> {
                                let base_path = self.base_path.push_element(key);
                                stdlib::ReadStorage::__exists(&self.ctx, &base_path).then(|| #v_model_ty::new(self.ctx.clone(), base_path)#with_index_call)
                            }

                            #mutators

                            pub fn load(&self) -> IndexedMap<#k_ty, #v_ty> {
                                IndexedMap::new(&[])
                            }

                            pub fn keys(&self) -> impl Iterator<Item = #k_ty> {
                                stdlib::ReadStorage::__get_keys(&self.ctx, &self.base_path)
                            }
                        }

                        // The typed `where_<field>`/`count_<field>` lookups come
                        // from the value's `<Value>Index` trait; this supplies its
                        // two primitives. `bucket_count` reads the count the
                        // framework maintains AT the bucket-prefix path.
                        impl #index_trait<#k_ty> for #field_model_name {
                            fn by_index(&self, index_id: u8, bucket: &[&[u8]]) -> impl Iterator<Item = #k_ty> + use<> {
                                let bucket = self.index_path.push_interned(index_id).push_raw_elements(bucket);
                                stdlib::ReadStorage::__get_keys(&self.ctx, &bucket)
                            }

                            fn by_index_sorted<S: stdlib::KeyElement + Clone + 'static>(&self, index_id: u8, bucket: &[&[u8]]) -> stdlib::SortedScan<#k_ty, S> {
                                let bucket = self.index_path.push_interned(index_id).push_raw_elements(bucket);
                                // Each member is one `(sort, pk)` tuple element; decode
                                // it directly. `SortedScan` drops the sort field, yields
                                // `K` in value order, and bounds on the decoded sort.
                                let members = stdlib::ReadStorage::__get_keys::<(S, #k_ty)>(&self.ctx, &bucket);
                                stdlib::SortedScan::new(alloc::boxed::Box::new(members))
                            }

                            fn bucket_count(&self, index_id: u8, bucket: &[&[u8]]) -> u64 {
                                let bucket = self.index_path.push_interned(index_id).push_raw_elements(bucket);
                                stdlib::ReadStorage::__get_u64(&self.ctx, &bucket).unwrap_or(0)
                            }
                        }
                    });

                    Ok(quote! {
                        pub fn #field_name(&self) -> #field_model_name {
                            #field_model_name {
                                base_path: self.base_path.push_interned(#field_id),
                                index_path: self.base_path.push_interned(#idx_marker_id),
                                ctx: self.ctx.clone(),
                            }
                        }
                    })
                } else if utils::is_deque_type(field_ty) {
                    let v_ty = get_deque_type(field_ty)?;
                    let field_model_name = Ident::new(&format!("{}{}{}Model", type_name, &field_name.to_string().to_pascal_case(), write_prefix), field.span());
                    let vi = value_item(write, &v_ty, field.span())?;
                    let item_ty = &vi.item_ty;

                    // `get`/`front`/`back`/`iter` yield the VALUE for a leaf element, or
                    // the value MODEL for a struct/enum element (a subtree), like `Map`.
                    // `pop_*` always returns an owned value (materialized via the model's
                    // `load()` for non-leaf elements, since the entry is then deleted).
                    let (get_body, iter_body) = if vi.is_primitive {
                        (
                            quote! { stdlib::deque::get::<_, #v_ty>(&self.ctx, &self.base_path, pos) },
                            quote! {
                                let ctx = self.ctx.clone();
                                let base = self.base_path.clone();
                                let n = stdlib::deque::len(&ctx, &base);
                                (0..n).filter_map(move |i| stdlib::deque::get::<_, #v_ty>(&ctx, &base, i))
                            },
                        )
                    } else {
                        let vm = vi.model_ty.as_ref().unwrap();
                        (
                            quote! {
                                let h = stdlib::deque::head(&self.ctx, &self.base_path);
                                if pos >= stdlib::deque::tail(&self.ctx, &self.base_path).wrapping_sub(h) {
                                    None
                                } else {
                                    Some(#vm::new(self.ctx.clone(), stdlib::deque::entry_path(&self.base_path, h.wrapping_add(pos))))
                                }
                            },
                            quote! {
                                let ctx = self.ctx.clone();
                                let base = self.base_path.clone();
                                let h = stdlib::deque::head(&ctx, &base);
                                let n = stdlib::deque::len(&ctx, &base);
                                (0..n).map(move |i| #vm::new(ctx.clone(), stdlib::deque::entry_path(&base, h.wrapping_add(i))))
                            },
                        )
                    };

                    let mutators = if write {
                        let (pop_front_body, pop_back_body) = if vi.is_primitive {
                            (
                                quote! { stdlib::deque::pop_front::<_, #v_ty>(&self.ctx, &self.base_path) },
                                quote! { stdlib::deque::pop_back::<_, #v_ty>(&self.ctx, &self.base_path) },
                            )
                        } else {
                            let vm = vi.model_ty.as_ref().unwrap();
                            (
                                quote! {
                                    let h = stdlib::deque::head(&self.ctx, &self.base_path);
                                    if h == stdlib::deque::tail(&self.ctx, &self.base_path) {
                                        return None;
                                    }
                                    let entry = stdlib::deque::entry_path(&self.base_path, h);
                                    let value = #vm::new(self.ctx.clone(), entry.clone()).load();
                                    stdlib::WriteStorage::__delete(&self.ctx, &entry);
                                    stdlib::deque::set_head(&self.ctx, &self.base_path, h.wrapping_add(1));
                                    Some(value)
                                },
                                quote! {
                                    let t = stdlib::deque::tail(&self.ctx, &self.base_path);
                                    if stdlib::deque::head(&self.ctx, &self.base_path) == t {
                                        return None;
                                    }
                                    let pos = t.wrapping_sub(1);
                                    let entry = stdlib::deque::entry_path(&self.base_path, pos);
                                    let value = #vm::new(self.ctx.clone(), entry.clone()).load();
                                    stdlib::WriteStorage::__delete(&self.ctx, &entry);
                                    stdlib::deque::set_tail(&self.ctx, &self.base_path, pos);
                                    Some(value)
                                },
                            )
                        };
                        quote! {
                            pub fn push_back(&self, value: #v_ty) {
                                stdlib::deque::push_back(&self.ctx, &self.base_path, value)
                            }

                            pub fn push_front(&self, value: #v_ty) {
                                stdlib::deque::push_front(&self.ctx, &self.base_path, value)
                            }

                            pub fn pop_front(&self) -> Option<#v_ty> {
                                #pop_front_body
                            }

                            pub fn pop_back(&self) -> Option<#v_ty> {
                                #pop_back_body
                            }

                            /// Overwrite position `pos` (0 = front). Returns false if out of bounds.
                            pub fn set(&self, pos: u64, value: #v_ty) -> bool {
                                stdlib::deque::set(&self.ctx, &self.base_path, pos, value)
                            }
                        }
                    } else {
                        quote! {}
                    };

                    special_models.push(quote! {
                        #[derive(Clone)]
                        pub struct #field_model_name {
                            pub base_path: stdlib::KeyPath,
                            ctx: alloc::rc::Rc<#context_param>,
                        }

                        impl #field_model_name {
                            pub fn len(&self) -> u64 {
                                stdlib::deque::len(&self.ctx, &self.base_path)
                            }

                            pub fn is_empty(&self) -> bool {
                                self.len() == 0
                            }

                            /// Element at relative position `pos` (0 = front).
                            pub fn get(&self, pos: u64) -> Option<#item_ty> {
                                #get_body
                            }

                            pub fn front(&self) -> Option<#item_ty> {
                                self.get(0)
                            }

                            pub fn back(&self) -> Option<#item_ty> {
                                let n = self.len();
                                if n == 0 { None } else { self.get(n - 1) }
                            }

                            pub fn iter(&self) -> impl Iterator<Item = #item_ty> {
                                #iter_body
                            }

                            pub fn load(&self) -> Deque<#v_ty> {
                                Deque::new(&[])
                            }

                            #mutators
                        }
                    });

                    Ok(quote! {
                        pub fn #field_name(&self) -> #field_model_name {
                            #field_model_name { base_path: self.base_path.push_interned(#field_id), ctx: self.ctx.clone() }
                        }
                    })
                } else if utils::is_option_type(field_ty) {
                    let inner_ty = get_option_inner_type(field_ty)?;
                    let base_path = quote! { self.base_path.push_interned(#field_id) };
                    if utils::is_primitive_type(&inner_ty) {
                        Ok(quote! {
                            pub fn #field_name(&self) -> Option<#inner_ty> {
                                let base_path = #base_path;
                                if stdlib::ReadStorage::__extend_path_with_match(&self.ctx, &base_path, &[stdlib::string_element("none")]).is_some() {
                                    None
                                } else {
                                    stdlib::ReadStorage::__get(&self.ctx, base_path.push("some"))
                                }
                            }
                        })
                    } else {
                        let inner_model_ty = get_model_ident(write, &inner_ty, field.span())?;
                        let (load, ret_ty) = (quote! {}, quote! { #inner_model_ty });
                        Ok(quote! {
                            pub fn #field_name(&self) -> Option<#ret_ty> {
                                let base_path = #base_path;
                                if stdlib::ReadStorage::__extend_path_with_match(&self.ctx, &base_path, &[stdlib::string_element("none")]).is_some() {
                                    None
                                } else {
                                    Some(#inner_model_ty::new(self.ctx.clone(), base_path.push("some"))#load)
                                }
                            }
                        })
                    }
                } else if utils::is_primitive_type(field_ty) {
                    Ok(quote! {
                        pub fn #field_name(&self) -> #field_ty {
                            stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(#field_id)).unwrap()
                        }
                    })
                } else {
                    let field_model_ty = get_model_ident(write, field_ty, field.span())?;
                    Ok(quote! {
                        pub fn #field_name(&self) -> #field_model_ty {
                            #field_model_ty::new(self.ctx.clone(), self.base_path.push_interned(#field_id))
                        }
                    })
                }
            }).collect::<Result<Vec<_>>>()?;

            // A field's current stored value, as the read/write model exposes it:
            // a primitive getter yields the value; a non-primitive (e.g. enum)
            // getter yields a model, so `.load()` it. The value index entries are
            // built from — shared by the read model's `__index_entries` and the
            // in-place setters' reconcile (for fields they don't themselves change).
            let current_value = |field: &Ident| {
                let ty = index_decl::field_type(fields, field);
                // An `Option` field's getter already yields the `Option`, which
                // `IndexKey` buckets by its none/some discriminant (the payload is
                // irrelevant) — so no `.load()`, same as a primitive.
                if utils::is_primitive_type(ty) || utils::is_option_type(ty) {
                    quote! { self.#field() }
                } else {
                    quote! { self.#field().load() }
                }
            };

            let setters = if write {
                fields
                    .named
                    .iter()
                    .enumerate()
                    .map(|(field_idx, field)| {
                        let field_name = field.ident.as_ref().unwrap();
                        let field_id = field_idx as u8;
                        let field_ty = &field.ty;
                        let set_field_name =
                            Ident::new(&format!("set_{}", field_name), field_name.span());
                        let setter = quote! {
                            pub fn #set_field_name(&self, value: #field_ty) {
                                stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_interned(#field_id), value);
                            }
                        };

                        // Every index this field participates in, as a bucket OR a
                        // sort field. Setting it must move the member across all of
                        // them: the changed field uses `old`/`new`, every other
                        // participating field is read at its current value. Empty ⇒
                        // a plain write, nothing to reconcile.
                        let relevant: Vec<&IndexDecl> = decls
                            .iter()
                            .filter(|d| {
                                d.by.iter().any(|b| b == field_name)
                                    || d.sort.as_ref() == Some(field_name)
                            })
                            .collect();
                        let participates = !relevant.is_empty();
                        let reconcile = if participates {
                            // Read every OTHER participating field once; the changed
                            // field uses the `old`/`new` locals, so neither the two
                            // entry sides nor two indexes sharing a field re-read it.
                            let others: Vec<&Ident> =
                                index_decl::referenced_fields(relevant.iter().copied())
                                    .into_iter()
                                    .filter(|f| *f != field_name)
                                    .collect();
                            let hoists = others.iter().map(|f| {
                                let local = idx_local(f);
                                let read = current_value(f);
                                quote! { let #local = #read; }
                            });
                            let value_old = |g: &Ident| {
                                if g == field_name {
                                    quote! { old }
                                } else {
                                    let local = idx_local(g);
                                    quote! { #local }
                                }
                            };
                            let value_new = |g: &Ident| {
                                if g == field_name {
                                    quote! { new }
                                } else {
                                    let local = idx_local(g);
                                    quote! { #local }
                                }
                            };
                            let old_entries =
                                relevant.iter().map(|d| index_decl::index_entry(d, &value_old));
                            let new_entries =
                                relevant.iter().map(|d| index_decl::index_entry(d, &value_new));
                            quote! {
                                if let Some((index_root, index_key)) = &self.index_binding {
                                    #(#hoists)*
                                    stdlib::apply_index_diff(
                                        &self.ctx, index_root, index_key,
                                        &[#(#old_entries),*],
                                        &[#(#new_entries),*],
                                    );
                                }
                            }
                        } else {
                            quote! {}
                        };

                        if utils::is_map_type(field_ty) || utils::is_indexed_map_type(field_ty) {
                            Ok(quote! {})
                        } else if utils::is_primitive_type(field_ty) {
                            let update_field_name = Ident::new(&format!("update_{}", field_name), field_name.span());
                            let try_update_field_name = Ident::new(&format!("try_update_{}", field_name), field_name.span());
                            // A participating field's in-place write must read the old
                            // value to diff it; a non-participating `set` has nothing
                            // to reconcile, so it skips the read. `update`/`try_update`
                            // already read-modify-write, so they fold the reconcile in
                            // (empty for non-participating fields).
                            let set_fn = if participates {
                                quote! {
                                    pub fn #set_field_name(&self, value: #field_ty) {
                                        let path = self.base_path.push_interned(#field_id);
                                        let old: #field_ty = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
                                        let new = value;
                                        #reconcile
                                        stdlib::WriteStorage::__set(&self.ctx, path, new);
                                    }
                                }
                            } else {
                                setter
                            };
                            Ok(quote! {
                                #set_fn

                                pub fn #update_field_name(&self, f: impl Fn(#field_ty) -> #field_ty) {
                                    let path = self.base_path.push_interned(#field_id);
                                    let old: #field_ty = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
                                    let new = f(old.clone());
                                    #reconcile
                                    stdlib::WriteStorage::__set(&self.ctx, path, new);
                                }

                                pub fn #try_update_field_name(&self, f: impl Fn(#field_ty) -> Result<#field_ty, crate::error::Error>) -> Result<(), crate::error::Error> {
                                    let path = self.base_path.push_interned(#field_id);
                                    let old: #field_ty = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
                                    let new = f(old.clone())?;
                                    #reconcile
                                    stdlib::WriteStorage::__set(&self.ctx, path, new);
                                    Ok(())
                                }
                            })
                        } else if participates && utils::is_option_type(field_ty) {
                            // Participating `Option` field. Read the old value via the
                            // getter (which yields the `Option`); `IndexKey` buckets it
                            // by its none/some discriminant, so no model load is needed.
                            Ok(quote! {
                                pub fn #set_field_name(&self, value: #field_ty) {
                                    let path = self.base_path.push_interned(#field_id);
                                    let old = self.#field_name();
                                    let new = value;
                                    #reconcile
                                    stdlib::WriteStorage::__set(&self.ctx, path, new);
                                }
                            })
                        } else if participates {
                            // Participating non-primitive field (a storage enum). Read
                            // the old value through its model (live, via `ctx`) to
                            // reconcile every index it buckets, then write. Its value
                            // must be `IndexKey` — a storage enum keys by its
                            // discriminant via the `Storage` derive.
                            let v_model_ty = get_model_ident(true, field_ty, field.span())?;
                            Ok(quote! {
                                pub fn #set_field_name(&self, value: #field_ty) {
                                    let path = self.base_path.push_interned(#field_id);
                                    let old = #v_model_ty::new(self.ctx.clone(), path.clone()).load();
                                    let new = value;
                                    #reconcile
                                    stdlib::WriteStorage::__set(&self.ctx, path, new);
                                }
                            })
                        } else {
                            Ok(setter)
                        }
                    })
                    .collect::<Result<Vec<_>>>()?
            } else {
                Vec::new()
            };

            let load_fields = fields
                .named
                .iter()
                .map(|field| {
                    let field_name = field.ident.as_ref().unwrap();
                    let _field_name_str = field_name.to_string();
                    let field_ty = &field.ty;

                    if utils::is_map_type(field_ty) {
                        let (_k_ty, _v_ty) = get_map_types(field_ty)?;
                        Ok(quote! {
                            #field_name: self.#field_name().load()
                        })
                    } else if utils::is_option_type(field_ty) {
                        let inner_ty = get_option_inner_type(field_ty)?;
                        if utils::is_primitive_type(&inner_ty) {
                            Ok(quote! {
                                #field_name: self.#field_name()
                            })
                        } else {
                            let load = quote! { .map(|p| p.load()) };
                            Ok(quote! {
                                #field_name: self.#field_name()#load
                            })
                        }
                    } else if utils::is_primitive_type(field_ty) {
                        Ok(quote! {
                            #field_name: self.#field_name()
                        })
                    } else {
                        Ok(quote! {
                            #field_name: self.#field_name().load()
                        })
                    }
                })
                .collect::<Result<Vec<_>>>()?;

            // Write model: an optional binding to the owning IndexedMap (`#idx`
            // root + this entry's key), injected by the field model's `get` via
            // `with_index`; indexed-field setters consult it to keep the index in
            // step.
            let (binding_field, binding_init, with_index_method) = if write && has_indexed {
                (
                    quote! {
                        index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
                    },
                    quote! { index_binding: None, },
                    quote! {
                        pub fn with_index(mut self, index_root: stdlib::KeyPath, index_key: alloc::vec::Vec<u8>) -> Self {
                            self.index_binding = Some((index_root, index_key));
                            self
                        }
                    },
                )
            } else {
                (quote! {}, quote! {}, quote! {})
            };

            // Read model: recompute a value's index entries from ONLY its indexed
            // fields (via getters), so the field model can diff against the prior
            // value without loading the whole struct. Goes through the shared
            // `index_decl::index_entry`, so it matches what `Indexed::index_entries`
            // wrote. Works for WIT values too — they get the index declarations
            // injected by `contract!`'s `indexed = "..."`.
            let index_reader = if !write && has_indexed {
                // Read each referenced field once (a field shared by two indexes
                // would otherwise be read per index), then build entries from the
                // locals.
                let hoists = index_decl::referenced_fields(&decls).into_iter().map(|f| {
                    let local = idx_local(f);
                    let read = current_value(f);
                    quote! { let #local = #read; }
                });
                let value_for = |f: &Ident| {
                    let local = idx_local(f);
                    quote! { #local }
                };
                let pushes = decls.iter().map(|decl| {
                    let entry = index_decl::index_entry(decl, &value_for);
                    quote! { entries.push(#entry); }
                });
                quote! {
                    pub fn __index_entries(&self) -> alloc::vec::Vec<stdlib::IndexEntry> {
                        #(#hoists)*
                        let mut entries = alloc::vec::Vec::new();
                        #(#pushes)*
                        entries
                    }
                }
            } else {
                quote! {}
            };

            let proc_props = if write {
                quote! {
                    model: #read_only_model_name,
                }
            } else {
                quote! {}
            };

            let proc_prelude = if write {
                quote! {
                    let view_storage = ctx.view_storage();
                }
            } else {
                quote! {}
            };

            let proc_assigns = if write {
                quote! {
                    model: #read_only_model_name::new(alloc::rc::Rc::new(view_storage), base_path.clone()),
                }
            } else {
                quote! {}
            };

            let proc_impls = if write {
                quote! {
                    impl core::ops::Deref for #model_name {
                        type Target = #read_only_model_name;

                        fn deref(&self) -> &Self::Target {
                            &self.model
                        }
                    }
                }
            } else {
                quote! {}
            };

            let result = quote! {
                pub struct #model_name {
                    pub base_path: stdlib::KeyPath,
                    ctx: alloc::rc::Rc<#context_param>,
                    #binding_field
                    #proc_props
                }

                impl #model_name {
                    pub fn new(ctx: alloc::rc::Rc<#context_param>, base_path: stdlib::KeyPath) -> Self {
                        #proc_prelude
                        Self {
                            base_path: base_path.clone(),
                            ctx,
                            #binding_init
                            #proc_assigns
                        }
                    }

                    #with_index_method

                    #index_reader

                    #(#getters)*

                    #(#setters)*

                    pub fn load(&self) -> #type_name {
                        #type_name {
                            #(#load_fields,)*
                        }
                    }
                }

                #proc_impls

                #(#special_models)*
            };

            Ok(result)
        }
        _ => Err(Error::new(
            type_name.span(),
            "Model derive only supports structs with named fields",
        )),
    }
}

pub fn generate_enum(data_enum: &DataEnum, type_name: &Ident, write: bool) -> Result<TokenStream> {
    let write_prefix = if write { "Write" } else { "" };
    let model_name = Ident::new(
        &format!("{}{}Model", type_name, write_prefix),
        type_name.span(),
    );
    let context_param = if write {
        quote! { crate::context::ProcStorage }
    } else {
        quote! { crate::context::ViewStorage }
    };

    let model_variants: Result<Vec<_>> = data_enum
        .variants
        .iter()
        .map(|variant| {
            let variant_ident = &variant.ident;
            match &variant.fields {
                Fields::Unit => Ok(quote! { #variant_ident }),
                Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                    let inner_ty = &fields.unnamed[0].ty;
                    if utils::is_primitive_type(inner_ty) {
                        Ok(quote! { #variant_ident(#inner_ty) })
                    } else {
                        let inner_model_ty =
                            get_model_ident(write, inner_ty, variant.ident.span())?;
                        Ok(quote! { #variant_ident(#inner_model_ty) })
                    }
                }
                _ => Err(Error::new(
                    variant.ident.span(),
                    "Model derive only supports unit or single-field tuple variants",
                )),
            }
        })
        .collect();

    let model_variants = model_variants?;

    // Each variant's discriminant is an interned dict-ref id = its declaration
    // order in the enum (a per-enum dict, distinct from struct field ids), numbered
    // once via `numbered_variants` so the read side here and the write side in
    // `store::generate_enum_body` can't drift. The candidates the host byte-matches
    // are those dict-ref elements, in id order, so `extend_path_with_match` returns
    // the variant's index.
    let numbered = utils::numbered_variants(data_enum, type_name.span())?;
    let variant_candidates = numbered
        .iter()
        .map(|&(id, _)| quote! { stdlib::interned_element(#id) })
        .collect::<Vec<_>>();

    let new_arms = numbered.iter().map(|&(variant_id, variant)| {
        let variant_ident = &variant.ident;
        let arm_idx = variant_id as u32;

        // `__extend_path_with_match` returns the live variant's INDEX; match on it.
        match &variant.fields {
            Fields::Unit => Ok(quote! {
                #arm_idx => #model_name::#variant_ident
            }),
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                let inner_ty = &fields.unnamed[0].ty;
                if utils::is_primitive_type(inner_ty) {
                    Ok(quote! {
                        #arm_idx => #model_name::#variant_ident(stdlib::ReadStorage::__get(&ctx, base_path.push_interned(#variant_id)).unwrap())
                    })
                } else {
                    let inner_model_ty = get_model_ident(write, inner_ty, variant.ident.span())?;
                    Ok(quote! {
                        #arm_idx => #model_name::#variant_ident(#inner_model_ty::new(ctx.clone(), base_path.push_interned(#variant_id)))
                    })
                }
            }
            _ => unreachable!(),
        }
    }).collect::<Result<Vec<_>>>()?;

    let load_arms = data_enum.variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        match &variant.fields {
            Fields::Unit => quote! {
                #model_name::#variant_ident => #type_name::#variant_ident
            },
            Fields::Unnamed(fields) => {
                let inner_ty = &fields.unnamed[0].ty;
                if utils::is_primitive_type(inner_ty) {
                    quote! {
                        #model_name::#variant_ident(inner) => #type_name::#variant_ident(inner.clone())
                    }
                } else {
                    quote! {
                        #model_name::#variant_ident(inner) => #type_name::#variant_ident(inner.load())
                    }
                }
            }
            _ => unreachable!(),
        }
    }).collect::<Vec<_>>();

    Ok(quote! {
        pub enum #model_name {
            #(#model_variants,)*
        }

        impl #model_name {
            pub fn new(ctx: alloc::rc::Rc<#context_param>, base_path: stdlib::KeyPath) -> Self {
                stdlib::ReadStorage::__extend_path_with_match(&ctx, &base_path, &[#(#variant_candidates),*])
                    .map(|__idx| match __idx {
                        #(#new_arms,)*
                        _ => {
                            panic!("Matching path not found")
                        }
                    })
                    .unwrap()
            }

            pub fn load(&self) -> #type_name {
                match self {
                    #(#load_arms,)*
                }
            }
        }
    })
}

/// The `<Value>Index` lookup trait generated by the value type's `Indexed`
/// derive — named from the value type's last path segment, matching the derive.
fn index_trait_ident(ty: &Type, span: Span) -> Result<Ident> {
    if let Type::Path(type_path) = ty {
        type_path
            .path
            .segments
            .last()
            .map(|segment| Ident::new(&format!("{}Index", segment.ident), span))
            .ok_or_else(|| Error::new(span, "Expected a named type for IndexedMap value"))
    } else {
        Err(Error::new(
            span,
            "Expected a named type for IndexedMap value",
        ))
    }
}

/// The accessor element type for a collection value `v_ty`: the value itself for a
/// leaf (`u64`, `Vec<u8>`, …), or the value MODEL (`<V>Model`/`<V>WriteModel`) for a
/// struct/enum. Both model kinds share `new(ctx, path)` + `load()`, so callers
/// construct and materialize them uniformly. Centralizes the primitive-vs-model
/// dispatch shared by `Map` and `Deque`.
struct ValueItem {
    is_primitive: bool,
    /// The inner accessor type: `#v_ty` (leaf) or the value-model ident (struct/enum).
    item_ty: TokenStream,
    /// The value-model ident, for a struct/enum value (used to `::new(...)`/`load()`).
    model_ty: Option<Ident>,
}

fn value_item(write: bool, v_ty: &Type, span: Span) -> Result<ValueItem> {
    if utils::is_primitive_type(v_ty) {
        Ok(ValueItem {
            is_primitive: true,
            item_ty: quote! { #v_ty },
            model_ty: None,
        })
    } else {
        let model = get_model_ident(write, v_ty, span)?;
        Ok(ValueItem {
            is_primitive: false,
            item_ty: quote! { #model },
            model_ty: Some(model),
        })
    }
}

fn get_model_ident(write: bool, ty: &Type, span: Span) -> Result<Ident> {
    if let Type::Path(type_path) = ty {
        type_path
            .path
            .segments
            .last()
            .map(|segment| {
                Ident::new(
                    &format!("{}{}Model", segment.ident, if write { "Write" } else { "" }),
                    span,
                )
            })
            .ok_or_else(|| Error::new(span, "Expected a named type for variant field"))
    } else {
        Err(Error::new(span, "Expected a named type for variant field"))
    }
}

fn get_option_inner_type(ty: &Type) -> Result<Type> {
    if let Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
        && segment.ident == "Option"
        && let PathArguments::AngleBracketed(args) = &segment.arguments
        && args.args.len() == 1
        && let GenericArgument::Type(inner_ty) = &args.args[0]
    {
        return Ok(inner_ty.clone());
    }
    Err(Error::new(ty.span(), "Expected Option<T> type"))
}

fn get_map_types(ty: &Type) -> Result<(Type, Type)> {
    if let Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
        && segment.ident == "Map"
        && let PathArguments::AngleBracketed(args) = &segment.arguments
        && args.args.len() == 2
        && let (GenericArgument::Type(k_ty), GenericArgument::Type(v_ty)) =
            (&args.args[0], &args.args[1])
    {
        return Ok((k_ty.clone(), v_ty.clone()));
    }
    Err(Error::new(ty.span(), "Expected Map<K, V> type"))
}

fn get_indexed_map_types(ty: &Type) -> Result<(Type, Type)> {
    if let Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
        && segment.ident == "IndexedMap"
        && let PathArguments::AngleBracketed(args) = &segment.arguments
        && args.args.len() == 2
        && let (GenericArgument::Type(k_ty), GenericArgument::Type(v_ty)) =
            (&args.args[0], &args.args[1])
    {
        return Ok((k_ty.clone(), v_ty.clone()));
    }
    Err(Error::new(ty.span(), "Expected IndexedMap<K, V> type"))
}

fn get_deque_type(ty: &Type) -> Result<Type> {
    if let Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
        && segment.ident == "Deque"
        && let PathArguments::AngleBracketed(args) = &segment.arguments
        && args.args.len() == 1
        && let GenericArgument::Type(v_ty) = &args.args[0]
    {
        return Ok(v_ty.clone());
    }
    Err(Error::new(ty.span(), "Expected Deque<V> type"))
}
