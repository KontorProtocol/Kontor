extern crate proc_macro;

use darling::{FromMeta, ast::NestedMeta};
use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Error, ItemFn, parse_macro_input, spanned::Spanned};

mod contract;
mod contract_address;
mod holder_ref;
mod impls;
mod import;
mod index_decl;
mod indexed;
mod interface;
mod model;
mod regtest;
mod root;
mod storage_enum;
mod store;
mod test;
mod utils;
mod wavey;

#[proc_macro]
pub fn contract(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.into()).unwrap();
    let config = contract::Config::from_list(&attr_args).unwrap();
    contract::generate(config).into()
}

#[proc_macro]
pub fn impls(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.into()).unwrap();
    let config = impls::Config::from_list(&attr_args).unwrap();
    impls::generate(config).into()
}

#[proc_macro]
pub fn import(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.clone().into()).unwrap();
    let config = import::Config::from_list(&attr_args).unwrap();
    import::generate(config, false).into()
}

#[proc_macro]
pub fn import_test(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.clone().into()).unwrap();
    let config = import::Config::from_list(&attr_args).unwrap();
    import::generate(config, true).into()
}

#[proc_macro]
pub fn interface(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.clone().into()).unwrap();
    let config = interface::Config::from_list(&attr_args).unwrap();
    interface::generate(config, false).into()
}

#[proc_macro]
pub fn interface_test(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.clone().into()).unwrap();
    let config = interface::Config::from_list(&attr_args).unwrap();
    interface::generate(config, true).into()
}

#[proc_macro_derive(Store)]
pub fn derive_store(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let generics = &input.generics;

    if !generics.params.is_empty() {
        return Error::new(
            generics.span(),
            "Store derive does not support generic parameters (lifetimes or types)",
        )
        .to_compile_error()
        .into();
    }

    let body = match &input.data {
        Data::Struct(data_struct) => store::generate_struct_body(data_struct, name),
        Data::Enum(data_enum) => store::generate_enum_body(data_enum, name),
        Data::Union(_) => Err(Error::new(
            name.span(),
            "Store derive is not supported for unions",
        )),
    };

    let body = match body {
        Ok(body) => body,
        Err(err) => return err.to_compile_error().into(),
    };

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let expanded = quote! {
        #[automatically_derived]
        impl #impl_generics stdlib::Store<crate::context::ProcStorage> for #name #ty_generics #where_clause {
            fn __set(ctx: &alloc::rc::Rc<crate::context::ProcStorage>, base_path: stdlib::KeyPath, value: #name #ty_generics) {
                #body
            }
        }
    };

    TokenStream::from(expanded)
}

/// The `Indexed` impl + `<T>Index` lookup trait for a struct, folded into the
/// `Storage` derive so every struct storage value is `Indexed` (empty when it has
/// no `#[index]`). This is what lets one `Map<K, V>` serve plain and indexed
/// values: the generated `set` keys off `HAS_INDEXES` (a `const`) to skip index
/// maintenance entirely when there are none. Non-struct inputs get nothing here.
fn indexed_struct_tokens(input: &DeriveInput) -> proc_macro2::TokenStream {
    let name = &input.ident;
    let Data::Struct(syn::DataStruct {
        fields: syn::Fields::Named(fields),
        ..
    }) = &input.data
    else {
        return quote! {};
    };
    let decls = match index_decl::parse(&input.attrs, fields) {
        Ok(decls) => decls,
        Err(err) => return err.to_compile_error(),
    };
    let has_indexes = !decls.is_empty();
    let body = indexed::generate_index_entries(&decls);
    let lookup_trait = indexed::generate_lookup_trait(&decls, fields, name);
    quote! {
        #[automatically_derived]
        impl stdlib::Indexed for #name {
            const HAS_INDEXES: bool = #has_indexes;
            fn index_entries(&self) -> alloc::vec::Vec<stdlib::IndexEntry> {
                #body
            }
        }

        #lookup_trait
    }
}

/// The (always-empty) `Indexed` impl + `<E>Index` lookup trait for an enum, so an
/// enum can be a non-primitive `Map` value like any struct. Enums never declare
/// `#[index]`, so `HAS_INDEXES` is `false` and the field model's index path
/// const-folds out — the trait just supplies the primitives the merged `Map`
/// codegen expects. (The enum value model gets matching no-op `with_index` /
/// `__index_entries` from `model::generate_enum`.)
fn indexed_enum_tokens(name: &syn::Ident) -> proc_macro2::TokenStream {
    let empty_fields = syn::FieldsNamed {
        brace_token: Default::default(),
        named: syn::punctuated::Punctuated::new(),
    };
    let lookup_trait = indexed::generate_lookup_trait(&[], &empty_fields, name);
    quote! {
        #[automatically_derived]
        impl stdlib::Indexed for #name {
            const HAS_INDEXES: bool = false;
            fn index_entries(&self) -> alloc::vec::Vec<stdlib::IndexEntry> {
                alloc::vec::Vec::new()
            }
        }

        #lookup_trait
    }
}

#[proc_macro_derive(Model)]
pub fn derive_model(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let generics = &input.generics;

    let body = match &input.data {
        Data::Struct(data_struct) => model::generate_struct(data_struct, &input.attrs, name, false),
        Data::Enum(data_enum) => model::generate_enum(data_enum, name, false),
        Data::Union(_) => Err(Error::new(
            name.span(),
            "Wrapper derive is not supported for unions",
        )),
    };
    let mut body = match body {
        Ok(body) => body,
        Err(err) => return err.to_compile_error().into(),
    };

    let body_cont = match &input.data {
        Data::Struct(data_struct) => model::generate_struct(data_struct, &input.attrs, name, true),
        Data::Enum(data_enum) => model::generate_enum(data_enum, name, true),
        Data::Union(_) => Err(Error::new(
            name.span(),
            "Wrapper derive is not supported for unions",
        )),
    };
    let body_cont = match body_cont {
        Ok(body) => body,
        Err(err) => return err.to_compile_error().into(),
    };

    body.extend(body_cont);

    let (_impl_generics, _ty_generics, _where_clause) = generics.split_for_impl();
    quote! {
        #body
    }
    .into()
}

#[proc_macro_derive(Storage, attributes(index))]
pub fn derive_storage(input: TokenStream) -> TokenStream {
    let mut tokens = derive_store(input.clone());
    tokens.extend(derive_model(input.clone()));
    if let Ok(parsed) = syn::parse::<DeriveInput>(input) {
        match &parsed.data {
            // Structs fold in the index machinery (`Indexed` impl + `<T>Index`
            // lookup trait), empty when no `#[index]` — so every struct value is
            // `Indexed` and one `Map<K, V>` serves plain and indexed values.
            Data::Struct(_) => tokens.extend(TokenStream::from(indexed_struct_tokens(&parsed))),
            // Every storage enum gains its index machinery: the `<E>Kind` marker,
            // discriminant `From`, and `IndexKey`. All new names, so it's safe even
            // on built-ins like `HolderRef` whose `Display`/`FromStr` already exist.
            // It also gets the empty `Indexed` + `<E>Index` (so it can be a `Map`
            // value).
            Data::Enum(data_enum) => {
                match storage_enum::generate(data_enum, &parsed.ident) {
                    Ok(body) => tokens.extend(TokenStream::from(body)),
                    Err(err) => tokens.extend(TokenStream::from(err.to_compile_error())),
                }
                tokens.extend(TokenStream::from(indexed_enum_tokens(&parsed.ident)));
            }
            Data::Union(_) => {}
        }
    }
    tokens
}

#[proc_macro_derive(Root)]
pub fn derive_root(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let generics = &input.generics;

    let body = match &input.data {
        Data::Struct(data_struct) => root::generate_root_struct(data_struct, name),
        _ => Err(Error::new(
            name.span(),
            "Root derive only supports structs with named fields",
        )),
    };

    let body = match body {
        Ok(body) => body,
        Err(err) => return err.to_compile_error().into(),
    };

    let (_impl_generics, _ty_generics, _where_clause) = generics.split_for_impl();
    quote! {
        #body
    }
    .into()
}

#[proc_macro_derive(StorageRoot)]
pub fn derive_storage_root(input: TokenStream) -> TokenStream {
    let mut tokens = derive_storage(input.clone());
    tokens.extend(derive_root(input));
    tokens
}

#[proc_macro_derive(Wavey)]
pub fn derive_wavey(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let generics = &input.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let wave_type_body = match &input.data {
        Data::Struct(data) => wavey::generate_struct_wave_type_impl(data),
        Data::Enum(data) => wavey::generate_enum_wave_type_impl(data),
        _ => Err(Error::new(
            name.span(),
            "Wavey derive is only supported for structs and enums",
        )),
    };

    let wave_type_body = match wave_type_body {
        Ok(body) => body,
        Err(err) => return err.to_compile_error().into(),
    };

    let from_self_body = match &input.data {
        Data::Struct(data) => wavey::generate_struct_to_value(data, name),
        Data::Enum(data) => wavey::generate_enum_to_value(data, name),
        _ => Err(Error::new(
            name.span(),
            "Wavey derive is only supported for structs and enums",
        )),
    };

    let from_self_body = match from_self_body {
        Ok(body) => body,
        Err(err) => return err.to_compile_error().into(),
    };

    let from_wave_value_body = match &input.data {
        Data::Struct(data) => wavey::generate_struct_from_wave_value(data, name),
        Data::Enum(data) => wavey::generate_enum_from_wave_value(data, name),
        _ => Err(Error::new(
            name.span(),
            "Wavey derive is only supported for structs and enums",
        )),
    };

    let from_wave_value_body = match from_wave_value_body {
        Ok(body) => body,
        Err(err) => return err.to_compile_error().into(),
    };

    quote! {
        #[automatically_derived]
        impl stdlib::WaveType for #name {
            fn wave_type() -> stdlib::wasm_wave::value::Type {
                #wave_type_body
            }
        }

        #[automatically_derived]
        impl stdlib::FromWaveValue for #name {
            fn from_wave_value(value_: stdlib::wasm_wave::value::Value) -> Self {
                #from_wave_value_body
            }
        }

        #[automatically_derived]
        impl #impl_generics From<#name #ty_generics> for stdlib::wasm_wave::value::Value #where_clause {
            fn from(value_: #name #ty_generics) -> Self {
                #from_self_body
            }
        }

        #[automatically_derived]
        impl #impl_generics From<stdlib::wasm_wave::value::Value> for #name #ty_generics #where_clause {
            fn from(value_: stdlib::wasm_wave::value::Value) -> Self {
                stdlib::from_wave_value(value_)
            }
        }
    }
    .into()
}

#[proc_macro_attribute]
pub fn test(attr: TokenStream, item: TokenStream) -> TokenStream {
    let config: test::Config = match syn::parse(attr) {
        Ok(v) => v,
        Err(e) => {
            return e.to_compile_error().into();
        }
    };
    let func = parse_macro_input!(item as ItemFn);
    test::generate(config, func).into()
}

#[proc_macro]
pub fn regtest_tests(input: TokenStream) -> TokenStream {
    let config = parse_macro_input!(input as regtest::Config);
    regtest::generate(config).into()
}

#[proc_macro]
pub fn contract_address(input: TokenStream) -> TokenStream {
    contract_address::generate(input)
}

#[proc_macro]
pub fn holder_ref(input: TokenStream) -> TokenStream {
    holder_ref::generate(input)
}
