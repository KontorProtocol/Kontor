extern crate proc_macro;

use std::fs;

use darling::{FromMeta, ast::NestedMeta};
use heck::ToPascalCase;
use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Error, Ident, parse_macro_input, spanned::Spanned};

use wit_parser::{Resolve, TypeDefKind, WorldItem, WorldKey};

mod import;
mod root;
mod store;
mod utils;
mod wavey;
mod wrapper;

#[derive(FromMeta)]
struct ContractConfig {
    name: String,
    world: Option<String>,
    path: Option<String>,
}

#[proc_macro]
pub fn contract(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.into()).unwrap();
    let config = ContractConfig::from_list(&attr_args).unwrap();

    let world = config.world.unwrap_or("contract".to_string());
    let path = config.path.unwrap_or("wit".to_string());
    let name = Ident::from_string(&config.name.to_pascal_case()).unwrap();
    let boilerplate = quote! {
        use stdlib::*;

        wit_bindgen::generate!({
            world: #world,
            path: #path,
            generate_all,
            additional_derives: [stdlib::Storage],
        });

        use kontor::built_in::*;
        use kontor::built_in::foreign::ContractAddressWrapper;

        impl ReadContext for context::ViewContext {
            fn __get_str(&self, path: &str) -> Option<String> {
                self.get_str(path)
            }

            fn __get_u64(&self, path: &str) -> Option<u64> {
                self.get_u64(path)
            }

            fn __get_s64(&self, path: &str) -> Option<i64> {
                self.get_s64(path)
            }

            fn __exists(&self, path: &str) -> bool {
                self.exists(path)
            }

            fn __is_void(&self, path: &str) -> bool {
                self.is_void(path)
            }

            fn __matching_path(&self, regexp: &str) -> Option<String> {
                self.matching_path(regexp)
            }

            fn __get<T: Retrieve>(&self, path: DotPathBuf) -> Option<T> {
                T::__get(self, path)
            }
        }

        impl ReadContext for context::ProcContext {
            fn __get_str(&self, path: &str) -> Option<String> {
                self.get_str(path)
            }

            fn __get_u64(&self, path: &str) -> Option<u64> {
                self.get_u64(path)
            }

            fn __get_s64(&self, path: &str) -> Option<i64> {
                self.get_s64(path)
            }

            fn __exists(&self, path: &str) -> bool {
                self.exists(path)
            }

            fn __is_void(&self, path: &str) -> bool {
                self.is_void(path)
            }

            fn __matching_path(&self, regexp: &str) -> Option<String> {
                self.matching_path(regexp)
            }

            fn __get<T: Retrieve>(&self, path: DotPathBuf) -> Option<T> {
                T::__get(self, path)
            }
        }

        impl WriteContext for context::ProcContext {
            fn __set_str(&self, path: &str, value: &str) {
                self.set_str(path, value)
            }

            fn __set_u64(&self, path: &str, value: u64) {
                self.set_u64(path, value)
            }

            fn __set_s64(&self, path: &str, value: i64) {
                self.set_s64(path, value)
            }

            fn __set_void(&self, path: &str) {
                self.set_void(path)
            }

            fn __set<T: stdlib::Store>(&self, path: DotPathBuf, value: T) {
                T::__set(self, path, value)
            }
        }

        impl ReadWriteContext for context::ProcContext {}

        impl From<core::num::ParseIntError> for kontor::built_in::error::Error {
            fn from(err: core::num::ParseIntError) -> Self {
                kontor::built_in::error::Error::Message(format!("Parse integer error: {:?}", err))
            }
        }

        impl From<core::num::TryFromIntError> for kontor::built_in::error::Error {
            fn from(err: core::num::TryFromIntError) -> Self {
                kontor::built_in::error::Error::Message(format!("Try from integer error: {:?}", err))
            }
        }

        impl From<core::str::Utf8Error> for kontor::built_in::error::Error {
            fn from(err: core::str::Utf8Error) -> Self {
                kontor::built_in::error::Error::Message(format!("UTF-8 parse error: {:?}", err))
            }
        }

        impl From<core::char::ParseCharError> for kontor::built_in::error::Error {
            fn from(err: core::char::ParseCharError) -> Self {
                kontor::built_in::error::Error::Message(format!("Parse char error: {:?}", err))
            }
        }

        impl kontor::built_in::error::Error {
            pub fn new(message: impl Into<String>) -> Self {
                kontor::built_in::error::Error::Message(message.into())
            }
        }

        struct #name;

        export!(#name);
    };

    boilerplate.into()
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
        impl #impl_generics stdlib::Store for #name #ty_generics #where_clause {
            fn __set(ctx: &impl stdlib::WriteContext, base_path: stdlib::DotPathBuf, value: #name #ty_generics) {
                #body
            }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(Wrapper)]
pub fn derive_wrapper(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let generics = &input.generics;

    let body = match &input.data {
        Data::Struct(data_struct) => wrapper::generate_struct_wrapper(data_struct, name),
        Data::Enum(data_enum) => wrapper::generate_enum_wrapper(data_enum, name),
        Data::Union(_) => Err(Error::new(
            name.span(),
            "Wrapper derive is not supported for unions",
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

#[proc_macro_derive(Storage)]
pub fn derive_storage(input: TokenStream) -> TokenStream {
    let mut tokens = derive_store(input.clone());
    tokens.extend(derive_wrapper(input));
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
    let mut tokens = derive_store(input.clone());
    tokens.extend(derive_wrapper(input.clone()));
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
        Data::Struct(data) => wavey::generate_struct_wave_type(data),
        Data::Enum(data) => wavey::generate_enum_wave_type(data),
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

    let from_value_body = match &input.data {
        Data::Struct(data) => wavey::generate_struct_from_value(data, name),
        Data::Enum(data) => wavey::generate_enum_from_value(data, name),
        _ => Err(Error::new(
            name.span(),
            "Wavey derive is only supported for structs and enums",
        )),
    };

    let from_value_body = match from_value_body {
        Ok(body) => body,
        Err(err) => return err.to_compile_error().into(),
    };

    quote! {
        impl #impl_generics #name #ty_generics #where_clause {
            pub fn wave_type() -> wasm_wave::value::Type {
                #wave_type_body
            }
        }

        impl #impl_generics From<#name #ty_generics> for wasm_wave::value::Value #where_clause {
            fn from(value_: #name #ty_generics) -> Self {
                #from_self_body
            }
        }

        impl #impl_generics From<wasm_wave::value::Value> for #name #ty_generics #where_clause {
            fn from(value_: wasm_wave::value::Value) -> Self {
                #from_value_body
            }
        }
    }
    .into()
}

#[derive(FromMeta)]
struct ImportConfig {
    name: String,
    height: i64,
    tx_index: i64,
    path: String,
    world: Option<String>,
}

#[proc_macro]
pub fn import(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.clone().into()).unwrap();
    let config = ImportConfig::from_list(&attr_args).unwrap();

    let name = config.name;
    let module_name = Ident::from_string(name.to_string().as_str()).unwrap();
    let height = config.height;
    let tx_index = config.tx_index;
    let path = config.path;
    let world_name = config.world.unwrap_or("contract".to_string());

    assert!(fs::metadata(&path).is_ok());
    let mut resolve = Resolve::new();
    resolve.push_dir(&path).unwrap();

    let (_world_id, world) = resolve
        .worlds
        .iter()
        .find(|(_, w)| w.name == world_name)
        .unwrap();

    let exports = world
        .exports
        .iter()
        .filter_map(|e| match e {
            (WorldKey::Name(name), WorldItem::Function(f))
                if !["init"].contains(&name.as_str()) =>
            {
                Some(f)
            }
            _ => None,
        })
        .collect::<Vec<_>>();

    let mut type_streams = Vec::new();
    for (_id, def) in resolve.types.iter().filter(|(_, def)| {
        if let Some(name) = def.name.as_deref() {
            ![
                "contract-address",
                "view-context",
                "fall-context",
                "proc-context",
                "signer",
                "error",
            ]
            .contains(&name)
        } else {
            false
        }
    }) {
        let name = def.name.as_deref().expect("Filtered types have names");
        let stream = match &def.kind {
            TypeDefKind::Record(record) => import::print_typedef_record(&resolve, name, record),
            TypeDefKind::Enum(enum_) => import::print_typedef_enum(name, enum_),
            TypeDefKind::Variant(variant) => import::print_typedef_variant(&resolve, name, variant),
            _ => panic!("Unsupported type definition kind: {:?}", def.kind),
        }
        .expect("Failed to generate type");
        type_streams.push(stream);
    }

    let mut func_streams = Vec::new();
    for export in exports {
        func_streams.push(
            import::generate_functions(&resolve, export, height, tx_index)
                .expect("Function didn't generate"),
        )
    }

    quote! {
        mod #module_name {
            use wasm_wave::wasm::WasmValue as _;
            use stdlib::Wavey;

            use super::context;
            use super::foreign;
            use super::error::Error;

            const CONTRACT_NAME: &str = #name;

            impl foreign::ContractAddress {
                pub fn wave_type() -> wasm_wave::value::Type {
                    wasm_wave::value::Type::record([
                        ("name", wasm_wave::value::Type::STRING),
                        ("height", wasm_wave::value::Type::S64),
                        ("tx_index", wasm_wave::value::Type::S64),
                    ])
                    .unwrap()
                }
            }

            impl From<foreign::ContractAddress> for wasm_wave::value::Value {
                fn from(value_: foreign::ContractAddress) -> Self {
                    wasm_wave::value::Value::make_record(
                        &foreign::ContractAddress::wave_type(),
                        [
                            ("name", wasm_wave::value::Value::from(value_.name)),
                            ("height", wasm_wave::value::Value::from(value_.height)),
                            ("tx_index", wasm_wave::value::Value::from(value_.tx_index)),
                        ],
                    )
                    .unwrap()
                }
            }

            impl From<wasm_wave::value::Value> for foreign::ContractAddress {
                fn from(value_: wasm_wave::value::Value) -> Self {
                    let mut name = None;
                    let mut height = None;
                    let mut tx_index = None;

                    for (key_, val_) in  value_.unwrap_record() {
                        match key_.as_ref() {
                            "name" => name = Some(val_.unwrap_string().into_owned()),
                            "height" => height = Some(val_.unwrap_s64()),
                            "tx_index" => tx_index = Some(val_.unwrap_s64()),
                            key_ => panic!("Unknown field: {}", key_),
                        }
                    }

                    Self {
                        name: name.expect("Missing 'name' field"),
                        height: height.expect("Missing 'height' field"),
                        tx_index: tx_index.expect("Missing 'tx_index' field"),
                    }
                }
            }

            impl Error {
                pub fn wave_type() -> wasm_wave::value::Type {
                    wasm_wave::value::Type::variant([
                            ("message", Some(wasm_wave::value::Type::STRING)),
                        ])
                        .unwrap()
                }
            }
            impl From<Error> for wasm_wave::value::Value {
                fn from(value_: Error) -> Self {
                    (match value_ {
                        Error::Message(operand) => {
                            wasm_wave::value::Value::make_variant(
                                &Error::wave_type(),
                                "message",
                                Some(wasm_wave::value::Value::from(operand)),
                            )
                        }
                    })
                        .unwrap()
                }
            }
            impl From<wasm_wave::value::Value> for Error {
                fn from(value_: wasm_wave::value::Value) -> Self {
                    let (key_, val_) = value_.unwrap_variant();
                    match key_ {
                        key_ if key_.eq("message") => {
                            Error::Message(val_.unwrap().unwrap_string().into_owned())
                        }
                        key_ => panic!("Unknown tag {}", key_),
                    }
                }
            }

             #(#type_streams)*
             #(#func_streams)*
        }
    }
    .into()
}
