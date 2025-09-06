extern crate proc_macro;

use darling::{FromMeta, ast::NestedMeta};
use heck::{ToPascalCase, ToSnakeCase};
use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Error, Ident, parse_macro_input, spanned::Spanned};

mod import;
mod root;
mod store;
mod transformers;
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
        wit_bindgen::generate!({
            world: #world,
            path: #path,
            generate_all,
            additional_derives: [stdlib::Storage, stdlib::Wavey],
            export_macro_name: "__export__",
        });

        use std::{cmp::Ordering, ops::{Add, Sub, Mul, Div}};
        use stdlib::wasm_wave::wasm::WasmValue as _;
        use kontor::built_in::*;
        use kontor::built_in::foreign::ContractAddressWrapper;
        use kontor::built_in::numbers::IntegerWrapper;
        use kontor::built_in::numbers::DecimalWrapper;

        fn make_keys_iterator<T: FromString>(keys: context::Keys) -> impl Iterator<Item = T> {
            struct KeysIterator<T: FromString> {
                keys: context::Keys,
                _phantom: std::marker::PhantomData<T>,
            }

            impl<T: FromString> Iterator for KeysIterator<T> {
                type Item = T;
                fn next(&mut self) -> Option<Self::Item> {
                    self.keys.next().map(|s| T::from_string(s))
                }
            }

            KeysIterator {
                keys,
                _phantom: std::marker::PhantomData,
            }
        }

        #[automatically_derived]
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

            fn __get_bool(&self, path: &str) -> Option<bool> {
                self.get_bool(path)
            }

            fn __get_keys<'a, T: ToString + FromString + Clone + 'a>(&self, path: &'a str) -> impl Iterator<Item = T> + 'a {
                make_keys_iterator(self.get_keys(path))
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

        #[automatically_derived]
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

            fn __get_bool(&self, path: &str) -> Option<bool> {
                self.get_bool(path)
            }

            fn __get_keys<'a, T: ToString + FromString + Clone + 'a>(&self, path: &'a str) -> impl Iterator<Item = T> + 'a{
                make_keys_iterator(self.get_keys(path))
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

        #[automatically_derived]
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

            fn __set_bool(&self, path: &str, value: bool) {
                self.set_bool(path, value)
            }

            fn __set_void(&self, path: &str) {
                self.set_void(path)
            }

            fn __set<T: stdlib::Store>(&self, path: DotPathBuf, value: T) {
                T::__set(self, path, value)
            }
        }

        #[automatically_derived]
        impl ReadWriteContext for context::ProcContext {}

        #[automatically_derived]
        impl From<core::num::ParseIntError> for kontor::built_in::error::Error {
            fn from(err: core::num::ParseIntError) -> Self {
                kontor::built_in::error::Error::Message(format!("Parse integer error: {:?}", err))
            }
        }

        #[automatically_derived]
        impl From<core::num::TryFromIntError> for kontor::built_in::error::Error {
            fn from(err: core::num::TryFromIntError) -> Self {
                kontor::built_in::error::Error::Message(format!("Try from integer error: {:?}", err))
            }
        }

        #[automatically_derived]
        impl From<core::str::Utf8Error> for kontor::built_in::error::Error {
            fn from(err: core::str::Utf8Error) -> Self {
                kontor::built_in::error::Error::Message(format!("UTF-8 parse error: {:?}", err))
            }
        }

        #[automatically_derived]
        impl From<core::char::ParseCharError> for kontor::built_in::error::Error {
            fn from(err: core::char::ParseCharError) -> Self {
                kontor::built_in::error::Error::Message(format!("Parse char error: {:?}", err))
            }
        }

        #[automatically_derived]
        impl kontor::built_in::error::Error {
            pub fn new(message: impl Into<String>) -> Self {
                kontor::built_in::error::Error::Message(message.into())
            }
        }

        #[automatically_derived]
        impl Default for numbers::Integer {
            fn default() -> Self {
                Self {
                    value: "0".to_string(),
                }
            }
        }

        #[automatically_derived]
        impl Add for numbers::Integer {
            type Output = Self;

            fn add(self, other: Self) -> Self::Output {
                numbers::add_integer(&self, &other)
            }
        }

        #[automatically_derived]
        impl Sub for numbers::Integer {
            type Output = Self;

            fn sub(self, other: Self) -> Self::Output {
                numbers::sub_integer(&self, &other)
            }
        }

        #[automatically_derived]
        impl Mul for numbers::Integer {
            type Output = Self;

            fn mul(self, rhs: Self) -> Self {
                numbers::mul_integer(&self, &rhs)
            }
        }

        #[automatically_derived]
        impl Div for numbers::Integer {
            type Output = Self;

            fn div(self, rhs: Self) -> Self {
                numbers::div_integer(&self, &rhs)
            }
        }

        #[automatically_derived]
        impl PartialOrd for numbers::Integer {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        #[automatically_derived]
        impl Ord for numbers::Integer {
            fn cmp(&self, other: &Self) -> Ordering {
                match numbers::cmp_integer(&self, &other) {
                    numbers::Ordering::Less => Ordering::Less,
                    numbers::Ordering::Equal => Ordering::Equal,
                    numbers::Ordering::Greater => Ordering::Greater,
                }
            }
        }

        #[automatically_derived]
        impl PartialEq for numbers::Integer {
            fn eq(&self, other: &Self) -> bool {
                numbers::eq_integer(&self, &other)
            }
        }

        #[automatically_derived]
        impl Eq for numbers::Integer {}

        #[automatically_derived]
        impl Default for numbers::Decimal {
            fn default() -> Self {
                Self {
                    value: "0.0".to_string(),
                }
            }
        }

        #[automatically_derived]
        impl Add for numbers::Decimal {
            type Output = Self;

            fn add(self, other: Self) -> Self::Output {
                numbers::add_decimal(&self, &other)
            }
        }

        #[automatically_derived]
        impl Sub for numbers::Decimal {
            type Output = Self;

            fn sub(self, other: Self) -> Self::Output {
                numbers::sub_decimal(&self, &other)
            }
        }

        #[automatically_derived]
        impl Mul for numbers::Decimal {
            type Output = Self;

            fn mul(self, rhs: Self) -> Self {
                numbers::mul_decimal(&self, &rhs)
            }
        }

        #[automatically_derived]
        impl Div for numbers::Decimal {
            type Output = Self;

            fn div(self, rhs: Self) -> Self {
                numbers::div_decimal(&self, &rhs)
            }
        }


        #[automatically_derived]
        impl PartialOrd for numbers::Decimal {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        #[automatically_derived]
        impl Ord for numbers::Decimal {
            fn cmp(&self, other: &Self) -> Ordering {
                match numbers::cmp_decimal(&self, &other) {
                    numbers::Ordering::Less => Ordering::Less,
                    numbers::Ordering::Equal => Ordering::Equal,
                    numbers::Ordering::Greater => Ordering::Greater,
                }
            }
        }

        #[automatically_derived]
        impl PartialEq for numbers::Decimal {
            fn eq(&self, other: &Self) -> bool {
                numbers::eq_decimal(&self, &other)
            }
        }

        #[automatically_derived]
        impl Eq for numbers::Decimal {}

        #[automatically_derived]
        impl From<numbers::Integer> for numbers::Decimal {
            fn from(i: numbers::Integer) -> numbers::Decimal {
                numbers::integer_to_decimal(&i)
            }
        }

        struct #name;

        __export__!(#name);
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
        #[automatically_derived]
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
            pub fn wave_type() -> stdlib::wasm_wave::value::Type {
                #wave_type_body
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
                #from_value_body
            }
        }
    }
    .into()
}

#[derive(FromMeta)]
struct ImportConfig {
    name: String,
    mod_name: Option<String>,
    height: i64,
    tx_index: i64,
    path: String,
    world: Option<String>,
    test: Option<bool>,
}

#[proc_macro]
pub fn import(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.clone().into()).unwrap();
    let config = ImportConfig::from_list(&attr_args).unwrap();

    let name = config.name;
    let module_name =
        Ident::from_string(&config.mod_name.unwrap_or(name.clone().to_snake_case())).unwrap();
    let height = config.height;
    let tx_index = config.tx_index;
    let path = config.path;
    let world_name = config.world.unwrap_or("contract".to_string());
    let test = config.test.unwrap_or(false);

    import::import(
        path,
        module_name,
        world_name,
        Some((&name, height, tx_index)),
        test,
    )
    .into()
}

#[derive(FromMeta)]
struct InterfaceConfig {
    name: String,
    path: String,
    world: Option<String>,
    test: Option<bool>,
}

#[proc_macro]
pub fn interface(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.clone().into()).unwrap();
    let config = InterfaceConfig::from_list(&attr_args).unwrap();

    let name = config.name;
    let module_name = Ident::from_string(&name.clone().to_snake_case()).unwrap();
    let path = config.path;
    let world_name = config.world.unwrap_or("contract".to_string());
    let test = config.test.unwrap_or(false);

    import::import(path, module_name, world_name, None, test).into()
}
