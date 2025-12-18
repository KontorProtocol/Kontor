use darling::FromMeta;
use heck::ToPascalCase;
use proc_macro2::TokenStream;
use quote::quote;
use std::path::Path;
use syn::Ident;

#[derive(FromMeta)]
pub struct Config {
    name: String,
    path: Option<String>,
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
    let path = abs_path.to_string_lossy().to_string();
    quote! {
        extern crate alloc;

        use alloc::{
            format,
            string::{String, ToString},
            vec::Vec,
        };
        use core::{fmt::Debug, str::FromStr};

        wit_bindgen::generate!({
            world: "root",
            path: #path,
            generate_all,
            generate_unused_types: true,
            additional_derives: [stdlib::Storage, stdlib::Wavey],
            export_macro_name: "__export__",
            runtime_path: "stdlib::wit_bindgen::rt",
        });

        use kontor::built_in::*;
        use kontor::built_in::foreign::{ContractAddressModel, ContractAddressWriteModel, get_contract_address};
        use kontor::built_in::numbers::{IntegerModel, IntegerWriteModel, DecimalModel, DecimalWriteModel};

        type Map<K, V> = stdlib::StorageMap<K, V, context::ProcStorage>;

        impl stdlib::HasNext for context::Keys {
            fn next(&self) -> Option<String> {
                self.next()
            }
        }

        #[automatically_derived]
        impl stdlib::ReadStorage for context::ViewStorage {
            fn __get_str(self: &alloc::rc::Rc<Self>, path: &str) -> Option<String> {
                self.get_str(path)
            }

            fn __get_u64(self: &alloc::rc::Rc<Self>, path: &str) -> Option<u64> {
                self.get_u64(path)
            }

            fn __get_s64(self: &alloc::rc::Rc<Self>, path: &str) -> Option<i64> {
                self.get_s64(path)
            }

            fn __get_bool(self: &alloc::rc::Rc<Self>, path: &str) -> Option<bool> {
                self.get_bool(path)
            }

            fn __get_list_u8(self: &alloc::rc::Rc<Self>, path: &str) -> Option<Vec<u8>> {
                self.get_list_u8(path)
            }

            fn __get_keys<'a, T: ToString + FromStr + Clone + 'a>(self: &alloc::rc::Rc<Self>, path: &'a str) -> impl Iterator<Item = T> + 'a
            where
                <T as FromStr>::Err: Debug,
            {
                stdlib::make_keys_iterator(self.get_keys(path))
            }

            fn __exists(self: &alloc::rc::Rc<Self>, path: &str) -> bool {
                self.exists(path)
            }

            fn __extend_path_with_match(self: &alloc::rc::Rc<Self>, path: &str, variants: &[&str]) -> Option<String> {
                self.extend_path_with_match(path, &variants.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            }

            fn __get<T: Retrieve<Self>>(self: &alloc::rc::Rc<Self>, path: DotPathBuf) -> Option<T> {
                T::__get(self, path)
            }
        }

        #[automatically_derived]
        impl stdlib::ReadStorage for context::ProcStorage {
            fn __get_str(self: &alloc::rc::Rc<Self>, path: &str) -> Option<String> {
                self.get_str(path)
            }

            fn __get_u64(self: &alloc::rc::Rc<Self>, path: &str) -> Option<u64> {
                self.get_u64(path)
            }

            fn __get_s64(self: &alloc::rc::Rc<Self>, path: &str) -> Option<i64> {
                self.get_s64(path)
            }

            fn __get_bool(self: &alloc::rc::Rc<Self>, path: &str) -> Option<bool> {
                self.get_bool(path)
            }

            fn __get_list_u8(self: &alloc::rc::Rc<Self>, path: &str) -> Option<Vec<u8>> {
                self.get_list_u8(path)
            }

            fn __get_keys<'a, T: ToString + FromStr + Clone + 'a>(self: &alloc::rc::Rc<Self>, path: &'a str) -> impl Iterator<Item = T> + 'a
            where
                <T as FromStr>::Err: Debug,
            {
                stdlib::make_keys_iterator(self.get_keys(path))
            }

            fn __exists(self: &alloc::rc::Rc<Self>, path: &str) -> bool {
                self.exists(path)
            }

            fn __extend_path_with_match(self: &alloc::rc::Rc<Self>, path: &str, variants: &[&str]) -> Option<String> {
                self.extend_path_with_match(path, &variants.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            }

            fn __get<T: Retrieve<Self>>(self: &alloc::rc::Rc<Self>, path: DotPathBuf) -> Option<T> {
                T::__get(self, path)
            }
        }

        #[automatically_derived]
        impl stdlib::WriteStorage for context::ProcStorage {
            fn __set_str(self: &alloc::rc::Rc<Self>, path: &str, value: &str) {
                self.set_str(path, value)
            }

            fn __set_u64(self: &alloc::rc::Rc<Self>, path: &str, value: u64) {
                self.set_u64(path, value)
            }

            fn __set_s64(self: &alloc::rc::Rc<Self>, path: &str, value: i64) {
                self.set_s64(path, value)
            }

            fn __set_bool(self: &alloc::rc::Rc<Self>, path: &str, value: bool) {
                self.set_bool(path, value)
            }

            fn __set_list_u8(self: &alloc::rc::Rc<Self>, path: &str, value: Vec<u8>) {
                self.set_list_u8(path, &value)
            }

            fn __set_void(self: &alloc::rc::Rc<Self>, path: &str) {
                self.set_void(path)
            }

            fn __set<T: stdlib::Store<Self>>(self: &alloc::rc::Rc<Self>, path: DotPathBuf, value: T) {
                T::__set(self, path, value)
            }

            fn __delete_matching_paths(self: &alloc::rc::Rc<Self>, base_path: &str, variants: &[&str]) -> u64 {
                self.delete_matching_paths(base_path, &variants.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            }
        }

        impl Retrieve<crate::context::ViewStorage> for foreign::ContractAddress {
            fn __get(ctx: &alloc::rc::Rc<crate::context::ViewStorage>, path: stdlib::DotPathBuf) -> Option<Self> {
                stdlib::ReadStorage::__exists(ctx, &path).then(|| foreign::ContractAddressModel::new(ctx.clone(), path).load())
            }
        }

        impl Retrieve<crate::context::ProcStorage> for foreign::ContractAddress {
            fn __get(ctx: &alloc::rc::Rc<crate::context::ProcStorage>, path: stdlib::DotPathBuf) -> Option<Self> {
                stdlib::ReadStorage::__exists(ctx, &path).then(|| foreign::ContractAddressWriteModel::new(ctx.clone(), path).load())
            }
        }

        impl Retrieve<crate::context::ViewStorage> for numbers::Integer {
            fn __get(ctx: &alloc::rc::Rc<crate::context::ViewStorage>, path: stdlib::DotPathBuf) -> Option<Self> {
                stdlib::ReadStorage::__exists(ctx, &path).then(|| numbers::IntegerModel::new(ctx.clone(), path).load())
            }
        }

        impl Retrieve<crate::context::ProcStorage> for numbers::Integer {
            fn __get(ctx: &alloc::rc::Rc<crate::context::ProcStorage>, path: stdlib::DotPathBuf) -> Option<Self> {
                stdlib::ReadStorage::__exists(ctx, &path).then(|| numbers::IntegerWriteModel::new(ctx.clone(), path).load())
            }
        }

        impl Retrieve<crate::context::ViewStorage> for numbers::Decimal {
            fn __get(ctx: &alloc::rc::Rc<crate::context::ViewStorage>, path: stdlib::DotPathBuf) -> Option<Self> {
                stdlib::ReadStorage::__exists(ctx, &path).then(|| numbers::DecimalModel::new(ctx.clone(), path).load())
            }
        }

        impl Retrieve<crate::context::ProcStorage> for numbers::Decimal {
            fn __get(ctx: &alloc::rc::Rc<crate::context::ProcStorage>, path: stdlib::DotPathBuf) -> Option<Self> {
                stdlib::ReadStorage::__exists(ctx, &path).then(|| numbers::DecimalWriteModel::new(ctx.clone(), path).load())
            }
        }

        impls!();

        struct #name;

        __export__!(#name);
    }
}
