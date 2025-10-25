use darling::FromMeta;
use heck::ToPascalCase;
use proc_macro2::TokenStream;
use quote::quote;
use syn::Ident;

#[derive(FromMeta)]
pub struct Config {
    name: String,
    world: Option<String>,
    path: Option<String>,
}

pub fn generate(config: Config) -> TokenStream {
    let world = config.world.unwrap_or("contract".to_string());
    let path = config.path.unwrap_or("wit".to_string());
    let name = Ident::from_string(&config.name.to_pascal_case()).unwrap();
    quote! {
        wit_bindgen::generate!({
            world: #world,
            path: #path,
            generate_all,
            additional_derives: [stdlib::Storage, stdlib::Wavey],
            export_macro_name: "__export__",
        });

        use kontor::built_in::*;
        use kontor::built_in::context::{Signer};
        use kontor::built_in::foreign::{ContractAddressWrapper, ContractAddressModel, ContractAddressWriteModel, get_contract_address};
        use kontor::built_in::numbers::{IntegerWrapper, IntegerModel, IntegerWriteModel};
        use kontor::built_in::numbers::{DecimalWrapper, DecimalModel, DecimalWriteModel};

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

            fn __extend_path_with_match(&self, path: &str, variants: &[&str]) -> Option<String> {
                self.extend_path_with_match(path, &variants.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            }

            fn __get<T: Retrieve>(&self, path: DotPathBuf) -> Option<T> {
                T::__get(self, path)
            }
        }

        #[automatically_derived]
        impl ReadContext for context::ViewStorage {
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

            fn __extend_path_with_match(&self, path: &str, variants: &[&str]) -> Option<String> {
                self.extend_path_with_match(path, &variants.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            }

            fn __get<T: Retrieve>(&self, path: DotPathBuf) -> Option<T> {
                T::__get(self, path)
            }
        }

        #[automatically_derived]
        impl context::ViewStorage {
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

            fn __extend_path_with_match(&self, path: &str, variants: &[&str]) -> Option<String> {
                self.extend_path_with_match(path, &variants.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            }

            fn __get<T: Retrieve>(&self, path: DotPathBuf) -> Option<T> {
                T::__get(self, path)
            }
        }

        #[automatically_derived]
        impl context::ViewContext {
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

            fn __extend_path_with_match(&self, path: &str, variants: &[&str]) -> Option<String> {
                self.extend_path_with_match(path, &variants.iter().map(|s| s.to_string()).collect::<Vec<_>>())
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

            fn __extend_path_with_match(&self, path: &str, variants: &[&str]) -> Option<String> {
                self.extend_path_with_match(path, &variants.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            }

            fn __get<T: Retrieve>(&self, path: DotPathBuf) -> Option<T> {
                T::__get(self, path)
            }
        }

        #[automatically_derived]
        impl ReadContext for context::ProcStorage {
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

            fn __extend_path_with_match(&self, path: &str, variants: &[&str]) -> Option<String> {
                self.extend_path_with_match(path, &variants.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            }

            fn __get<T: Retrieve>(&self, path: DotPathBuf) -> Option<T> {
                T::__get(self, path)
            }
        }

        #[automatically_derived]
        impl context::ProcStorage {
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

            fn __extend_path_with_match(&self, path: &str, variants: &[&str]) -> Option<String> {
                self.extend_path_with_match(path, &variants.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            }

            fn __get<T: Retrieve>(&self, path: DotPathBuf) -> Option<T> {
                T::__get(self, path)
            }
        }

        #[automatically_derived]
        impl WriteContext for context::ProcStorage {
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

            fn __delete_matching_paths(&self, base_path: &str, variants: &[&str]) -> u64 {
                self.delete_matching_paths(base_path, &variants.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            }

            fn generate_id(&self) -> String {
                unimplemented!()
            }
        }

        #[automatically_derived]
        impl context::ProcStorage {
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

            fn __delete_matching_paths(&self, base_path: &str, variants: &[&str]) -> u64 {
                self.delete_matching_paths(base_path, &variants.iter().map(|s| s.to_string()).collect::<Vec<_>>())
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

            fn __delete_matching_paths(&self, base_path: &str, variants: &[&str]) -> u64 {
                self.delete_matching_paths(base_path, &variants.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            }

            fn generate_id(&self) -> String {
                self.generate_id()
            }
        }

        #[automatically_derived]
        impl ReadWriteContext for context::ProcContext {}


        #[automatically_derived]
        impl ReadWriteContext for context::ProcStorage {}


        #[automatically_derived]
        impl context::ProcContext {
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

            fn __extend_path_with_match(&self, path: &str, variants: &[&str]) -> Option<String> {
                self.extend_path_with_match(path, &variants.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            }

            fn __get<T: Retrieve>(&self, path: DotPathBuf) -> Option<T> {
                T::__get(self, path)
            }
        }

        #[automatically_derived]
        impl context::ProcContext {
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

            fn __delete_matching_paths(&self, base_path: &str, variants: &[&str]) -> u64 {
                self.delete_matching_paths(base_path, &variants.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            }
        }

        impls!();

        struct #name;

        __export__!(#name);
    }
}
