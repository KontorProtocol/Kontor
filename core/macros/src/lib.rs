extern crate proc_macro;

use darling::{FromMeta, ast::NestedMeta};
use proc_macro::TokenStream;
use quote::quote;
use syn::Ident;

#[derive(FromMeta)]
struct ContractConfig {
    name: String,
    world: Option<String>,
    path: Option<String>,
}

fn to_pascal_case(name: &str) -> String {
    name.split('-')
        .map(|s| {
            let mut c = s.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        })
        .collect()
}

#[proc_macro]
pub fn contract(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.into()).unwrap();
    let config = ContractConfig::from_list(&attr_args).unwrap();

    let world = config.world.unwrap_or("contract".to_string());
    let path = config.path.unwrap_or("wit".to_string());
    let name = Ident::from_string(&to_pascal_case(&config.name)).unwrap();
    let boilerplate = quote! {
        wit_bindgen::generate!({
            world: #world,
            path: #path,
            generate_all,
        });

        use kontor::built_in::*;

        use stdlib::*;

        impl ReadContext for context::ViewContext {
            fn get_str(&self, path: &str) -> Option<String> {
                self.get_str(path)
            }

            fn get_u64(&self, path: &str) -> Option<u64> {
                self.get_u64(path)
            }

            fn get_s64(&self, path: &str) -> Option<i64> {
                self.get_s64(path)
            }

            fn exists(&self, path: &str) -> bool {
                self.exists(path)
            }

            fn is_void(&self, path: &str) -> bool {
                self.is_void(path)
            }

            fn matching_path(&self, regexp: &str) -> Option<String> {
                self.matching_path(regexp)
            }

            fn __get<T: Retrieve>(&self, path: DotPathBuf) -> Option<T> {
                T::__get(self, path)
            }
        }

        impl ReadContext for context::ProcContext {
            fn get_str(&self, path: &str) -> Option<String> {
                self.get_str(path)
            }

            fn get_u64(&self, path: &str) -> Option<u64> {
                self.get_u64(path)
            }

            fn get_s64(&self, path: &str) -> Option<i64> {
                self.get_s64(path)
            }

            fn exists(&self, path: &str) -> bool {
                self.exists(path)
            }

            fn is_void(&self, path: &str) -> bool {
                self.is_void(path)
            }

            fn matching_path(&self, regexp: &str) -> Option<String> {
                self.matching_path(regexp)
            }

            fn __get<T: Retrieve>(&self, path: DotPathBuf) -> Option<T> {
                T::__get(self, path)
            }
        }

        impl WriteContext for context::ProcContext {
            fn set_str(&self, path: &str, value: &str) {
                self.set_str(path, value)
            }

            fn set_u64(&self, path: &str, value: u64) {
                self.set_u64(path, value)
            }

            fn set_s64(&self, path: &str, value: i64) {
                self.set_s64(path, value)
            }

            fn set_void(&self, path: &str) {
                self.set_void(path)
            }
        }

        impl ReadWriteContext for context::ProcContext {}

        impl Store for foreign::ContractAddress {
            fn __set(&self, ctx: &impl WriteContext, base_path: DotPathBuf) {
                self.name.__set(ctx, base_path.push("name"));
                self.height.__set(ctx, base_path.push("height"));
                self.tx_index.__set(ctx, base_path.push("tx_index"));
            }
        }

        struct #name;
    };

    boilerplate.into()
}
