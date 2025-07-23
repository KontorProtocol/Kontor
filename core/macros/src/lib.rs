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

        impl ReadStorage for context::ViewStorage {
            fn get_str(&self, path: &str) -> Option<String> {
                self.get_str(path)
            }

            fn get_u64(&self, path: &str) -> Option<u64> {
                self.get_u64(path)
            }

            fn exists(&self, path: &str) -> bool {
                self.exists(path)
            }
        }

        impl ReadStorage for context::ProcStorage {
            fn get_str(&self, path: &str) -> Option<String> {
                self.get_str(path)
            }

            fn get_u64(&self, path: &str) -> Option<u64> {
                self.get_u64(path)
            }

            fn exists(&self, path: &str) -> bool {
                self.exists(path)
            }
        }

        impl WriteStorage for context::ProcStorage {
            fn set_str(&self, path: &str, value: &str) {
                self.set_str(path, value)
            }

            fn set_u64(&self, path: &str, value: u64) {
                self.set_u64(path, value)
            }
        }

        impl ReadWriteStorage for context::ProcStorage {}

        impl ReadContext for &context::ViewContext {
            fn read_storage(&self) -> impl ReadStorage {
                self.storage()
            }
        }

        impl ReadContext for &context::ProcContext {
            fn read_storage(&self) -> impl ReadStorage {
                self.storage()
            }
        }

        impl WriteContext for &context::ProcContext {
            fn write_storage(&self) -> impl WriteStorage {
                self.storage()
            }
        }

        impl ReadWriteContext for &context::ProcContext {}

        struct #name;
    };

    boilerplate.into()
}
