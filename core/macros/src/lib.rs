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

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

#[proc_macro]
pub fn contract(input: TokenStream) -> TokenStream {
    let attr_args = NestedMeta::parse_meta_list(input.into()).unwrap();
    let config = ContractConfig::from_list(&attr_args).unwrap();

    let world = config.world.unwrap_or("contract".to_string());
    let path = config.path.unwrap_or("wit".to_string());
    let name = Ident::from_string(&capitalize(&config.name)).unwrap();
    let boilerplate = quote! {
        wit_bindgen::generate!({
            world: #world,
            path: #path,
            generate_all,
        });

        use kontor::built_in::*;
        use wasm_wave::{to_string as to_wave, value::Value as WaveValue};

        struct #name;
    };

    boilerplate.into()
}
