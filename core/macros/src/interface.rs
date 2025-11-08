use darling::FromMeta;
use heck::ToSnakeCase;
use proc_macro2::TokenStream;
use syn::Ident;

use crate::import;

#[derive(FromMeta)]
pub struct Config {
    name: String,
    path: String,
}

pub fn generate(config: Config, test: bool) -> TokenStream {
    let name = config.name;
    let module_name = Ident::from_string(&name.clone().to_snake_case()).unwrap();
    let path = config.path;

    import::import(path, module_name, "root".to_string(), None, test, false)
}
