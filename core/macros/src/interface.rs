use darling::FromMeta;
use heck::ToSnakeCase;
use proc_macro2::TokenStream;
use syn::Ident;

use crate::import;

#[derive(FromMeta)]
pub struct Config {
    name: String,
    path: String,
    world: Option<String>,
}

pub fn generate(config: Config, test: bool) -> TokenStream {
    let name = config.name;
    let module_name = Ident::from_string(&name.clone().to_snake_case()).unwrap();
    let path = config.path;
    let world_name = config.world.unwrap_or("contract".to_string());

    import::import(path, module_name, world_name, None, test, false)
}
