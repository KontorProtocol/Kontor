use proc_macro2::TokenStream;
use quote::quote;
use syn::{DataStruct, Error, Fields, Ident, Result};

/// Body of `Indexed::index_entries` for a struct: one `(field_name, field
/// stringified)` entry per `#[index]`-tagged field. The field's value is the
/// index key, so each indexed field must be `ToString`.
pub fn generate_index_entries(data_struct: &DataStruct, type_name: &Ident) -> Result<TokenStream> {
    let Fields::Named(fields) = &data_struct.fields else {
        return Err(Error::new(
            type_name.span(),
            "Indexed derive only supports structs with named fields",
        ));
    };

    let pushes: Vec<TokenStream> = fields
        .named
        .iter()
        .filter(|f| f.attrs.iter().any(|a| a.path().is_ident("index")))
        .map(|field| {
            let field_name = field.ident.as_ref().unwrap();
            let name_str = field_name.to_string();
            quote! {
                entries.push((#name_str, alloc::string::ToString::to_string(&self.#field_name)));
            }
        })
        .collect();

    Ok(quote! {
        let mut entries = alloc::vec::Vec::new();
        #(#pushes)*
        entries
    })
}
