use crate::utils;
use proc_macro2::TokenStream;
use quote::quote;
use syn::{DataEnum, DataStruct, Error, Fields, Ident, Result};

pub fn generate_struct_body(data_struct: &DataStruct, type_name: &Ident) -> Result<TokenStream> {
    match &data_struct.fields {
        Fields::Named(fields) => {
            let mut field_sets = Vec::new();
            for field in fields.named.iter() {
                let field_name = field.ident.as_ref().unwrap();
                let field_name_str = field_name.to_string();
                let field_ty = &field.ty;

                if utils::is_result_type(field_ty) {
                    return Err(Error::new(
                        type_name.span(),
                        "Store derive does not support Result field types",
                    ));
                } else if utils::is_option_type(field_ty) {
                    field_sets.push(quote! {
                        match value.#field_name {
                            Some(inner) => ctx.__set(base_path.push(#field_name_str), inner),
                            None => ctx.__set(base_path.push(#field_name_str), ()),
                        }
                    })
                } else {
                    field_sets.push(quote! {
                        ctx.__set(base_path.push(#field_name_str), value.#field_name);
                    })
                }
            }
            Ok(quote! { #(#field_sets)* })
        }
        _ => Err(Error::new(
            type_name.span(),
            "Store derive only supports structs with named fields",
        )),
    }
}

pub fn generate_enum_body(data_enum: &DataEnum, type_name: &Ident) -> Result<TokenStream> {
    let arms = data_enum.variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        let variant_name = variant_ident.to_string().to_lowercase();

        match &variant.fields {
            Fields::Unit => {
                Ok(quote! {
                    #type_name::#variant_ident => ctx.__set(base_path.push(#variant_name), ()),
                })
            }
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                let field = fields.unnamed.first().unwrap();
                if utils::is_result_type(&field.ty) {
                    Err(Error::new(variant_ident.span(), "Store derive does not support Result type in Enums"))
                } else {
                    Ok(quote! {
                        #type_name::#variant_ident(inner) => ctx.__set(base_path.push(#variant_name), inner),
                    })
                }
            }
            _ => Err(Error::new(
                variant_ident.span(),
                "Store derive only supports unit or single-field tuple variants",
            )),
        }
    }).collect::<Result<Vec<_>>>()?;

    Ok(quote! {
        match value {
            #(#arms)*
        }
    })
}
