use crate::utils;
use proc_macro2::TokenStream;
use quote::quote;
use syn::{DataEnum, DataStruct, Error, Fields, Ident, Result};

pub fn generate_struct_body(data_struct: &DataStruct, type_name: &Ident) -> Result<TokenStream> {
    match &data_struct.fields {
        Fields::Named(fields) => {
            // Interned path ids MUST match `model.rs`'s scheme (field declaration
            // index), so the wholesale write lands at the same paths the field
            // getters read. Same struct, same iteration order ⇒ same ids.
            if fields.named.len() > 128 {
                return Err(Error::new(
                    type_name.span(),
                    "storage struct may not exceed 128 fields (interned path-id space)",
                ));
            }
            let mut field_sets = Vec::new();
            for (field_idx, field) in fields.named.iter().enumerate() {
                let field_name = field.ident.as_ref().unwrap();
                let field_id = field_idx as u8;
                let field_ty = &field.ty;

                if utils::is_result_type(field_ty) {
                    return Err(Error::new(
                        type_name.span(),
                        "Store derive does not support Result field types",
                    ));
                } else {
                    field_sets.push(quote! {
                        stdlib::WriteStorage::__set(ctx, base_path.push_interned(#field_id), value.#field_name);
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
    // The discriminant segment is an interned dict-ref id = the variant's
    // declaration order (a per-enum dict). MUST match `model::generate_enum`'s
    // read side (same enum, same order ⇒ same ids), so a write and its later read
    // resolve to the same variant.
    let mut variant_candidates = vec![];
    let arms = data_enum.variants.iter().enumerate().map(|(i, variant)| {
        let variant_ident = &variant.ident;
        let variant_id = i as u8;
        variant_candidates.push(quote! { stdlib::interned_element(#variant_id) });

        match &variant.fields {
            Fields::Unit => {
                Ok(quote! {
                    #type_name::#variant_ident => stdlib::WriteStorage::__set(ctx, base_path.push_interned(#variant_id), ()),
                })
            }
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                let field = fields.unnamed.first().unwrap();
                if utils::is_result_type(&field.ty) {
                    Err(Error::new(variant_ident.span(), "Store derive does not support Result type in Enums"))
                } else {
                    Ok(quote! {
                        #type_name::#variant_ident(inner) => stdlib::WriteStorage::__set(ctx, base_path.push_interned(#variant_id), inner),
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
        stdlib::WriteStorage::__delete_matching_paths(ctx, &base_path, &[#(#variant_candidates),*]);
        match value {
            #(#arms)*
        }
    })
}
