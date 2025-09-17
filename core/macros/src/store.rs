use crate::registry;
use crate::utils;
use proc_macro2::TokenStream;
use quote::quote;
use syn::{spanned::Spanned, DataEnum, DataStruct, Error, Fields, GenericArgument, Ident, PathArguments, Result, Type};

pub fn generate_struct_body(data_struct: &DataStruct, type_name: &Ident) -> Result<TokenStream> {
    match &data_struct.fields {
        Fields::Named(fields) => {
            let mut field_sets = Vec::new();
            for field in fields.named.iter() {
                if field_contains_resource(&field.ty) {
                    return Err(Error::new(
                        field.ty.span(),
                        "Storage derive cannot be used on structs containing resource fields",
                    ));
                }

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
                        ctx.__delete_matching_paths(&format!(r"^{}.({})(\..*|$)", base_path.push(#field_name_str), ["none", "some"].join("|")));
                        match value.#field_name {
                            Some(inner) => ctx.__set(base_path.push(#field_name_str).push("some"), inner),
                            None => ctx.__set(base_path.push(#field_name_str).push("none"), ()),
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
    let mut variant_names = vec![];
    let arms = data_enum.variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        let variant_name = variant_ident.to_string().to_lowercase();
        variant_names.push(variant_name.clone());

        match &variant.fields {
            Fields::Unit => {
                Ok(quote! {
                    #type_name::#variant_ident => ctx.__set(base_path.push(#variant_name), ()),
                })
            }
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                let field = fields.unnamed.first().unwrap();
                if field_contains_resource(&field.ty) {
                    return Err(Error::new(
                        field.ty.span(),
                        "Storage derive cannot be used on enums containing resource fields",
                    ));
                }
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
        ctx.__delete_matching_paths(&format!(r"^{}.({})(\..*|$)", base_path, [#(#variant_names),*].join("|")));
        match value {
            #(#arms)*
        }
    })
}

fn field_contains_resource(ty: &Type) -> bool {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    type_contains_resource(ty, &manifest_dir)
}

fn type_contains_resource(ty: &Type, manifest_dir: &str) -> bool {
    match ty {
        Type::Path(path) => {
            if let Some(segment) = path.path.segments.last() {
                if registry::is_resource_type(manifest_dir, &segment.ident.to_string()) {
                    return true;
                }

                match &segment.arguments {
                    PathArguments::AngleBracketed(args) => args.args.iter().any(|arg| match arg {
                        GenericArgument::Type(inner) => type_contains_resource(inner, manifest_dir),
                        _ => false,
                    }),
                    _ => false,
                }
            } else {
                false
            }
        }
        Type::Reference(reference) => type_contains_resource(&reference.elem, manifest_dir),
        Type::Paren(paren) => type_contains_resource(&paren.elem, manifest_dir),
        Type::Group(group) => type_contains_resource(&group.elem, manifest_dir),
        Type::Tuple(tuple) => tuple.elems.iter().any(|elem| type_contains_resource(elem, manifest_dir)),
        Type::Array(array) => type_contains_resource(&array.elem, manifest_dir),
        _ => false,
    }
}
