use anyhow::{anyhow, bail};
use heck::ToUpperCamelCase;
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::Ident;
use syn::PathArguments;
use wit_parser::{Handle, Resolve, Type as WitType, TypeDefKind};

pub fn is_option_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        type_path
            .path
            .segments
            .last()
            .map(|segment| {
                segment.ident == "Option"
                    && matches!(segment.arguments, PathArguments::AngleBracketed(_))
            })
            .unwrap_or(false)
    } else {
        false
    }
}

pub fn is_result_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        type_path
            .path
            .segments
            .last()
            .map(|segment| {
                segment.ident == "Result"
                    && matches!(segment.arguments, syn::PathArguments::AngleBracketed(_))
            })
            .unwrap_or(false)
    } else {
        false
    }
}

pub fn is_primitive_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        let segment = type_path.path.segments.last().map(|s| s.ident.to_string());
        matches!(
            segment.as_deref(),
            Some("u64" | "i64" | "String" | "bool" | "ContractAddress" | "Integer" | "Decimal")
        )
    } else {
        false
    }
}

pub fn is_map_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        type_path
            .path
            .segments
            .last()
            .map(|segment| segment.ident == "Map")
            .unwrap_or(false)
    } else {
        false
    }
}

pub fn wit_type_to_rust_type(
    resolve: &Resolve,
    ty: &WitType,
    use_str: bool,
) -> anyhow::Result<TokenStream> {
    match (ty, use_str) {
        (WitType::U64, _) => Ok(quote! { u64 }),
        (WitType::S64, _) => Ok(quote! { i64 }),
        (WitType::Bool, _) => Ok(quote! { bool }),
        (WitType::String, false) => Ok(quote! { String }),
        (WitType::String, true) => Ok(quote! { &str }),
        (WitType::Id(id), _) => {
            let ty_def = &resolve.types[*id];
            match &ty_def.kind {
                TypeDefKind::Type(inner) => Ok(wit_type_to_rust_type(resolve, inner, use_str)?),
                TypeDefKind::Option(inner) => {
                    let inner_ty = wit_type_to_rust_type(resolve, inner, use_str)?;
                    Ok(quote! { Option<#inner_ty> })
                }
                TypeDefKind::List(inner) => {
                    let inner_ty = wit_type_to_rust_type(resolve, inner, use_str)?;
                    Ok(quote! { Vec<#inner_ty> })
                }
                TypeDefKind::Result(result) => {
                    let ok_ty = match result.ok {
                        Some(ty) => wit_type_to_rust_type(resolve, &ty, use_str)?,
                        None => quote! { () },
                    };
                    let err_ty = match result.err {
                        Some(ty) => wit_type_to_rust_type(resolve, &ty, use_str)?,
                        None => quote! { () },
                    };
                    Ok(quote! { Result<#ok_ty, #err_ty> })
                }
                TypeDefKind::Handle(Handle::Borrow(resource_id)) => {
                    let resource_def = &resolve.types[*resource_id];
                    let resource_name = resource_def
                        .name
                        .as_ref()
                        .ok_or_else(|| anyhow!("Unnamed resource types are not supported"))?
                        .to_upper_camel_case();
                    let ident = Ident::new(&resource_name, Span::call_site());
                    Ok(quote! { &context::#ident })
                }
                TypeDefKind::Record(_) | TypeDefKind::Enum(_) | TypeDefKind::Variant(_) => {
                    let name = ty_def
                        .name
                        .as_ref()
                        .ok_or_else(|| anyhow!("Unnamed types are not supported"))?
                        .to_upper_camel_case();
                    let ident = Ident::new(&name, Span::call_site());
                    Ok(quote! { #ident })
                }
                _ => bail!("Unsupported type definition kind: {:?}", ty_def.kind),
            }
        }
        _ => bail!("Unsupported WIT type: {:?}", ty),
    }
}
